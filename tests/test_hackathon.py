"""Tests for the five DBS challenge requirements:
  1. multi-intent parsing (transfer / bill / investment, source account) into a structured draft
  2. dynamic disambiguation (ask with account tails, never guess)
  3. dual-engine semantic audit (independent verifier, deterministic comparison, freeze)
  4. deterministic HITL with native biometrics (WebAuthn passkey, user verification required)
  5. zero-trust execution gateway (re-verifies the device signature before posting)
plus account-bound protection levels.
"""
import base64
import hashlib
import json
import os
import tempfile
import unittest

os.environ.setdefault("RULE_FIXED_HOUR", "14")

from app.agent.llm import OfflineLLM  # noqa: E402
from app.agent.loop import Agent  # noqa: E402
from app.agent.tools import ToolGateway  # noqa: E402
from app.agent.verifier import Verifier, extract_offline, catalog  # noqa: E402
from app.bank.gateway import GatewayError  # noqa: E402
from app.bank.mock_bank import MockBank  # noqa: E402
from app.kernel import p256, protection, webauthn  # noqa: E402
from app.kernel.audit import AuditLog  # noqa: E402
from app.kernel.credentials import CredentialRegistry  # noqa: E402
from app.kernel.executor import Kernel, KernelError  # noqa: E402
from app.kernel.signing import Site, TokenService, canonical  # noqa: E402
from app.kernel.state import Session  # noqa: E402
from app.models import Phase, RiskLevel  # noqa: E402

SITE = Site("localhost", frozenset({"http://localhost:8000"}))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bank = MockBank()
        self.audit = AuditLog(os.path.join(self.tmp.name, "a.jsonl"))
        self.registry = CredentialRegistry(None)
        self.kernel = Kernel(self.bank, self.audit, TokenService(b"t"), allow_mock=False, registry=self.registry)
        self.verifier = Verifier(None, self.bank)
        self.gw = ToolGateway(self.bank, self.kernel, verifier=self.verifier)
        self.agent = Agent(self.bank, self.gw, self.audit, OfflineLLM())
        self.s = Session(session_id="h")

    def tearDown(self):
        self.tmp.cleanup()

    def turn(self, *texts):
        r = None
        for t in texts:
            r = self.agent.run_turn(self.s, t)
        return r

    def model_drafts(self, said, tool, args):
        self.s.messages.append({"role": "user", "content": said})
        res = self.gw.call(self.s, tool, args)
        self.assertTrue(res["ok"], res)
        return self.s.current_draft


# ---------------------------------------------------------------- 1. multi-intent parsing
class TestIntents(Base):
    def test_investment_draft_is_structured(self):
        r = self.turn("Invest 200 in the income fund")
        d = self.s.current_draft
        self.assertEqual((d.kind, d.payee_id, d.amount_cents, d.asset_class), ("investment", "f_income", 20000, "Unit trust"))
        self.assertEqual(r.ui["card"]["title"], "Confirm investment")
        self.assertIn("asset_class", d.card_fields())          # the asset class is part of what gets signed

    def test_source_account_from_words(self):
        self.turn("Send 50 to my daughter from my current account")
        self.assertEqual(self.s.current_draft.from_account, "CUR-002")

    def test_default_account_when_not_said(self):
        self.turn("Send 50 to my daughter")
        self.assertEqual(self.s.current_draft.from_account, "SAV-001")

    def test_savings_bonds_is_not_the_savings_account(self):
        self.turn("Buy 1000 of savings bonds")
        d = self.s.current_draft
        self.assertEqual((d.kind, d.payee_id, d.from_account), ("investment", "b_ssb", "SAV-001"))

    def test_unknown_account_rejected_by_tool(self):
        self.s.messages.append({"role": "user", "content": "Send 50 to my daughter"})
        res = self.gw.call(self.s, "draft_transfer", {"payee_id": "p_daughter", "amount": 50, "from_account": "CPF-9"})
        self.assertFalse(res["ok"])

    def test_risky_fund_above_profile_needs_care(self):
        self.turn("Invest 200 in the STI ETF")
        d = self.s.current_draft
        self.assertIn("R70_ABOVE_RISK_PROFILE", d.risk.rule_hits)
        self.assertEqual(d.risk.level, RiskLevel.HIGH)          # enhanced protection: cooling-off

    def test_below_minimum_blocked(self):
        self.turn("Buy 100 of savings bonds")
        self.assertEqual(self.s.current_draft.risk.level, RiskLevel.BLOCK)


class TestPendingAndCompound(Base):
    """Reported in testing: a payment was still waiting, the user asked for a new one, no card appeared and the model
    claimed it had "prepared" the new transfer (to the wrong person)."""
    def test_compound_with_and_is_split(self):
        r = self.turn("I want to send 500 to my son and the rest money I want to invest in apple stock.")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents), ("p_son", 50000))
        self.assertEqual(self.s.plan, ["the rest money I want to invest in apple stock"])
        self.assertIn(r.ui["type"], ("confirm", "cooldown"))

    def test_not_split_when_second_part_is_not_a_request(self):
        from app.agent.loop import split_plan
        self.assertEqual(len(split_plan("Send 50 to my son and daughter")), 1)

    def test_new_request_while_pending_shows_waiting_card_and_queues(self):
        self.turn("Send 50 to my grandson Chen Jun")
        first = self.s.current_draft
        r = self.turn("I want to send 500 to my son")
        self.assertEqual(r.ui["type"], "confirm")
        self.assertEqual(r.ui["card"]["draft_id"], first.draft_id)          # the SAME waiting card, shown again
        self.assertIn("still have one payment waiting", r.reply)
        self.assertIn("Chen Jun", r.reply)
        self.assertEqual(len(self.s.drafts), 1)                               # nothing new invented
        self.assertEqual(self.s.plan, ["I want to send 500 to my son"])     # offered after confirm / cancel

    def test_im_ready_reopens_the_card(self):
        self.turn("Send 50 to my daughter")
        r = self.turn("I'm ready")
        self.assertEqual(r.ui["type"], "confirm")
        self.assertTrue(r.ui.get("reopened"))

    def test_false_prepared_claim_corrected(self):
        class Liar(OfflineLLM):
            def chat(self, messages, tools=None, **kw):
                return {"role": "assistant", "content": "I've prepared a transfer of S$500 to your son Chen Jun.",
                        "tool_calls": []}
        r = Agent(self.bank, self.gw, self.audit, Liar()).run_turn(self.s, "Send 500 to my son")
        self.assertNotIn("Chen Jun", r.reply)
        # nudged once, still lying -> the rule-based planner finished the turn properly, to the REAL son
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents), ("p_son", 50000))
        self.assertEqual(r.ui["type"], "confirm")
        self.assertTrue(any(t["kind"] == "fallback" for t in self.s.trace))

    def test_answer_turn_finishes_the_compound_plan(self):
        """Live-model failure: '350 to my grandson and invest 2000 in ETF' -> 'which one?' -> 'Chen Wei' -> nothing."""
        class LazyOnAnswers(OfflineLLM):
            def chat(self, messages, tools=None, **kw):
                last = next(m["content"] for m in reversed(messages) if m["role"] == "user")
                if last == "Chen Wei":
                    seen.append(messages[0]["content"])
                    return {"role": "assistant", "content": "I've prepared the transfer to Chen Wei.", "tool_calls": []}
                return super().chat(messages, tools=tools, **kw)
        seen = []
        agent = Agent(self.bank, self.gw, self.audit, LazyOnAnswers())
        r1 = agent.run_turn(self.s, "I want to transfer 350 dollars to my grandson and I want to invest 2000 dollars in ETF.")
        self.assertEqual(r1.ui["type"], "choose")
        self.assertEqual(len(r1.ui["plan"]), 2)
        r2 = agent.run_turn(self.s, "Chen Wei")
        self.assertIn("payee_id p_grandson_wei", seen[0])          # the model was told exactly what to do
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents), ("p_grandson_wei", 35000))
        self.assertEqual(r2.ui["type"], "confirm")
        self.assertEqual(self.s.plan, ["I want to invest 2000 dollars in ETF"])

    def test_model_that_claims_without_tools_is_nudged_into_calling_them(self):
        """Seen with a live model: it imitated earlier "I've prepared a transfer" replies and skipped the tools."""
        class Lazy(OfflineLLM):
            def __init__(self):
                self.calls = 0
            def chat(self, messages, tools=None, **kw):
                self.calls += 1
                if not any("Harness check" in (m.get("content") or "") for m in messages):
                    return {"role": "assistant", "content": "I've prepared a transfer of S$300 to Chen Wei.", "tool_calls": []}
                # after the nudge: behaves properly (the offline rules can't read the harness note, so drop that pair)
                i = next(i for i, m in enumerate(messages) if "Harness check" in (m.get("content") or ""))
                return super().chat(messages[:i - 1] + messages[i + 1:], tools=tools, **kw)
        r = Agent(self.bank, self.gw, self.audit, Lazy()).run_turn(self.s, "Send 300 to Chen Wei")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents), ("p_grandson_wei", 30000))
        self.assertEqual(r.ui["type"], "confirm")
        self.assertTrue(any("without calling a draft tool" in t["label"] for t in self.s.trace))

    def test_history_records_what_really_happened(self):
        self.turn("Send 50 to my daughter")
        last = self.s.messages[-1]["content"]
        self.assertIn("[system note: draft_transfer was called", last)

    def test_system_note_never_shown_to_user(self):
        class Copycat(OfflineLLM):
            def chat(self, messages, tools=None, **kw):
                return {"role": "assistant", "content": "Your balance is fine. [system note: draft_transfer was called]",
                        "tool_calls": []}
        r = Agent(self.bank, self.gw, self.audit, Copycat()).run_turn(self.s, "How much money do I have?")
        self.assertNotIn("system note", r.reply)

    def test_restated_compound_replaces_queue(self):
        self.turn("Send 300 to my grandson and the rest 2000 dollars I want to invest in the ETF")
        self.turn("Send 300 to my grandson and the rest of the money I want to invest in the ETF")
        self.assertEqual(self.s.plan, ["the rest of the money I want to invest in the ETF"])

    def test_the_rest_is_never_turned_into_an_amount(self):
        r = self.turn("Invest the rest in apple stock")
        self.assertTrue(r.reply.rstrip().endswith("?"))          # asks how much
        self.assertFalse(self.s.drafts)


class TestLookupDiscipline(Base):
    """Seen with a live model: 'I can't find an ETF' / 'grandson isn't in your list' without calling any tool."""
    def lazy(self, times):
        class Lazy(OfflineLLM):
            n = 0
            def chat(inner, messages, tools=None, **kw):
                if Lazy.n < times:
                    Lazy.n += 1
                    return {"role": "assistant", "content": "I can't find a saved payee named grandson.", "tool_calls": []}
                clean = [m for m in messages if "Harness check" not in (m.get("content") or "")
                         and "can't find a saved payee" not in (m.get("content") or "")]
                return super().chat(clean, tools=tools, **kw)
        return Agent(self.bank, self.gw, self.audit, Lazy())

    def test_answer_without_lookup_is_nudged(self):
        r = self.lazy(1).run_turn(self.s, "I want to send 300 to my grandson.")
        self.assertEqual(r.ui["type"], "choose")                      # it looked, and asks which grandson
        self.assertTrue(any("without using any tool" in t["label"] for t in self.s.trace))

    def test_still_no_lookup_after_nudge_falls_back(self):
        r = self.lazy(5).run_turn(self.s, "I want to invest 2000 dollars in the ETF")
        self.assertEqual(self.s.current_draft.payee_id, "e_sti")
        self.assertIn(r.ui["type"], ("confirm", "cooldown"))
        self.assertTrue(any(t["kind"] == "fallback" for t in self.s.trace))

    def test_money_turn_asks_api_to_force_a_tool_call(self):
        seen = []

        class Forcing(OfflineLLM):
            supports_tool_choice = True
            def chat(inner, messages, tools=None, tool_choice=None, **kw):
                seen.append(tool_choice)
                return super().chat(messages, tools=tools, **kw)
        Agent(self.bank, self.gw, self.audit, Forcing()).run_turn(self.s, "Send 50 to my daughter")
        self.assertEqual(seen[0], "required")
        self.assertTrue(all(c is None for c in seen[1:]))
        seen.clear()
        Agent(self.bank, self.gw, self.audit, Forcing()).run_turn(Session(session_id="q"), "Hello there")
        self.assertTrue(all(c is None for c in seen))

    def test_server_without_required_degrades_to_auto(self):
        from unittest import mock
        from app.agent.llm import OpenAICompatLLM
        bodies = []

        def fake_post(url, json=None, **kw):
            bodies.append(dict(json))
            r = mock.Mock()
            r.status_code = 400 if json.get("tool_choice") == "required" else 200
            r.text = "tool_choice required not supported"
            r.json.return_value = {"choices": [{"message": {"content": "hi", "tool_calls": []}}]}
            return r
        llm = OpenAICompatLLM("http://x", "k", "m")
        with mock.patch("app.agent.llm.requests.post", side_effect=fake_post):
            self.assertEqual(llm.chat([{"role": "user", "content": "x"}], tools=[{}], tool_choice="required")["content"], "hi")
        self.assertEqual([b["tool_choice"] for b in bodies], ["required", "auto"])
        self.assertFalse(llm.supports_tool_choice)


class TestDbsProducts(Base):
    def test_buy_us_shares(self):
        r = self.turn("I want to invest 500 in apple stock")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.asset_class), ("s_aapl", "Shares (US)"))
        self.assertIn("AAPL", r.ui["card"]["payee_account"])
        self.assertIn("R70_ABOVE_RISK_PROFILE", d.risk.rule_hits)          # conservative profile: cooling-off

    def test_shares_execute_with_units_and_show_in_portfolio(self):
        d0, jwk = p256.generate_keypair()
        self.kernel.register_key(self.s, jwk)
        self.bank.risk_profile("u_chen")["max_product_risk"] = 5           # an adventurous customer
        self.turn("Buy 300 dollars of DBS shares")
        d = self.s.current_draft
        payload = self.kernel.issue_challenge(self.s, d.draft_id, d.digest)
        a = {"payload": payload, "signature": base64.b64encode(p256.sign(d0, payload.encode())).decode()}
        receipt = self.kernel.commit(self.s, d.draft_id, self.kernel.authorize(self.s, d.draft_id, d.digest, a))
        self.assertAlmostEqual(receipt["units"], 300 / 38.5, places=3)
        held = next(h for h in self.bank.portfolio("u_chen") if h["product_id"] == "s_d05")
        self.assertAlmostEqual(held["units"], 50 + 300 / 38.5, places=3)

    def test_fixed_deposit(self):
        r = self.turn("Put 1000 in a fixed deposit")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.asset_class, d.risk.level), ("d_fd12", "Fixed deposit", RiskLevel.LOW))
        self.assertIn("1.80%", r.ui["card"]["payee_account"])

    def test_unknown_company_not_invented(self):
        r = self.turn("Buy tesla stock")
        self.assertFalse(self.s.drafts)
        self.assertIn("Apple", r.reply)

    def test_portfolio(self):
        r = self.turn("How are my investments doing?")
        self.assertIn("get_portfolio", [t["label"].split("(")[0] for t in self.s.trace if t["kind"] == "action"])
        self.assertIn("+S$325.00", r.reply)                                # 50 DBS shares: 1,600 -> 1,925

    def test_lock_lost_cards_immediately_no_money_moves(self):
        r = self.turn("I lost my wallet, please lock my cards")
        self.assertTrue(all(c["status"] == "locked" for c in self.bank.cards("u_chen")))
        self.assertIn("1800 111 1111", r.reply)
        self.assertFalse(self.s.drafts)

    def test_lock_one_card(self):
        self.turn("Lock my credit card")
        st = {c["card_id"]: c["status"] for c in self.bank.cards("u_chen")}
        self.assertEqual(st, {"c_debit": "active", "c_credit": "locked"})

    def test_lock_by_card_name_from_button(self):
        self.turn("Lock my DBS Live Fresh Card")
        self.assertEqual(self.bank.card("u_chen", "c_credit")["status"], "locked")

    def test_no_unlock_tool_exists(self):
        self.assertFalse([n for n in self.gw.tools if "unlock" in n])


# ---------------------------------------------------------------- 2. disambiguation
class TestDisambiguation(Base):
    def test_two_grandsons_asks_with_account_tails(self):
        r = self.turn("Send 50 to my grandson")
        self.assertEqual(r.ui["type"], "choose")
        self.assertIn("••••2290", r.reply)
        self.assertIn("••••6613", r.reply)
        self.assertFalse(self.s.drafts)                          # never guesses

    def test_missing_amount_asks(self):
        r = self.turn("Send money to my son")
        self.assertTrue(r.reply.endswith("?"))
        self.assertFalse(self.s.drafts)


# ---------------------------------------------------------------- 3. dual-engine audit
class TestVerifier(Base):
    def test_matching_draft_is_signable(self):
        self.turn("Send 50 to my daughter")
        d = self.s.current_draft
        self.assertEqual(d.verification["status"], "match")
        self.assertEqual(self.s.phase, Phase.AWAITING_AUTH)

    def test_verifier_runs_in_parallel(self):
        self.turn("Send 50 to my daughter")
        self.assertTrue(self.s.current_draft.verification["parallel"])

    def test_wrong_amount_frozen(self):
        d = self.model_drafts("Send 50 to my daughter", "draft_transfer", {"payee_id": "p_daughter", "amount": 500})
        self.assertEqual(self.s.phase, Phase.FROZEN)
        self.assertIn("amount", " ".join(d.verification["mismatches"]).lower())
        with self.assertRaises(KernelError):
            self.kernel.issue_challenge(self.s, d.draft_id, d.digest)

    def test_wrong_payee_frozen(self):
        self.model_drafts("Send 50 to my daughter", "draft_transfer", {"payee_id": "p_son", "amount": 50})
        self.assertEqual(self.s.phase, Phase.FROZEN)

    def test_wrong_account_frozen(self):
        self.model_drafts("Pay my utilities bill from my current account", "draft_bill_payment",
                          {"bill_id": "b_sp_oct", "from_account": "SAV-001"})
        self.assertEqual(self.s.phase, Phase.FROZEN)

    def test_wrong_asset_type_frozen(self):
        self.model_drafts("Invest 200 in the income fund", "draft_transfer", {"payee_id": "p_daughter", "amount": 200})
        self.assertEqual(self.s.phase, Phase.FROZEN)

    def test_frozen_reply_is_code_template(self):
        class Wrong(OfflineLLM):      # always drafts S$500
            def chat(self, messages, tools=None, **kw):
                if messages[-1]["role"] == "tool":
                    return {"role": "assistant", "content": "All set, S$500 is ready!", "tool_calls": []}
                return {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {
                    "name": "draft_transfer", "arguments": json.dumps({"payee_id": "p_daughter", "amount": 500})}}]}
        r = Agent(self.bank, self.gw, self.audit, Wrong()).run_turn(self.s, "Send 50 to my daughter")
        self.assertEqual(r.ui["type"], "frozen")
        self.assertIn("doesn't match what you said", r.reply)

    def test_unverified_draft_cannot_be_signed(self):
        self.s.messages.append({"role": "user", "content": "Send 50 to my daughter"})
        d = self.kernel.create_draft(self.s, kind="transfer", payee_id="p_daughter", amount_cents=5000, local_hour=14)
        with self.assertRaises(KernelError) as e:
            self.kernel.issue_challenge(self.s, d.draft_id, d.digest)
        self.assertEqual(e.exception.code, "NOT_VERIFIED")

    def test_not_stated_is_not_a_mismatch(self):
        ex = extract_offline(["Send money to my daughter", "the usual amount"], catalog(self.bank, "u_chen"))
        self.assertIsNone(ex["amount"])

    def test_model_verifier_parses_json_and_runs_in_parallel(self):
        seen = {}

        class FakeModel:
            name = "openai_compat"
            def chat(self, messages, tools=None, **kw):
                seen["tools"], seen["payload"] = tools, json.loads(messages[-1]["content"])
                return {"content": '```json\n{"intent": "transfer", "payee": "my daughter", "amount": 50, '
                                   '"asset_class": "cash", "from_account": null}\n```', "tool_calls": []}
        gw = ToolGateway(self.bank, self.kernel, verifier=Verifier(FakeModel(), self.bank))
        Agent(self.bank, gw, self.audit, OfflineLLM()).run_turn(self.s, "Send 50 to my daughter")
        v = self.s.current_draft.verification
        self.assertEqual((v["status"], v["parallel"]), ("match", True))
        self.assertIsNone(seen["tools"])                                   # read-only: no tools at all
        self.assertNotIn("draft", json.dumps(seen["payload"]).lower())     # never shown the draft
        self.assertEqual(seen["payload"]["transcript"], ["Send 50 to my daughter"])

    def test_verifier_failure_falls_back_not_open(self):
        class Boom:
            name = "openai_compat"
            def chat(self, *a, **k):
                raise RuntimeError("down")
        v = Verifier(Boom(), self.bank)
        self.s.messages.append({"role": "user", "content": "Send 50 to my daughter"})
        out = v.verdict(self.s)
        self.assertIn("fallback", out["engine"])
        self.assertEqual(out["extracted"]["amount"], 50)


# ---------------------------------------------------------------- 4. passkeys (native biometric)
class TestPasskey(Base):
    def enrol(self):
        self.auth = webauthn.SoftAuthenticator()
        opts = self.kernel.passkey_options(self.s, SITE)
        reg = self.auth.register(webauthn.unb64u(opts["challenge"]))
        return self.kernel.passkey_register(self.s, SITE, reg["credential_id"], reg["client_data_json"],
                                            reg["attestation_object"])

    def pay(self, sign):
        self.turn("Send 50 to my daughter")
        d = self.s.current_draft
        payload = self.kernel.issue_challenge(self.s, d.draft_id, d.digest)
        tok = self.kernel.authorize(self.s, d.draft_id, d.digest, sign(payload), site=SITE)
        return self.kernel.commit(self.s, d.draft_id, tok)

    def test_enrol_and_pay(self):
        self.enrol()
        receipt = self.pay(self.auth.sign)
        auth = receipt["verifiable"]["authorization"]
        self.assertEqual(auth["method"], "passkey")
        self.assertEqual(self.bank.account("u_chen", "SAV-001")["balance_cents"], 325000 - 5000)

    def test_receipt_verifies_offline(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
        from verify_receipt import check
        self.enrol()
        receipt = self.pay(self.auth.sign)["verifiable"]
        self.assertTrue(all(ok for _, ok in check(receipt)), check(receipt))

    def test_windows_hello_rsa_passkey(self):
        """Some Windows Hello set-ups make RS256 (RSA) passkeys instead of ES256."""
        self.auth = webauthn.SoftAuthenticator(alg="RS256")
        opts = self.kernel.passkey_options(self.s, SITE)
        reg = self.auth.register(webauthn.unb64u(opts["challenge"]))
        self.kernel.passkey_register(self.s, SITE, reg["credential_id"], reg["client_data_json"], reg["attestation_object"])
        receipt = self.pay(self.auth.sign)
        self.assertIn("RS256", receipt["verifiable"]["authorization"]["alg"])
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
        from verify_receipt import check
        self.assertTrue(all(ok for _, ok in check(receipt["verifiable"])))
        self.s.settle()
        with self.assertRaises(KernelError):                       # tampered RSA signature
            self.pay(lambda p: {**self.auth.sign(p), "signature": webauthn.b64u(b"\x01" * 256)})

    def test_no_user_verification_rejected(self):
        self.enrol()
        with self.assertRaises(KernelError) as e:
            self.pay(lambda p: self.auth.sign(p, uv=False))
        self.assertEqual(e.exception.code, "UV_REQUIRED")

    def test_wrong_origin_rejected(self):
        self.enrol()
        with self.assertRaises(KernelError) as e:
            self.pay(lambda p: self.auth.sign(p, origin="https://evil.example"))
        self.assertEqual(e.exception.code, "ORIGIN_MISMATCH")

    def test_other_key_rejected(self):
        self.enrol()
        other, _ = p256.generate_keypair()
        with self.assertRaises(KernelError) as e:
            self.pay(lambda p: self.auth.sign(p, key=other))
        self.assertEqual(e.exception.code, "INVALID_SIGNATURE")

    def test_counter_must_increase(self):
        self.enrol()
        self.auth.count = 100
        self.pay(self.auth.sign)
        self.s.settle()
        self.auth.count = 5                                   # a cloned authenticator
        with self.assertRaises(KernelError) as e:
            self.pay(self.auth.sign)
        self.assertEqual(e.exception.code, "COUNTER_REPLAY")

    def test_no_downgrade_to_browser_key(self):
        d0, jwk = p256.generate_keypair()
        self.kernel.register_key(self.s, jwk)
        self.enrol()
        with self.assertRaises(KernelError) as e:
            self.pay(lambda p: {"payload": p, "signature": base64.b64encode(p256.sign(d0, p.encode())).decode()})
        self.assertEqual(e.exception.code, "PASSKEY_REQUIRED")

    def test_registration_with_wrong_challenge_rejected(self):
        auth = webauthn.SoftAuthenticator()
        self.kernel.passkey_options(self.s, SITE)
        reg = auth.register(b"x" * 32)
        with self.assertRaises(KernelError) as e:
            self.kernel.passkey_register(self.s, SITE, reg["credential_id"], reg["client_data_json"],
                                         reg["attestation_object"])
        self.assertEqual(e.exception.code, "CHALLENGE_MISMATCH")

    def test_registry_persists(self):
        path = os.path.join(self.tmp.name, "pk.json")
        reg = CredentialRegistry(__import__("pathlib").Path(path))
        reg.add_passkey("u_chen", {"credential_id": "abc", "public_key": {}, "rp_id": "localhost", "sign_count": 0})
        self.assertTrue(CredentialRegistry(__import__("pathlib").Path(path)).passkeys("u_chen", "localhost"))


# ---------------------------------------------------------------- 5. execution gateway
class TestGateway(Base):
    def setUp(self):
        super().setUp()
        self.d0, jwk = p256.generate_keypair()
        self.kernel.register_key(self.s, jwk)

    def signed_draft(self):
        self.turn("Send 50 to my daughter")
        d = self.s.current_draft
        payload = self.kernel.issue_challenge(self.s, d.draft_id, d.digest)
        a = {"payload": payload, "signature": base64.b64encode(p256.sign(self.d0, payload.encode())).decode()}
        tok = self.kernel.authorize(self.s, d.draft_id, d.digest, a)
        return d, tok

    def test_happy_path_goes_through_gateway(self):
        d, tok = self.signed_draft()
        self.kernel.commit(self.s, d.draft_id, tok)
        self.assertTrue(any(e["event"] == "gateway.posted" for e in self.audit.for_session("h")))

    def test_gateway_rejects_unsigned(self):
        d, _ = self.signed_draft()
        with self.assertRaises(GatewayError) as e:
            self.kernel.gateway.execute(user_id="u_chen", session_id="h", card=d.card_fields(), digest=d.digest,
                                        auth=None, idempotency_key="x")
        self.assertEqual(e.exception.code, "GW_UNSIGNED")

    def test_gateway_rejects_signature_for_other_card(self):
        d, _ = self.signed_draft()
        card = {**d.card_fields(), "amount_cents": 999_00}
        with self.assertRaises(GatewayError) as e:
            self.kernel.gateway.execute(user_id="u_chen", session_id="h", card=card,
                                        digest=hashlib.sha256(canonical(card).encode()).hexdigest(),
                                        auth=self.s.signatures[d.draft_id], idempotency_key="x")
        self.assertEqual(e.exception.code, "GW_PAYLOAD_MISMATCH")

    def test_gateway_does_not_trust_a_forged_record(self):
        d, _ = self.signed_draft()
        forged = {**self.s.signatures[d.draft_id], "signature": base64.b64encode(b"\x01" * 64).decode()}
        with self.assertRaises(GatewayError) as e:
            self.kernel.gateway.execute(user_id="u_chen", session_id="h", card=d.card_fields(), digest=d.digest,
                                        auth=forged, idempotency_key="x")
        self.assertEqual(e.exception.code, "GW_INVALID_SIGNATURE")

    def test_gateway_own_replay_list(self):
        d, tok = self.signed_draft()
        self.kernel.commit(self.s, d.draft_id, tok)
        with self.assertRaises(GatewayError) as e:
            self.kernel.gateway.execute(user_id="u_chen", session_id="h", card=d.card_fields(), digest=d.digest,
                                        auth=self.s.signatures[d.draft_id], idempotency_key="again")
        self.assertEqual(e.exception.code, "GW_REPLAY")


# ---------------------------------------------------------------- protection levels
class TestProtection(Base):
    def lower(self):
        d0, jwk = p256.generate_keypair()
        self.kernel.register_key(self.s, jwk)
        payload = self.kernel.protection_challenge(self.s, "standard")
        a = {"payload": payload, "signature": base64.b64encode(p256.sign(d0, payload.encode())).decode()}
        return self.kernel.change_protection(self.s, "standard", a)

    def test_lowering_is_signed_and_delayed(self):
        st = self.lower()
        self.assertEqual(st["level"], "enhanced")
        self.assertEqual(st["pending"]["to"], "standard")
        self.assertEqual(protection.effective(self.bank, "u_chen", now=st["pending"]["effective_at"] + 1), "standard")

    def test_lowering_without_signature_refused(self):
        with self.assertRaises(KernelError):
            self.kernel.change_protection(self.s, "standard", None)

    def test_raising_is_instant_and_cancels_pending(self):
        self.lower()
        st = self.kernel.change_protection(self.s, "enhanced")
        self.assertEqual((st["level"], st["pending"]), ("enhanced", None))

    def test_standard_turns_scam_high_into_warning(self):
        self.bank.protection("u_chen")["level"] = "standard"
        r = self.turn("A bank officer called and said it's urgent, send 50 to my daughter")
        self.assertNotEqual(r.ui["type"], "blocked")
        self.assertEqual(self.s.current_draft.risk.level, RiskLevel.MEDIUM)     # warning + question

    def test_enhanced_blocks_same_message(self):
        r = self.turn("A bank officer called and said it's urgent, send 50 to my daughter")
        self.assertEqual(r.ui["type"], "blocked")

    def test_safe_account_blocks_everyone(self):
        self.bank.protection("u_chen")["level"] = "standard"
        r = self.turn("The police say I must move my savings to a safe account")
        self.assertEqual(r.ui["type"], "blocked")

    def test_standard_has_higher_cooling_threshold(self):
        self.bank.protection("u_chen")["level"] = "standard"
        self.turn("Send 1500 to my daughter")
        self.assertNotIn("R12_ABOVE_THRESHOLD", self.s.current_draft.risk.rule_hits)


if __name__ == "__main__":
    unittest.main()
