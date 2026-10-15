"""Unit tests for the safety kernel: rules, signing, state machine, executor, audit chain. Run: python -m unittest discover tests"""
import os
import tempfile
import time
import unittest

os.environ.setdefault("RULE_FIXED_HOUR", "14")

from app.agent.textparse import amount_words_en, parse_amount  # noqa: E402
from app.agent.verifier import Verifier  # noqa: E402
from app.bank.mock_bank import MockBank  # noqa: E402
from app.kernel.audit import AuditLog  # noqa: E402
from app.kernel.executor import Kernel, KernelError  # noqa: E402
from app.kernel.signing import TokenService  # noqa: E402
from app.kernel.state import IllegalTransition, Session  # noqa: E402
from app.models import Phase, RiskLevel  # noqa: E402


class KernelTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bank = MockBank()
        self.audit = AuditLog(os.path.join(self.tmp.name, "audit.jsonl"))
        self.kernel = Kernel(self.bank, self.audit, TokenService(b"test-secret"), allow_mock=True)
        self.s = Session(session_id="t")

    def tearDown(self):
        self.tmp.cleanup()

    def say(self, text):
        self.s.messages.append({"role": "user", "content": text})

    def draft(self, payee="p_daughter", cents=20000, said=True, **kw):
        # By default the user actually asked for this payment (evidence grounding needs the user's words)
        p = self.bank.payee("u_chen", payee)
        if said and p:
            self.say(f"Send {cents / 100:g} to {p['name']}")
        kw.setdefault("verification", Verifier(None, self.bank).verdict(self.s))   # the independent check
        return self.kernel.create_draft(self.s, kind="transfer", payee_id=payee, amount_cents=cents,
                                        local_hour=14, **kw)


class TestRules(KernelTestBase):
    def test_low_for_usual_amount_to_known_payee(self):
        self.assertEqual(self.draft().risk.level, RiskLevel.LOW)

    def test_medium_when_far_above_usual(self):
        d = self.draft("p_son", 50000)
        self.assertEqual(d.risk.level, RiskLevel.MEDIUM)
        self.assertIsNotNone(d.risk.verify_question)

    def test_high_above_threshold_has_cooldown(self):
        d = self.draft(cents=150000)
        self.assertEqual(d.risk.level, RiskLevel.HIGH)
        self.assertEqual(self.s.phase, Phase.COOLING)

    def test_block_unknown_payee(self):
        d = self.draft("p_stranger", 1000)
        self.assertEqual(d.risk.level, RiskLevel.BLOCK)
        self.assertEqual(self.s.phase, Phase.BLOCKED)

    def test_block_insufficient_balance(self):
        self.assertEqual(self.draft(cents=400000).risk.level, RiskLevel.BLOCK)

    def test_night_is_medium(self):
        d = self.kernel.create_draft(self.s, kind="transfer", payee_id="p_daughter", amount_cents=20000,
                                     local_hour=2)
        self.assertIn("R20_NIGHT", d.risk.rule_hits)

    def test_scam_escalation_only_goes_up(self):
        self.s.escalate_scam(RiskLevel.HIGH, ["x"])
        self.s.escalate_scam(RiskLevel.LOW, [])
        self.assertEqual(self.s.scam_level, RiskLevel.HIGH)
        self.assertEqual(self.draft().risk.level, RiskLevel.HIGH)

    def test_deterministic(self):
        a = self.draft("p_son", 50000).risk
        self.s = Session(session_id="t2")
        b = self.draft("p_son", 50000).risk
        self.assertEqual((a.level, a.rule_hits), (b.level, b.rule_hits))


class TestSigningAndExecution(KernelTestBase):
    def test_happy_path(self):
        d = self.draft()
        tok = self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint")
        r = self.kernel.commit(self.s, d.draft_id, tok)
        self.assertEqual(r["status"], "SUCCESS")
        self.assertEqual(self.bank.account("u_chen", "SAV-001")["balance_cents"], 325000 - 20000)

    def test_digest_mismatch_rejected(self):
        d = self.draft()
        with self.assertRaises(KernelError) as e:
            self.kernel.authorize(self.s, d.draft_id, "0" * 64, "demo-fingerprint")
        self.assertEqual(e.exception.code, "DIGEST_MISMATCH")

    def test_tamper_after_authorize_rejected(self):
        d = self.draft()
        tok = self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint")
        d.amount_cents = 999900
        with self.assertRaises(KernelError):
            self.kernel.commit(self.s, d.draft_id, tok)
        self.assertEqual(self.bank.executed, {})

    def test_token_replay_rejected_by_token_service(self):
        ts = TokenService(b"k")
        tok = ts.issue("d1", "h")
        self.assertTrue(ts.verify_and_consume(tok, "d1", "h")[0])
        ok, why = ts.verify_and_consume(tok, "d1", "h")
        self.assertFalse(ok)
        self.assertIn("replay", why)

    def test_forged_token_rejected(self):
        ts = TokenService(b"k")
        forged = TokenService(b"attacker").issue("d1", "h")
        self.assertFalse(ts.verify_and_consume(forged, "d1", "h")[0])

    def test_cooling_blocks_authorize_then_allows(self):
        d = self.draft(cents=150000)
        with self.assertRaises(KernelError):
            self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint")
        d.cooling_until = time.time() - 1
        # family the customer has paid before: no second reviewer (see test_contract.WhoNeedsAReviewer)
        tok = self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint")
        self.assertEqual(self.kernel.commit(self.s, d.draft_id, tok)["status"], "SUCCESS")

    def test_medium_requires_verify_answer(self):
        d = self.draft("p_son", 50000)
        with self.assertRaises(KernelError) as e:
            self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint")
        self.assertEqual(e.exception.code, "VERIFY_REQUIRED")
        self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint", verify_answer=True)

    def test_idempotent_execution(self):
        r1 = self.bank.execute_payment("u_chen", "SAV-001", "p_son", 100, "same-key")
        r2 = self.bank.execute_payment("u_chen", "SAV-001", "p_son", 100, "same-key")
        self.assertEqual(r1["txn_id"], r2["txn_id"])
        self.assertEqual(self.bank.account("u_chen", "SAV-001")["balance_cents"], 325000 - 100)

    def test_second_draft_while_pending_rejected(self):
        self.draft()
        with self.assertRaises(KernelError) as e:
            self.draft("p_son", 100)
        self.assertEqual(e.exception.code, "PENDING_DRAFT")


class TestEvidenceGrounding(KernelTestBase):
    """The payee and amount must be backed by what the user actually said (kernel/evidence.py)."""

    def test_grounded_payment_is_low(self):
        self.say("Send two hundred to my daughter")
        d = self.draft(said=False)
        self.assertEqual(d.risk.level, RiskLevel.LOW)
        self.assertEqual(d.you_said, "Send two hundred to my daughter")

    def test_amount_not_said_is_medium_and_flagged(self):
        self.say("Send money to my daughter, the usual amount")
        d = self.draft(said=False)
        self.assertEqual(d.risk.level, RiskLevel.MEDIUM)
        self.assertIn("R50_AMOUNT_NOT_SAID", d.risk.rule_hits)
        self.assertFalse(d.grounding["amount"])

    def test_payee_not_said_is_high(self):
        self.say("Send two hundred dollars please")
        d = self.draft("p_son", said=False)
        self.assertIn("R51_PAYEE_NOT_SAID", d.risk.rule_hits)
        self.assertEqual(d.risk.level, RiskLevel.HIGH)

    def test_nothing_said_is_blocked(self):
        # e.g. the model was steered by text hidden in a bill: the user only asked about bills
        self.say("What bills do I have?")
        d = self.draft("p_son", 300000, said=False)
        self.assertEqual(d.risk.level, RiskLevel.BLOCK)
        self.assertIn("R52_NOT_REQUESTED", d.risk.rule_hits)

    def test_bill_amount_comes_from_the_bill(self):
        self.say("Pay my utilities bill")
        d = self.kernel.create_draft(self.s, kind="bill", payee_id="p_sp", amount_cents=8640, bill_id="b_sp_oct",
                                     local_hour=14)
        self.assertEqual(d.grounding["amount_source"], "bill")
        self.assertEqual(d.risk.level, RiskLevel.LOW)

    def test_multi_turn_quote_joins_both_pieces(self):
        self.say("Send money to my son")
        self.say("three hundred")
        d = self.draft("p_son", 30000, said=False, evidence="three hundred")
        self.assertEqual(d.you_said, "Send money to my son … three hundred")

    def test_quote_is_part_of_the_signed_digest(self):
        from app.kernel.signing import compute_digest
        d = self.draft()
        before = compute_digest(d)
        d.you_said = "something else"
        self.assertNotEqual(before, compute_digest(d))

    def test_amount_words_and_digits(self):
        from app.kernel.evidence import amounts_in
        self.assertTrue({20000, 5000} <= amounts_in("two hundred, or maybe $50"))
        self.assertIn(2050, amounts_in("twenty dollars fifty"))
        self.assertNotIn(1234567800, amounts_in("account 12345678"))


class TestDeviceKeySigning(KernelTestBase):
    """The real path: the browser's P-256 key signs the exact challenge; nothing else moves money."""

    def setUp(self):
        super().setUp()
        from app.kernel import p256
        self.p256 = p256
        self.kernel.allow_mock = False
        self.d_priv, self.jwk = p256.generate_keypair()
        self.kernel.register_key(self.s, self.jwk)

    def signed(self, d, priv=None, **kw):
        import base64
        payload = self.kernel.issue_challenge(self.s, d.draft_id, d.digest, **kw)
        sig = base64.b64encode(self.p256.sign(priv or self.d_priv, payload.encode())).decode()
        return {"payload": payload, "signature": sig}

    def test_happy_path_and_verifiable_receipt(self):
        import json, subprocess, sys, tempfile
        d = self.draft()
        tok = self.kernel.authorize(self.s, d.draft_id, d.digest, self.signed(d))
        r = self.kernel.commit(self.s, d.draft_id, tok)
        self.assertEqual(r["status"], "SUCCESS")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(r["verifiable"], f)
        out = subprocess.run([sys.executable, "scripts/verify_receipt.py", f.name], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("VALID", out.stdout)

    def test_edited_receipt_fails_offline_check(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("vr", "scripts/verify_receipt.py")
        vr = importlib.util.module_from_spec(spec); spec.loader.exec_module(vr)
        d = self.draft()
        r = self.kernel.commit(self.s, d.draft_id, self.kernel.authorize(self.s, d.draft_id, d.digest, self.signed(d)))
        rec = r["verifiable"]
        rec["card"]["amount_cents"] = 2000000
        self.assertFalse(all(ok for _, ok in vr.check(rec)))

    def test_demo_string_rejected_when_mock_off(self):
        d = self.draft()
        with self.assertRaises(KernelError) as e:
            self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint")
        self.assertEqual(e.exception.code, "AUTH_FAILED")

    def test_attacker_key_rejected(self):
        d = self.draft()
        attacker, _ = self.p256.generate_keypair()
        with self.assertRaises(KernelError) as e:
            self.kernel.authorize(self.s, d.draft_id, d.digest, self.signed(d, priv=attacker))
        self.assertEqual(e.exception.code, "INVALID_SIGNATURE")
        self.assertEqual(self.bank.executed, {})

    def test_tampered_payload_rejected(self):
        import json
        d = self.draft()
        a = self.signed(d)
        body = json.loads(a["payload"]); body["amount_cents"] = 2000000
        a["payload"] = json.dumps(body)
        with self.assertRaises(KernelError) as e:
            self.kernel.authorize(self.s, d.draft_id, d.digest, a)
        self.assertEqual(e.exception.code, "PAYLOAD_MISMATCH")

    def test_signature_is_single_use(self):
        d = self.draft()
        a = self.signed(d)
        self.kernel.authorize(self.s, d.draft_id, d.digest, a)
        with self.assertRaises(KernelError) as e:
            self.kernel.authorize(self.s, d.draft_id, d.digest, a)
        self.assertEqual(e.exception.code, "PAYLOAD_MISMATCH")

    def test_new_challenge_invalidates_old_signature(self):
        d = self.draft()
        old = self.signed(d)
        self.kernel.issue_challenge(self.s, d.draft_id, d.digest)
        with self.assertRaises(KernelError):
            self.kernel.authorize(self.s, d.draft_id, d.digest, old)

    def test_expired_challenge_rejected(self):
        import base64, json
        from app.kernel import signing
        d = self.draft()
        payload = signing.build_challenge(self.s.session_id, d, ttl=-1)
        self.s.challenges[d.draft_id] = payload
        sig = base64.b64encode(self.p256.sign(self.d_priv, payload.encode())).decode()
        with self.assertRaises(KernelError) as e:
            self.kernel.authorize(self.s, d.draft_id, d.digest, {"payload": payload, "signature": sig})
        self.assertEqual(e.exception.code, "EXPIRED")

    def test_draft_changed_after_challenge_rejected(self):
        d = self.draft()
        a = self.signed(d)
        d.amount_cents = 999900            # server-side tampering after the user was shown the card
        with self.assertRaises(KernelError) as e:
            self.kernel.authorize(self.s, d.draft_id, d.digest, a)
        self.assertEqual(e.exception.code, "DIGEST_MISMATCH")

    def test_verify_question_needed_before_challenge(self):
        d = self.draft("p_son", 50000)
        with self.assertRaises(KernelError) as e:
            self.kernel.issue_challenge(self.s, d.draft_id, d.digest)
        self.assertEqual(e.exception.code, "VERIFY_REQUIRED")
        self.kernel.authorize(self.s, d.draft_id, d.digest, self.signed(d, verify_answer=True), verify_answer=True)

    def test_key_cannot_be_swapped(self):
        _, other = self.p256.generate_keypair()
        with self.assertRaises(KernelError) as e:
            self.kernel.register_key(self.s, other)
        self.assertEqual(e.exception.code, "KEY_EXISTS")
        self.kernel.register_key(self.s, self.jwk)          # same key again is fine (browser reload)

    def test_private_key_never_accepted(self):
        with self.assertRaises(KernelError):
            self.kernel.register_key(Session(session_id="z"), {**self.jwk, "d": "AAAA"})


class TestStateMachine(unittest.TestCase):
    def test_cannot_skip_to_executed(self):
        s = Session(session_id="x")
        with self.assertRaises(IllegalTransition):
            s.transition(Phase.EXECUTED)


class TestAudit(KernelTestBase):
    def test_chain_detects_tampering(self):
        d = self.draft()
        tok = self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint")
        self.kernel.commit(self.s, d.draft_id, tok)
        self.assertTrue(self.audit.verify()["ok"])
        lines = self.audit.path.read_text(encoding="utf-8").splitlines()
        i = next(n for n, l in enumerate(lines) if '"amount_cents":20000' in l)
        lines[i] = lines[i].replace('"amount_cents":20000', '"amount_cents":2000', 1)   # quietly lower the amount
        self.audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = AuditLog(self.audit.path).verify()
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at_line"], i + 1)


class TestTextParse(unittest.TestCase):
    def test_amounts(self):
        cases = {"send two hundred to my daughter": 200, "twenty dollars fifty": 20.5,
                 "twenty dollars and fifty cents": 20.5, "twelve thousand": 12000,
                 "three thousand and five": 3005, "transfer $1,500": 1500, "two hundred and fifty": 250,
                 "a hundred dollars": 100, "1.5k": 1500, "send some money": None,
                 "send two hundread to my daughter": None, "account 12345678": None,
                 # how people say amounts: "one fifty" is 150, not 51
                 "send my son two hundred, no wait, one fifty": 150, "two fifty to my daughter": 250,
                 "one twenty five dollars": 125, "fifty five dollars": 55, "twenty one dollars": 21}
        for text, want in cases.items():
            self.assertEqual(parse_amount(text), want, text)

    def test_words(self):
        self.assertEqual(amount_words_en(20000), "two hundred dollars")
        self.assertEqual(amount_words_en(8640), "eighty-six dollars and forty cents")


if __name__ == "__main__":
    unittest.main()
