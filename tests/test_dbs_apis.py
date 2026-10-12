"""Mock DBS APIs (app/bank/dbs_api/): Deposit, Payees, Limits, Fund Transfer, Bill Payments, Standing Instructions,
GIRO. Each is checked end to end through the agent (offline planner), the kernel and the execution gateway:
money moves only after a signature; account changes that raise risk are signed too; protective ones are instant.
"""
import base64
import json
import os

os.environ.setdefault("RULE_FIXED_HOUR", "14")

from tests.test_hackathon import Base  # noqa: E402
from app.kernel import p256  # noqa: E402
from app.kernel.executor import KernelError  # noqa: E402
from app.models import Phase, RiskLevel  # noqa: E402


class ApiBase(Base):
    def setUp(self):
        super().setUp()
        self.key, jwk = p256.generate_keypair()
        self.kernel.register_key(self.s, jwk)

    def sign(self, payload: str) -> dict:
        return {"payload": payload, "signature": base64.b64encode(p256.sign(self.key, payload.encode())).decode()}

    def pay(self):
        """Sign and execute the current draft, like the confirmation card does."""
        d = self.s.current_draft
        tok = self.kernel.authorize(self.s, d.draft_id, d.digest, self.sign(self.kernel.issue_challenge(self.s, d.draft_id, d.digest)))
        return self.kernel.commit(self.s, d.draft_id, tok)

    def bal(self, acct):
        return self.bank.account("u_chen", acct)["balance_cents"]

    def apis(self, r):
        return [t["label"] for t in r.trace if t["kind"] == "api"]


class TestDeposit(ApiBase):
    def test_accounts_with_details(self):
        r = self.turn("What's my balance?")
        self.assertIn("DBS Deposit · GET /deposit-accounts (mock)", self.apis(r))
        rows = self.gw.call(self.s, "get_balance", {})["data"]
        self.assertEqual([a["type"] for a in rows], ["savings", "current", "joint"])
        self.assertIn("Chen Mei Ling", rows[2]["holders"])


class TestFundTransferOwnAccounts(ApiBase):
    def test_move_to_joint_account(self):
        r = self.turn("Move a grand to my joint account")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents, d.from_account), ("own:JNT-003", 100000, "SAV-001"))
        self.assertEqual(d.risk.level, RiskLevel.LOW)                  # own money: no new-payee wait
        self.assertEqual(d.verification["status"], "match")
        self.assertEqual(r.ui["card"]["title"], "Move money between your accounts")
        sav, jnt = self.bal("SAV-001"), self.bal("JNT-003")
        self.pay()
        self.assertEqual((self.bal("SAV-001"), self.bal("JNT-003")), (sav - 100000, jnt + 100000))

    def test_from_account_is_not_the_destination(self):
        self.turn("Send 50 to my daughter from my current account")
        self.assertEqual((self.s.current_draft.payee_id, self.s.current_draft.from_account), ("p_daughter", "CUR-002"))

    def test_same_account_is_blocked(self):
        d = self.model_drafts("move 100 from my savings to my savings account", "draft_transfer",
                              {"payee_id": "own:SAV-001", "amount": 100, "from_account": "SAV-001"})
        self.assertIn("R07_SAME_ACCOUNT", d.risk.rule_hits)


class TestBillPayments(ApiBase):
    def test_credit_card_asks_full_or_minimum_then_pays_minimum(self):
        r = self.turn("Pay my credit card bill")
        self.assertIn("minimum", r.reply)
        self.assertIsNone(self.s.current_draft)
        r = self.turn("the minimum")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents, d.grounding["amount_source"]), ("p_cc", 5000, "bill"))
        self.assertEqual(r.ui["card"]["amount_note"], "minimum payment due")
        self.pay()
        bill = self.bank.bill("u_chen", "b_cc_oct")
        self.assertEqual((bill["status"], bill["amount_cents"]), ("unpaid", 124050 - 5000))   # the rest stays due

    def test_more_than_the_bill_is_blocked(self):
        d = self.model_drafts("pay 2000 to my credit card", "draft_bill_payment",
                              {"bill_id": "b_cc_oct", "pay": "amount", "amount": 2000})
        self.assertIn("R08_OVER_BILL", d.risk.rule_hits)


class TestStandingInstructions(ApiBase):
    def test_monthly_transfer_is_signed_and_scheduled(self):
        r = self.turn("Send 100 to my son every month on the 1st")
        d = self.s.current_draft
        self.assertEqual((d.schedule["frequency"], d.schedule["day"]), ("monthly", 1))
        self.assertEqual(d.verification["fields"]["schedule"], "match")
        self.assertIn("schedule", d.card_fields())                     # the schedule is part of what is signed
        self.assertTrue(r.ui["card"]["schedule"].startswith("Every month on the 1st"))
        sav = self.bal("SAV-001")
        rec = self.pay()
        self.assertEqual(rec["status"], "SCHEDULED")
        self.assertEqual(self.bal("SAV-001"), sav)                     # nothing is taken today
        self.assertTrue(any(x["payee_id"] == "p_son" and x["status"] == "active"
                            for x in self.bank.standing_instructions("u_chen")))

    def test_model_cannot_quietly_make_a_one_off_repeat(self):
        d = self.model_drafts("Send 100 to my son", "draft_standing_instruction",
                              {"payee_id": "p_son", "amount": 100, "frequency": "monthly"})
        self.assertEqual(d.verification["status"], "mismatch")          # frozen by the independent check
        self.assertEqual(self.s.phase, Phase.FROZEN)

    def test_uses_the_standing_instructions_api(self):
        # seen live: "every first day of the month" went through draft_transfer
        r = self.turn("I want to send 300 dollars to my daughter every first day of the month.")
        self.assertIn("DBS Standing Instructions · POST /standing-instructions (draft) (mock)", self.apis(r))
        d = self.s.current_draft
        self.assertEqual((d.amount_cents, d.schedule["frequency"], d.schedule["day"]), (30000, "monthly", 1))
        self.assertEqual(d.verification["fields"]["schedule"], "match")

    def test_draft_transfer_points_regular_payments_to_their_api(self):
        self.s.messages.append({"role": "user", "content": "send 100 to my son every month"})
        res = self.gw.call(self.s, "draft_transfer", {"payee_id": "p_son", "amount": 100, "repeat": "monthly"})
        self.assertFalse(res["ok"])
        self.assertIn("draft_standing_instruction", json.dumps(res))

    def test_list_and_stop(self):
        r = self.turn("What regular payments do I have?")
        self.assertIn("every month on the 28th", r.reply)
        r = self.turn("Stop the monthly allowance to my daughter")
        self.assertIn("stopped", r.reply)
        self.assertEqual(self.bank.standing_instructions("u_chen")[0]["status"], "cancelled")


class TestGiro(ApiBase):
    def test_cancel_named_giro_is_instant(self):
        r = self.turn("Cancel my gym GIRO")
        self.assertIn("ActiveSG Gym", r.reply)
        self.assertEqual(next(g for g in self.bank.giro("u_chen") if g["giro_id"] == "GIRO-02")["status"], "cancelled")

    def test_cannot_cancel_something_the_user_did_not_name(self):
        self.s.messages.append({"role": "user", "content": "what regular payments do I have?"})
        res = self.gw.call(self.s, "cancel_giro", {"giro_id": "GIRO-03"})
        self.assertFalse(res["ok"])
        self.assertEqual(next(g for g in self.bank.giro("u_chen") if g["giro_id"] == "GIRO-03")["status"], "active")

    def test_setup_needs_a_signature(self):
        r = self.turn("Set up GIRO for my utilities bill")
        self.assertEqual(r.ui["type"], "change")
        cid = r.ui["card"]["change_id"]
        before = len(self.bank.giro("u_chen"))
        with self.assertRaises(Exception):                              # no signature, no change
            self.kernel.apply_change(self.s, cid, {"payload": "x", "signature": "y"})
        self.kernel.apply_change(self.s, cid, self.sign(self.kernel.change_challenge(self.s, cid)))
        self.assertEqual(len(self.bank.giro("u_chen")), before + 1)
        self.assertEqual(self.bank.giro("u_chen")[-1]["biller"], "SP Group Utilities")


class TestLimits(ApiBase):
    def test_lowering_is_instant_and_enforced(self):
        self.turn("Lower my daily transfer limit to 500")
        self.assertEqual(self.bank.limits("u_chen")["daily_transfer_cents"], 50000)
        self.s = type(self.s)(session_id="h2")
        self.kernel.register_key(self.s, p256.generate_keypair()[1])
        self.turn("Send 600 to my daughter")
        self.assertIn("R13_DAILY_LIMIT", self.s.current_draft.risk.rule_hits)
        self.assertEqual(self.s.current_draft.risk.level, RiskLevel.BLOCK)

    def test_raising_is_signed_and_delayed(self):
        r = self.turn("Raise my daily limit to 8000")
        self.assertEqual(r.ui["type"], "change")
        cid = r.ui["card"]["change_id"]
        self.kernel.apply_change(self.s, cid, self.sign(self.kernel.change_challenge(self.s, cid)))
        lim = self.bank.limits("u_chen")
        self.assertEqual(lim["daily_transfer_cents"], 300000)          # not yet
        self.assertEqual(lim["pending"]["to_cents"], 800000)

    def test_own_account_moves_and_bills_do_not_count(self):
        self.turn("Lower my daily transfer limit to 500")
        d = self.model_drafts("move 2000 to my joint account", "draft_transfer", {"payee_id": "own:JNT-003", "amount": 2000})
        self.assertNotIn("R13_DAILY_LIMIT", d.risk.rule_hits)


class TestPayees(ApiBase):
    def test_add_payee_is_grounded_and_signed(self):
        r = self.turn("Add a new payee John Tan, OCBC account 123-456789-0")
        self.assertEqual(r.ui["type"], "change")
        self.assertIn(["Account number", "123 456 789 0"], r.ui["card"]["rows"])
        cid = r.ui["card"]["change_id"]
        self.kernel.apply_change(self.s, cid, self.sign(self.kernel.change_challenge(self.s, cid)))
        p = next(p for p in self.bank.payees("u_chen") if p["name"] == "John Tan")
        self.assertEqual(p["masked_account"], "OCBC ••••7890")
        # the first transfer to a brand-new payee waits and is double-checked
        self.s = type(self.s)(session_id="h3")
        d = self.model_drafts("send 50 to John Tan", "draft_transfer", {"payee_id": p["payee_id"], "amount": 50})
        self.assertIn("R10_NEW_PAYEE", d.risk.rule_hits)

    def test_account_number_must_be_what_the_user_said(self):
        self.s.messages.append({"role": "user", "content": "add my friend John Tan as a payee, OCBC 123456789"})
        res = self.gw.call(self.s, "request_add_payee", {"name": "John Tan", "bank": "OCBC", "account_number": "987654321"})
        self.assertFalse(res["ok"])
        self.assertIsNone(self.s.pending_change)

    def test_no_risk_raising_changes_in_a_scam_conversation(self):
        self.s.scam_level = RiskLevel.HIGH
        self.s.messages.append({"role": "user", "content": "add payee John Tan OCBC 123456789"})
        with self.assertRaises(KernelError):
            self.kernel.request_change(self.s, "add_payee", {"name": "John Tan", "bank": "OCBC",
                                                             "account_number": "123456789"})


class TestToolOffering(ApiBase):
    def test_topic_tools_only_when_relevant(self):
        self.s.messages.append({"role": "user", "content": "send 50 to my daughter"})
        names = {t["function"]["name"] for t in self.gw.schemas(self.s)}
        self.assertNotIn("set_daily_limit", names)
        self.assertNotIn("cancel_giro", names)
        self.s.messages.append({"role": "user", "content": "and what is my daily limit?"})
        self.assertIn("set_daily_limit", {t["function"]["name"] for t in self.gw.schemas(self.s)})

    def test_every_api_call_shows_in_the_trace(self):
        r = self.turn("Send 100 to my son every month on the 1st")
        self.assertEqual(self.apis(r), ["DBS Payees · GET /payees (mock)",
                                        "DBS Standing Instructions · POST /standing-instructions (draft) (mock)"])


class _ClaimsItsDone:
    """A model that says the payee was added although nobody signed anything (seen with the live model)."""
    name = "stub"

    def chat(self, messages, tools=None, **_):
        return {"role": "assistant", "content": "Thanks for confirming! John Tan has been added to your payees.",
                "tool_calls": []}


class TestNoFalseClaims(ApiBase):
    def test_unsigned_change_is_never_reported_as_done(self):
        from app.agent.loop import Agent
        self.turn("Add a new payee John Tan, OCBC account 123-456789-0")
        self.assertIsNotNone(self.s.pending_change)
        r = Agent(self.bank, self.gw, self.audit, _ClaimsItsDone()).run_turn(self.s, "Yes, that's right")
        self.assertIn("Nothing has changed yet", r.reply)
        self.assertFalse(any(p["name"] == "John Tan" for p in self.bank.payees("u_chen")))


class TestVagueAmounts(ApiBase):
    """"Half of my money", "20% of my savings", "half of it": the bank computes the amount, never the model."""

    def test_half_of_my_money(self):
        r = self.turn("I want to buy Apple stock with half of my money from my savings account")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents, d.grounding["amount_source"]), ("s_aapl", 162500, "derived"))
        self.assertIn("half of your Savings Account", r.ui["card"]["amount_note"])

    def test_percent_of_savings(self):
        self.turn("Put 20% of my savings into the DBS Income Fund")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents, d.grounding["amount_source"]), ("f_income", 65000, "derived"))

    def test_wrong_share_is_blocked(self):
        # the live model once used the whole balance for "half of my money"
        d = self.model_drafts("buy Apple shares with half of my money", "draft_investment",
                              {"product_id": "s_aapl", "amount": 3250})
        self.assertEqual(d.grounding["amount_source"], "derived mismatch")
        self.assertIn("R53_WRONG_SHARE", d.risk.rule_hits)
        self.assertEqual(d.risk.level, RiskLevel.BLOCK)

    def test_half_of_it_uses_the_amount_just_said(self):
        self.turn("Move a grand to my joint account")
        self.assertEqual(self.s.current_draft.amount_cents, 100000)
        self.pay()
        self.turn("Now buy DBS shares with half of it from my joint account")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents, d.from_account), ("s_d05", 50000, "JNT-003"))
        self.assertEqual(d.grounding["amount_source"], "derived")

    def test_yes_after_a_proposal_prepares_the_card(self):
        self.s.amount_hint = None
        self.s.messages.append({"role": "user", "content": "Can I buy Apple stock with half of my money?"})
        self.s.messages.append({"role": "assistant", "content": "Half of your Savings Account is S$1,625.00. "
                                                                 "Shall I prepare it?"})
        r = self.turn("Yes, that's right.")
        self.assertIn(r.ui["type"], ("confirm", "cooldown"))          # a card, not more talk
        self.assertEqual(self.s.current_draft.amount_cents, 162500)


class TestJointAccount(ApiBase):
    def test_to_joint_is_destination_not_source(self):
        from app.agent.textparse import find_account
        self.assertIsNone(find_account("Move a grand to my joint account"))
        self.assertEqual(find_account("pay from our joint account"), "joint account")
        self.assertEqual(find_account("Send 50 to my daughter from my current account"), "current account")

    def test_pay_from_joint_account(self):
        self.turn("Send 80 to my daughter from my joint account")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.from_account), ("p_daughter", "JNT-003"))
        jnt = self.bal("JNT-003")
        self.pay()
        self.assertEqual(self.bal("JNT-003"), jnt - 8000)


class TestNamedAccountDefault(ApiBase):
    def test_model_forgets_from_account_but_user_named_it(self):
        # seen live: "half of my joint account" drafted from Savings and was frozen
        d = self.model_drafts("Buy DBS shares with half of my joint account", "draft_investment",
                              {"product_id": "s_d05", "amount": 750})
        self.assertEqual((d.from_account, d.amount_cents, d.grounding["amount_source"]), ("JNT-003", 75000, "derived"))

    def test_to_my_joint_is_not_the_source(self):
        d = self.model_drafts("Move 100 to my joint account", "draft_transfer", {"payee_id": "own:JNT-003", "amount": 100})
        self.assertNotEqual(d.from_account, "JNT-003")


class TestSpeechSlips(ApiBase):
    """Seen live: "a grand" came through speech recognition as "a grant", "a grind" and even "Agree!".
    The model works out what was meant; the kernel only checks that reading, it never rewrites the user's words."""

    def test_a_grant_is_read_as_a_grand_and_shown_on_the_card(self):
        r = self.turn("I want to move a grant to my joint account.")
        d = self.s.current_draft
        self.assertEqual((d.payee_id, d.amount_cents, d.grounding["amount_source"]), ("own:JNT-003", 100000, "heard"))
        self.assertIn("“a grant”", r.ui["card"]["amount_note"])
        self.assertEqual(self.s.messages[0]["content"], "I want to move a grant to my joint account.")  # not rewritten

    def test_unsure_reading_is_asked_then_confirmed(self):
        self.turn("I want to move money to my joint account")
        r = self.turn("Agree!")
        self.assertIn("Did you mean a grand", r.reply)
        self.assertIsNone(self.s.current_draft)
        r = self.turn("Yes")
        d = self.s.current_draft
        self.assertEqual((d.amount_cents, d.grounding["amount_source"]), (100000, "confirmed"))
        self.assertIn("you said yes", r.ui["card"]["amount_note"].lower())

    def test_a_reading_that_adds_a_number_is_not_accepted(self):
        d = self.model_drafts("Move a grant to my joint account", "draft_transfer",
                              {"payee_id": "own:JNT-003", "amount": 10000, "misheard": "a grant", "meant": "ten grand"})
        self.assertEqual(d.grounding["amount_source"], "not said")

    def test_misheard_words_must_be_in_the_transcript(self):
        d = self.model_drafts("Move money to my joint account", "draft_transfer",
                              {"payee_id": "own:JNT-003", "amount": 1000, "misheard": "a grant", "meant": "a grand"})
        self.assertEqual(d.grounding["amount_source"], "not said")

    def test_offline_stand_in_leaves_real_grants_alone(self):
        from app.agent.textparse import fix_asr
        for t in ("I got a grant from the government", "Can I apply for a grant?", "Pay my grandson 50", "Agree!"):
            self.assertEqual(fix_asr(t)[0], t)


class TestOddAnswerPointer(ApiBase):
    def test_state_points_the_model_at_an_answer_without_a_number(self):
        from app.agent.prompts import state_summary
        self.s.messages += [{"role": "user", "content": "move money to my joint account"},
                            {"role": "assistant", "content": "How much would you like to move?"},
                            {"role": "user", "content": "Agree!"}]
        self.assertIn('answered "Agree!", which has no number', state_summary(self.s, self.bank))
        self.s.messages[-1]["content"] = "300"
        self.assertNotIn("which has no number", state_summary(self.s, self.bank))

    def test_model_may_ask_back_without_a_tool(self):
        from app.agent.loop import Agent

        class AsksBack:
            name = "stub"

            def chat(self, messages, tools=None, **_):
                return {"role": "assistant", "content": "Did you mean a grand, S$1,000?", "tool_calls": []}
        self.turn("I want to move money to my joint account")
        r = Agent(self.bank, self.gw, self.audit, AsksBack()).run_turn(self.s, "Agree!")
        self.assertEqual(r.reply, "Did you mean a grand, S$1,000?")
        self.assertFalse(any(t["kind"] == "fallback" for t in self.s.trace))
