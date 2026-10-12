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
        d = self.model_drafts("Send 100 to my son", "draft_transfer",
                              {"payee_id": "p_son", "amount": 100, "repeat": "monthly"})
        self.assertEqual(d.verification["status"], "mismatch")          # frozen by the independent check
        self.assertEqual(self.s.phase, Phase.FROZEN)

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
                                        "DBS Fund Transfer · POST /fund-transfers (draft) (mock)"])
