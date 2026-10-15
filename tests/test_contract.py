"""Contract boundaries: real signatures, separate approval, atomic frequency and honest evidence."""
import tempfile
import time
import unittest
import base64
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from app.config import settings
from app.contract_lab import run_showcase
from app.lab import sandbox
from app.bank.gateway import GatewayError
from app.bank.mock_bank import MockBank
from app.kernel.executor import KernelError
from app.kernel.signing import compute_digest
from app.kernel.signing import build_challenge
from app.kernel import p256
from scripts.verify_receipt import check


class ContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sb = sandbox(self.tmp.name)

    def large(self):
        # a never-paid person: Enhanced protection also asks "is this your own idea?", answered yes below
        stranger = self.sb.bank.add_payee("u_chen", "John Tan", "OCBC", "1234567890", "friend")["payee_id"]
        d = self.sb.ask("Send 1500 to John Tan", payee=stranger, cents=150000)
        d.cooling_until = time.time() - 1
        return d

    def test_secondary_is_required_even_after_cooling(self):
        d = self.large()
        with self.assertRaises(KernelError) as e:
            self.sb.sign(d, verify_answer=True)
        self.assertEqual(e.exception.code, "SECONDARY_APPROVAL_REQUIRED")
        self.assertEqual(self.sb.bank.executed, {})
        self.assertEqual(d.decision["action"], "wait_for_secondary_approval")

    def test_approved_exact_card_executes_and_persists_evidence(self):
        d = self.large()
        self.sb.kernel.approve_secondary(self.sb.session, d.draft_id, d.digest)
        r = self.sb.pay(d, self.sb.sign(d, verify_answer=True), verify_answer=True)
        record = r["verifiable"]["decision"]
        self.assertEqual(record["action"], "executed")
        self.assertEqual(record["checks"]["execution"]["status"], "pass")
        self.assertIsNotNone(record["secondary_approval"])
        self.assertTrue(all(ok for _, ok in check(r["verifiable"])))
        self.assertEqual(self.sb.bank.transaction("u_chen", d.draft_id)["verifiable"]["decision"], record)
        self.assertIsNone(self.sb.kernel.reviews.valid("u_chen", self.sb.session.session_id, d.draft_id, d.digest))

    def test_expired_review_after_signing_stops_commit(self):
        d = self.large()
        self.sb.kernel.approve_secondary(self.sb.session, d.draft_id, d.digest)
        token = self.sb.kernel.authorize(self.sb.session, d.draft_id, d.digest, self.sb.sign(d, verify_answer=True), verify_answer=True)
        self.sb.kernel.reviews.records[(self.sb.session.session_id, d.draft_id)]["expires_at"] = 0
        with self.assertRaises(KernelError) as e:
            self.sb.kernel.commit(self.sb.session, d.draft_id, token)
        self.assertEqual(e.exception.code, "SECONDARY_APPROVAL_REQUIRED")
        self.assertEqual(self.sb.balance(), 325000)

    def test_gateway_checks_review_independently(self):
        d = self.large()
        self.sb.kernel.approve_secondary(self.sb.session, d.draft_id, d.digest)
        self.sb.kernel.authorize(self.sb.session, d.draft_id, d.digest, self.sb.sign(d, verify_answer=True), verify_answer=True)
        self.sb.kernel.reviews.revoke(self.sb.session.session_id, d.draft_id)
        with self.assertRaises(GatewayError) as e:
            self.sb.kernel.gateway.execute(user_id="u_chen", session_id=self.sb.session.session_id,
                card=d.card_fields(), digest=d.digest, auth=self.sb.session.signatures[d.draft_id],
                idempotency_key=d.draft_id, decision={"secondary_approval": {"approved": True}})
        self.assertEqual(e.exception.code, "GW_SECONDARY_APPROVAL_REQUIRED")
        self.assertFalse(self.sb.bank.executed)

    def test_review_is_bound_to_customer_session_digest_and_cancel(self):
        d = self.large()
        self.sb.kernel.approve_secondary(self.sb.session, d.draft_id, d.digest)
        store = self.sb.kernel.reviews
        self.assertIsNone(store.valid("other", self.sb.session.session_id, d.draft_id, d.digest))
        self.assertIsNone(store.valid("u_chen", "other", d.draft_id, d.digest))
        self.assertIsNone(store.valid("u_chen", self.sb.session.session_id, d.draft_id, "0" * 64))
        self.sb.kernel.cancel(self.sb.session, d.draft_id)
        self.assertIsNone(store.valid("u_chen", self.sb.session.session_id, d.draft_id, d.digest))

    def test_failed_approval_audit_leaves_no_usable_approval(self):
        d = self.large()
        with patch.object(self.sb.audit, "append", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                self.sb.kernel.approve_secondary(self.sb.session, d.draft_id, d.digest)
        self.assertIsNone(self.sb.kernel.reviews.valid("u_chen", self.sb.session.session_id, d.draft_id, d.digest))

    def test_gateway_checks_signed_dependencies_without_kernel_decision(self):
        d = self.sb.ask("Send 50 to my daughter", cents=5000)
        d.dependency_ids = ["unexecuted"]
        d.digest = compute_digest(d)
        # Deliberately bypass the kernel but use a valid enrolled device signature.
        payload = build_challenge(self.sb.session.session_id, d)
        auth = {"payload":payload, "method":"device_key",
                "signature":base64.b64encode(p256.sign(self.sb.device_key, payload.encode())).decode()}
        with self.assertRaises(GatewayError) as e:
            self.sb.kernel.gateway.execute(user_id="u_chen", session_id=self.sb.session.session_id,
                card=d.card_fields(), digest=d.digest, auth=auth, idempotency_key=d.draft_id)
        self.assertEqual(e.exception.code, "GW_DEPENDENCY_NOT_COMPLETED")
        self.assertFalse(self.sb.bank.executed)

    def test_uncompleted_dependency_blocks_signature_and_is_signed_content(self):
        self.sb.session.messages.append({"role":"user", "content":"Send 50 to my daughter", "reference_parent_id":"not-posted"})
        from app.agent.verifier import Verifier
        d = self.sb.kernel.create_draft(self.sb.session, kind="transfer", payee_id="p_daughter", amount_cents=5000,
            verification=Verifier(None, self.sb.bank).verdict(self.sb.session))
        self.assertEqual(d.decision["checks"]["plan"]["status"], "fail")
        with self.assertRaises(KernelError) as e:
            self.sb.sign(d)
        self.assertEqual(e.exception.code, "DEPENDENCY_NOT_COMPLETED")
        d.dependency_ids = []
        self.assertNotEqual(compute_digest(d), d.digest)

    def test_velocity_is_a_hard_stop_even_with_yes_answer(self):
        self.sb.bank.recent_exec_times["u_chen"] = [time.time()] * settings.velocity_max
        d = self.sb.ask("Send 50 to my daughter", cents=5000)
        with self.assertRaises(KernelError):
            self.sb.sign(d, verify_answer=True)
        self.assertIn("R21_VELOCITY", d.decision["reason_codes"])
        self.assertEqual(d.decision["action"], "reject")

    def test_atomic_last_velocity_slot_and_persistence(self):
        bank = MockBank(self.tmp.name + "/ledger.sqlite3")
        bank.recent_exec_times["u_chen"] = [time.time()] * (settings.velocity_max - 1)
        def attempt(i):
            try:
                return bank.execute_payment("u_chen", "SAV-001", "p_daughter", 100, str(i))["status"]
            except ValueError as e:
                return str(e)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, [1, 2]))
        self.assertEqual(results.count("SUCCESS"), 1)
        self.assertTrue(any("R21_VELOCITY" in r for r in results))
        restarted = MockBank(self.tmp.name + "/ledger.sqlite3")
        self.assertEqual(restarted.account("u_chen", "SAV-001")["balance_cents"], 324900)
        with self.assertRaisesRegex(ValueError, "R21_VELOCITY"):
            restarted.execute_payment("u_chen", "SAV-001", "p_daughter", 100, "third")
        restarted.recent_exec_times["u_chen"] = [time.time() - settings.velocity_window_min * 60 - 1]
        self.assertEqual(restarted.execute_payment("u_chen", "SAV-001", "p_daughter", 100, "later")["status"], "SUCCESS")

    def test_evidence_does_not_claim_signature_before_signing(self):
        d = self.sb.ask("Send 50 to my daughter", cents=5000)
        self.assertEqual(d.decision["checks"]["authorization"]["status"], "pending")
        self.assertEqual(d.decision["checks"]["execution"]["status"], "pending")
        self.assertEqual(d.decision["verifier"]["mode"], "offline_shared_parser")
        self.assertEqual(self.sb.audit.for_session(self.sb.session.session_id)[-1]["event"], "contract.decision")

    def test_showcase_measures_actual_ledger_outcomes(self):
        result = run_showcase()
        self.assertEqual(result["passed"], result["total"])
        for row in result["cases"]:
            self.assertEqual(row["ledger_debit_cents"], 5000 if row["id"] == "normal" else 0)
        self.assertEqual(result["comparison"][-1]["unsafe_candidates_admitted"], 0)
        self.assertEqual(result["comparison"][-1]["normal_candidates_admitted"], 1)


class WhoNeedsAReviewer(unittest.TestCase):
    """Family and people paid before: no reviewer. Someone new above the threshold, or a large investment: reviewer."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sb = sandbox(self.tmp.name)

    def card(self, payee_id, cents, kind="transfer"):
        return {"user_id": "u_chen", "payee_id": payee_id, "amount_cents": cents, "kind": kind}

    def test_rules(self):
        from app.kernel.contract import secondary_required
        new = self.sb.bank.add_payee("u_chen", "John Tan", "OCBC", "1234567890", "friend")["payee_id"]
        self.assertFalse(secondary_required(self.card("p_daughter", 200000), self.sb.bank))   # family, paid before
        self.assertFalse(secondary_required(self.card("own:JNT-003", 400000), self.sb.bank))  # own accounts
        self.assertFalse(secondary_required(self.card("p_cc", 120000), self.sb.bank))         # a bill
        self.assertFalse(secondary_required(self.card(new, 50000), self.sb.bank))             # new, small
        self.assertTrue(secondary_required(self.card(new, 150000), self.sb.bank))             # new, large
        self.assertFalse(secondary_required(self.card("s_aapl", 275000, "investment"), self.sb.bank))
        self.assertTrue(secondary_required(self.card("s_aapl", 350000, "investment"), self.sb.bank))
