"""Reviewer access control and exact-card binding, without a live bank or model."""
import unittest
from unittest.mock import patch

from starlette.testclient import TestClient
from app import runtime, security
from app.config import settings
from app.server import app


class ReviewHttpTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, base_url="http://localhost")
        self.addCleanup(self.client.close)
        key = patch.object(settings, "secondary_review_key", "test-operator-secret")
        key.start()
        self.addCleanup(key.stop)
        security._hits.clear()
        self.s = runtime.sessions.new_for_visitor("abcdef0123456789")
        runtime.agent.run_turn(self.s, "Send 1500 to my daughter")
        self.d = self.s.current_draft
        self.ticket = {"session_id":self.s.session_id, "draft_id":self.d.draft_id,
                       "digest":self.d.digest, "operation":"approve"}

    def test_customer_cannot_self_approve_or_smuggle_key_in_body(self):
        r = self.client.post("/api/review/secondary", json={**self.ticket, "key":"test-operator-secret"})
        self.assertEqual(r.status_code, 403)
        self.assertIsNone(runtime.kernel.reviews.valid(self.s.user_id, self.s.session_id, self.d.draft_id, self.d.digest))

    def test_inspect_then_approve_never_moves_money(self):
        headers = {"X-Review-Key":"test-operator-secret"}
        before = runtime.bank.account(self.s.user_id, "SAV-001")["balance_cents"]
        r = self.client.post("/api/review/secondary", headers=headers, json={**self.ticket, "operation":"inspect"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["card"]["amount"], "S$1,500.00")
        self.assertNotIn("test-operator-secret", r.text)
        r = self.client.post("/api/review/secondary", headers=headers, json=self.ticket)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["simulation"])
        self.assertEqual(runtime.bank.account(self.s.user_id, "SAV-001")["balance_cents"], before)
        card = self.client.get("/api/card/" + self.s.session_id).json()["card"]
        self.assertFalse(card["secondary_required"])
        self.assertEqual(card["decision"]["checks"]["authorization"]["status"], "pending")

    def test_wrong_digest_and_cancelled_card_refused(self):
        headers = {"X-Review-Key":"test-operator-secret"}
        r = self.client.post("/api/review/secondary", headers=headers, json={**self.ticket, "digest":"wrong"})
        self.assertEqual(r.json()["code"], "DIGEST_MISMATCH")
        runtime.kernel.cancel(self.s, self.d.draft_id)
        r = self.client.post("/api/review/secondary", headers=headers, json=self.ticket)
        self.assertEqual(r.json()["code"], "REVIEW_NOT_PENDING")

    def test_unconfigured_review_is_fail_closed(self):
        with patch.object(settings, "secondary_review_key", ""):
            r = self.client.post("/api/review/secondary", json=self.ticket)
        self.assertEqual(r.status_code, 503)

    def test_invalid_reviewer_attempts_are_rate_limited(self):
        for _ in range(20):
            self.assertEqual(self.client.post("/api/review/secondary", json=self.ticket).status_code, 403)
        self.assertEqual(self.client.post("/api/review/secondary", json=self.ticket).status_code, 429)
