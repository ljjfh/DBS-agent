"""Regression tests for ledger atomicity, identity boundaries and signed credential removal."""
import base64
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from app.agent.llm import OfflineLLM
from app.agent.loop import Agent
from app.agent.tools import ToolGateway
from app.agent.verifier import Verifier
from app.bank.mock_bank import MockBank
from app.kernel.audit import AuditLog
from app.kernel.credentials import CredentialRegistry
from app.kernel.executor import Kernel, KernelError
from app.kernel.signing import Site
from app.kernel.state import Session, SessionStore, UnknownSession
from app.kernel import p256, webauthn
from scripts.verify_receipt import check


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'ledger.sqlite3'
        self.bank = MockBank(self.path)
        self.audit = AuditLog(Path(self.tmp.name) / 'audit.jsonl')
        self.kernel = Kernel(self.bank, self.audit, allow_mock=False, registry=CredentialRegistry())
        self.agent = Agent(self.bank, ToolGateway(self.bank, self.kernel, verifier=Verifier(None, self.bank)),
                           self.audit, OfflineLLM())
        self.s = Session('recovery')

    def pay(self):
        self.agent.run_turn(self.s, 'Send 50 to my daughter')
        d = self.s.current_draft
        key, pub = p256.generate_keypair()
        self.kernel.register_key(self.s, pub)
        payload = self.kernel.issue_challenge(self.s, d.draft_id, d.digest, verify_answer=True)
        assertion = {'payload': payload, 'signature': base64.b64encode(p256.sign(key, payload.encode())).decode()}
        token = self.kernel.authorize(self.s, d.draft_id, d.digest, assertion, verify_answer=True)
        return d, self.kernel.commit(self.s, d.draft_id, token)

    def enroll(self):
        auth = webauthn.SoftAuthenticator()
        opts = self.kernel.passkey_options(self.s, Site())
        self.kernel.passkey_register(self.s, Site(), **auth.register(webauthn.unb64u(opts['challenge'])))
        return auth

    def test_receipt_recovers_after_ledger_reopen(self):
        d, receipt = self.pay()
        reopened = MockBank(self.path)
        saved = reopened.transaction(self.s.user_id, d.draft_id)
        self.assertEqual(saved, receipt)
        self.assertEqual(reopened.account('u_chen', 'SAV-001')['balance_cents'], 320000)
        self.assertTrue(all(ok for _, ok in check(saved['verifiable'])))
        self.assertIsNone(reopened.transaction('another-customer', d.draft_id))

    def test_storage_failure_rolls_back_balance_and_bill(self):
        with patch.object(self.bank, '_save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.bank.execute_payment('u_chen', 'SAV-001', 'p_sp', 8640, 'bill', 'b_sp_oct')
        self.assertEqual(self.bank.account('u_chen', 'SAV-001')['balance_cents'], 325000)
        self.assertEqual(self.bank.bill('u_chen', 'b_sp_oct')['status'], 'unpaid')
        self.assertFalse(self.bank.executed)

    def test_audit_failure_keeps_durable_outbox_then_recovers(self):
        original = self.audit.append
        def fail_posting(event, *a, **kw):
            if event in ('gateway.posted', 'commit.executed'):
                raise OSError('audit unavailable')
            return original(event, *a, **kw)
        with patch.object(self.audit, 'append', side_effect=fail_posting):
            d, receipt = self.pay()
        reopened = MockBank(self.path)
        self.assertEqual(len(reopened.outbox), 2)
        self.assertEqual(reopened.transaction('u_chen', d.draft_id), receipt)
        reopened.flush_audit(self.audit)
        self.assertFalse(MockBank(self.path).outbox)
        events = self.audit.for_session(self.s.session_id)
        self.assertTrue(any(e['event'] == 'commit.executed' for e in events))
        self.assertTrue(self.audit.verify()['ok'])

    def test_parallel_bill_posting_only_debits_once(self):
        def post(i):
            try:
                return self.bank.execute_payment('u_chen', 'SAV-001', 'p_sp', 8640, f'bill-{i}', 'b_sp_oct')['status']
            except ValueError:
                return 'REJECTED'
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(post, range(2)))
        self.assertEqual(sorted(results), ['REJECTED', 'SUCCESS'])
        self.assertEqual(self.bank.account('u_chen', 'SAV-001')['balance_cents'], 316360)

    def test_invalid_bill_amount_does_not_debit(self):
        with self.assertRaises(ValueError):
            self.bank.execute_payment('u_chen', 'SAV-001', 'p_sp', 8641, 'bad', 'b_sp_oct')
        self.assertFalse(self.bank.executed)

    def test_passkey_removal_requires_fresh_signed_approval(self):
        auth = self.enroll()
        with self.assertRaises(KernelError):
            self.kernel.passkey_remove(self.s, Site())
        payload = self.kernel.passkey_remove_challenge(self.s, Site())
        assertion = auth.sign(payload)
        self.assertEqual(self.kernel.passkey_remove(self.s, Site(), assertion), 1)
        with self.assertRaises(KernelError):
            self.kernel.passkey_remove(self.s, Site(), assertion)

    def test_passkey_removal_rejects_missing_user_verification(self):
        auth = self.enroll()
        payload = self.kernel.passkey_remove_challenge(self.s, Site())
        with self.assertRaises(KernelError):
            self.kernel.passkey_remove(self.s, Site(), auth.sign(payload, uv=False))
        self.assertTrue(self.kernel.passkey_status('u_chen', Site())['enrolled'])

    def test_extra_passkey_cannot_bypass_removal_authentication(self):
        self.enroll()
        with self.assertRaises(KernelError) as e:
            self.kernel.passkey_options(self.s, Site())
        self.assertEqual(e.exception.code, 'PASSKEY_EXISTS')
        # A registration challenge obtained in a second session before enrolment is also rejected.
        attacker = webauthn.SoftAuthenticator()
        with self.assertRaises(KernelError):
            self.kernel.passkey_register(self.s, Site(), **attacker.register(b'old challenge'))
        self.assertTrue(self.kernel.passkey_status('u_chen', Site())['enrolled'])

    def test_client_visitor_label_cannot_restore_another_identity(self):
        store = SessionStore(self.path)
        a = store.new_for_visitor('aaaaaaaaaaaaaaaa')
        b = store.new_for_visitor('aaaaaaaaaaaaaaaa')
        self.assertNotEqual(a.user_id, b.user_id)
        with self.assertRaises(UnknownSession):
            store.get(a.session_id + '.abcdef')
        self.assertEqual(SessionStore(self.path).get(a.session_id).user_id, a.user_id)

    def test_cancelled_challenge_cannot_be_reused_after_correction(self):
        self.agent.run_turn(self.s, 'Send 200 to my daughter')
        old = self.s.current_draft
        self.agent.run_turn(self.s, 'Change the amount to 100')
        self.assertEqual(self.s.current_draft.amount_cents, 10000)
        with self.assertRaises(KernelError):
            self.kernel.issue_challenge(self.s, old.draft_id, old.digest)

    def test_corrupt_audit_startup_preserves_evidence(self):
        self.audit.path.write_text('{"truncated":', encoding='utf8')
        audit = AuditLog(self.audit.path)
        self.assertFalse(audit.verify()['ok'])
        with self.assertRaises(OSError):
            audit.append('event', 's', {})
        self.assertEqual(self.audit.path.read_text(), '{"truncated":')

    def test_lab_clock_does_not_change_at_midnight(self):
        from app.config import settings
        from app.lab import run_lab
        with patch.object(settings, 'fixed_hour', 23):
            results = run_lab()
        self.assertTrue(all(r['blocked'] for r in results), results)
