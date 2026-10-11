"""安全内核的单元测试：规则、签名、状态机、执行器、审计链。运行：python -m unittest discover tests"""
import os
import tempfile
import time
import unittest

os.environ.setdefault("RULE_FIXED_HOUR", "14")

from app.agent.textparse import amount_words_zh, parse_amount  # noqa: E402
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
        self.kernel = Kernel(self.bank, self.audit, TokenService(b"test-secret"))
        self.s = Session(session_id="t")

    def tearDown(self):
        self.tmp.cleanup()

    def draft(self, payee="p_daughter", cents=20000, **kw):
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
        self.assertIn("重放", why)

    def test_forged_token_rejected(self):
        ts = TokenService(b"k")
        forged = TokenService(b"attacker").issue("d1", "h")
        self.assertFalse(ts.verify_and_consume(forged, "d1", "h")[0])

    def test_cooling_blocks_authorize_then_allows(self):
        d = self.draft(cents=150000)
        with self.assertRaises(KernelError):
            self.kernel.authorize(self.s, d.draft_id, d.digest, "demo-fingerprint")
        d.cooling_until = time.time() - 1
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
        lines[i] = lines[i].replace('"amount_cents":20000', '"amount_cents":2000', 1)   # 偷偷改小金额
        self.audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        res = AuditLog(self.audit.path).verify()
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at_line"], i + 1)


class TestTextParse(unittest.TestCase):
    def test_amounts(self):
        cases = {"给女儿转两百": 200, "二十块五": 20.5, "一万二": 12000, "三千零五": 3005, "transfer $1,500": 1500,
                 "两百五": 250, "转一下": None, "给女儿转两白": None, "账号12345678": None}
        for text, want in cases.items():
            self.assertEqual(parse_amount(text), want, text)

    def test_words(self):
        self.assertEqual(amount_words_zh(20000), "两百元")
        self.assertEqual(amount_words_zh(8640), "八十六元四角")


if __name__ == "__main__":
    unittest.main()
