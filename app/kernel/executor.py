"""确定性内核的对外入口：起草、授权、提交、取消。

模型不可达：Agent 的工具网关只能调用 create_draft（草稿，无副作用），
authorize / commit 只能由前端在用户生物识别后通过 HTTP 调用。
"""
from __future__ import annotations

import secrets
import time
import uuid

from app.bank.mock_bank import MockBank
from app.config import settings
from app.kernel import rules
from app.kernel.audit import AuditLog
from app.kernel.signing import MockAuthenticator, TokenService, compute_digest
from app.kernel.state import Session
from app.models import Draft, Phase, RiskLevel, fmt_money


class KernelError(Exception):
    def __init__(self, message: str, code: str = "KERNEL_ERROR"):
        super().__init__(message)
        self.code = code


class Kernel:
    def __init__(self, bank: MockBank, audit: AuditLog, tokens: TokenService | None = None,
                 authenticator: MockAuthenticator | None = None):
        self.bank = bank
        self.audit = audit
        self.tokens = tokens or TokenService()
        self.authenticator = authenticator or MockAuthenticator()

    # ------------------------------------------------------------------ 起草
    def create_draft(self, s: Session, *, kind: str, payee_id: str, amount_cents: int,
                     from_account: str | None = None, bill_id: str | None = None,
                     taint: list[str] | None = None, local_hour: int | None = None) -> Draft:
        s.settle()
        if s.phase != Phase.IDLE:
            raise KernelError("已经有一笔待确认的交易，请先确认或取消。", "PENDING_DRAFT")
        accounts = self.bank.accounts(s.user_id)
        from_account = from_account or accounts[0]["account_id"]
        payee = self.bank.payee(s.user_id, payee_id)
        now = time.time()
        draft = Draft(
            draft_id="d_" + uuid.uuid4().hex[:10], user_id=s.user_id, kind=kind,
            from_account=from_account, payee_id=payee_id,
            payee_name=payee["name"] if payee else "（未知收款人）",
            amount_cents=amount_cents, bill_id=bill_id, created_at=now,
            expires_at=now + settings.draft_ttl, nonce=secrets.token_hex(6), taint=taint or [])
        draft.digest = compute_digest(draft)
        ctx = rules.RuleContext(now=now, scam_level=s.scam_level, scam_reasons=list(s.scam_reasons),
                                local_hour=local_hour)
        draft.risk = rules.evaluate(draft, self.bank, ctx)
        s.drafts[draft.draft_id] = draft
        s.current_draft_id = draft.draft_id
        s.transition(Phase.DRAFTED)

        if draft.risk.level == RiskLevel.BLOCK:
            s.transition(Phase.BLOCKED)
        elif draft.risk.level == RiskLevel.HIGH:
            draft.cooling_until = now + draft.risk.cooldown_seconds
            s.transition(Phase.COOLING)
        else:
            s.transition(Phase.AWAITING_AUTH)

        s.add_trace("rule", f"规则判级：{draft.risk.level.value}",
                    {"hits": draft.risk.rule_hits, "ruleset": rules.RULESET_VERSION})
        self.audit.append("draft.created", s.session_id, {
            "draft": draft.card_fields(), "digest": draft.digest, "risk": draft.risk.model_dump(mode="json"),
            "ruleset": rules.RULESET_VERSION})
        return draft

    # ------------------------------------------------------------------ 授权
    def authorize(self, s: Session, draft_id: str, shown_digest: str, assertion: str,
                  verify_answer: bool | None = None) -> str:
        draft = self._get_draft(s, draft_id)
        self._refresh_cooling(s, draft)
        if s.phase != Phase.AWAITING_AUTH:
            raise KernelError(self._phase_message(s, draft), "NOT_AWAITING_AUTH")
        if shown_digest != draft.digest:
            self.audit.append("auth.rejected", s.session_id, {"draft_id": draft_id, "reason": "digest_mismatch"})
            raise KernelError("确认卡内容与交易不一致，已拒绝。", "DIGEST_MISMATCH")
        if draft.risk and draft.risk.verify_question and verify_answer is not True:
            raise KernelError("请先回答核验问题。", "VERIFY_REQUIRED")
        if not self.authenticator.verify(assertion):
            self.audit.append("auth.rejected", s.session_id, {"draft_id": draft_id, "reason": "biometric_failed"})
            raise KernelError("身份验证没有通过。", "AUTH_FAILED")
        token = self.tokens.issue(draft_id, shown_digest)
        s.add_trace("sign", "用户已签名确认", {"digest": shown_digest[:16] + "…"})
        self.audit.append("auth.granted", s.session_id, {"draft_id": draft_id, "digest": shown_digest,
                                                         "method": assertion.split("-")[1] if "-" in assertion else "?"})
        return token

    # ------------------------------------------------------------------ 提交
    def commit(self, s: Session, draft_id: str, token: str) -> dict:
        draft = self._get_draft(s, draft_id)
        if s.phase != Phase.AWAITING_AUTH:
            raise KernelError(self._phase_message(s, draft), "NOT_AWAITING_AUTH")
        recomputed = compute_digest(draft)
        ok, why = self.tokens.verify_and_consume(token, draft_id, recomputed)
        if not ok:
            self.audit.append("commit.rejected", s.session_id, {"draft_id": draft_id, "reason": why})
            raise KernelError(why, "TOKEN_INVALID")
        # 执行前再跑一次规则（余额可能已变化；防止“检查时”与“使用时”不一致）
        recheck = rules.evaluate(draft, self.bank, rules.RuleContext(scam_level=s.scam_level))
        if recheck.level == RiskLevel.BLOCK:
            s.transition(Phase.CANCELLED)
            self.audit.append("commit.rejected", s.session_id, {"draft_id": draft_id, "reason": recheck.rule_hits})
            raise KernelError("；".join(recheck.reasons), "RECHECK_BLOCKED")
        receipt = self.bank.execute_payment(s.user_id, draft.from_account, draft.payee_id,
                                            draft.amount_cents, idempotency_key=draft.draft_id,
                                            bill_id=draft.bill_id)
        s.transition(Phase.EXECUTED)
        s.add_trace("exec", f"已执行 {fmt_money(draft.amount_cents)} → {draft.payee_name}",
                    {"txn_id": receipt["txn_id"]})
        self.audit.append("commit.executed", s.session_id, {"draft_id": draft_id, "digest": recomputed,
                                                            "receipt": receipt})
        return receipt

    # ------------------------------------------------------------------ 取消
    def cancel(self, s: Session, draft_id: str, reason: str = "user") -> None:
        draft = self._get_draft(s, draft_id)
        if s.phase in (Phase.DRAFTED, Phase.COOLING, Phase.AWAITING_AUTH):
            s.transition(Phase.CANCELLED)
            self.audit.append("draft.cancelled", s.session_id, {"draft_id": draft.draft_id, "reason": reason})

    # ------------------------------------------------------------------ 工具
    def _get_draft(self, s: Session, draft_id: str) -> Draft:
        if s.current_draft_id != draft_id or draft_id not in s.drafts:
            raise KernelError("找不到这笔待确认的交易。", "NO_SUCH_DRAFT")
        return s.drafts[draft_id]

    def _refresh_cooling(self, s: Session, draft: Draft) -> None:
        if s.phase == Phase.COOLING and time.time() >= draft.cooling_until:
            s.transition(Phase.AWAITING_AUTH)

    @staticmethod
    def _phase_message(s: Session, draft: Draft) -> str:
        if s.phase == Phase.COOLING:
            left = max(0, int(draft.cooling_until - time.time()))
            return f"还在冷静期，请 {left} 秒后再确认。"
        if s.phase == Phase.BLOCKED:
            return "这笔交易已被拦截，不能执行。"
        if s.phase == Phase.EXECUTED:
            return "这笔交易已经完成了。"
        return "当前不能确认这笔交易。"
