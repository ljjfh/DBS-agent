"""确定性规则引擎：同一输入永远得到同一结果。模型无法调用或绕过这里。

每条规则都有编号（给审计）和白话理由（给老人）。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.bank.mock_bank import MockBank
from app.config import settings
from app.models import Draft, RiskDecision, RiskLevel, fmt_money

RULESET_VERSION = "rules-2026.10.11-v1"


@dataclass
class RuleContext:
    now: float = field(default_factory=time.time)
    scam_level: RiskLevel = RiskLevel.LOW          # 来自诈骗研判（只能调高）
    scam_reasons: list[str] = field(default_factory=list)
    local_hour: int | None = None                  # 测试时可注入


def evaluate(draft: Draft, bank: MockBank, ctx: RuleContext | None = None) -> RiskDecision:
    ctx = ctx or RuleContext()
    level = RiskLevel.LOW
    reasons: list[str] = []
    hits: list[str] = []
    question = None

    def raise_to(new: RiskLevel, code: str, why: str):
        nonlocal level
        level = RiskLevel.max(level, new)
        hits.append(code)
        reasons.append(why)

    payee = bank.payee(draft.user_id, draft.payee_id)
    acct = bank.account(draft.user_id, draft.from_account)

    # ---- 硬性校验（BLOCK）----
    if payee is None:
        raise_to(RiskLevel.BLOCK, "R00_UNKNOWN_PAYEE", "这个收款人不在您已保存的名单里，不能直接转账。")
    if acct is None:
        raise_to(RiskLevel.BLOCK, "R01_UNKNOWN_ACCOUNT", "找不到这个扣款账户。")
    if draft.amount_cents <= 0:
        raise_to(RiskLevel.BLOCK, "R02_BAD_AMOUNT", "金额必须大于 0。")
    if acct and draft.amount_cents > acct["balance_cents"]:
        raise_to(RiskLevel.BLOCK, "R03_INSUFFICIENT",
                 f"余额不够，账户里只有 {fmt_money(acct['balance_cents'])}。")
    if draft.amount_cents > settings.single_txn_hard_limit * 100:
        raise_to(RiskLevel.BLOCK, "R04_HARD_LIMIT",
                 f"单笔超过 {fmt_money(int(settings.single_txn_hard_limit * 100))}，需要到柜台或联系客服办理。")
    if draft.expires_at < ctx.now:
        raise_to(RiskLevel.BLOCK, "R05_EXPIRED", "这张单子已经过期，请重新说一次。")

    if payee is not None and draft.kind == "transfer":
        history = bank.payee_history(draft.user_id, draft.payee_id)
        # ---- 新收款人（HIGH）----
        if not history:
            raise_to(RiskLevel.HIGH, "R10_NEW_PAYEE", "这是第一次转给这个人，为了安全，我们等一会儿再确认。")
        else:
            typical = max(history)
            if draft.amount_cents > typical * 2:
                raise_to(RiskLevel.MEDIUM, "R11_ABOVE_USUAL",
                         f"这次金额比您平时转给 {payee['name']} 的（{fmt_money(typical)}）多不少。")
        # ---- 大额（HIGH）----
        if draft.amount_cents > settings.user_high_threshold * 100:
            raise_to(RiskLevel.HIGH, "R12_ABOVE_THRESHOLD",
                     f"金额超过您设定的 {fmt_money(int(settings.user_high_threshold * 100))}，需要多等一会儿再确认。")

    # ---- 时间与频率（MEDIUM）----
    if ctx.local_hour is not None:
        hour = ctx.local_hour
    elif settings.fixed_hour is not None:
        hour = settings.fixed_hour
    else:
        hour = time.localtime(ctx.now).tm_hour
    if hour >= settings.night_start or hour < settings.night_end:
        raise_to(RiskLevel.MEDIUM, "R20_NIGHT", "现在是深夜，我们多确认一次。")
    recent = bank.recent_exec_count(draft.user_id, settings.velocity_window_min * 60)
    if recent >= settings.velocity_max:
        raise_to(RiskLevel.MEDIUM, "R21_VELOCITY", "短时间内已经转了好几笔，我们多确认一次。")

    # ---- 不可信来源字段（MEDIUM）----
    if draft.taint:
        raise_to(RiskLevel.MEDIUM, "R30_TAINTED", "部分信息来自图片或短信，请您逐项核对。")

    # ---- 诈骗研判结果：单向升级，只会更严 ----
    if ctx.scam_level.rank > RiskLevel.LOW.rank:
        level = RiskLevel.max(level, ctx.scam_level)
        hits.append(f"R40_SCAM_{ctx.scam_level.value}")
        reasons.extend(ctx.scam_reasons)

    if level == RiskLevel.MEDIUM:
        question = "这个人您认识、并且是您自己想转的吗？"
    cooldown = settings.cooldown_seconds if level == RiskLevel.HIGH else 0
    return RiskDecision(level=level, reasons=reasons, rule_hits=hits,
                        verify_question=question, cooldown_seconds=cooldown)
