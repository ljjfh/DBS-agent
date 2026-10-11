"""把草稿变成确认卡和语音复述。

确认卡完全由程序从草稿生成，不经过模型改写：用户看到的、签名的、执行的，是同一份数据。
"""
from __future__ import annotations

import time

from app.agent.textparse import amount_digits_spoken, amount_words_zh
from app.bank.mock_bank import MockBank
from app.models import Draft, Phase, RiskLevel, fmt_money


def build_card(d: Draft, bank: MockBank, phase: Phase) -> dict:
    payee = bank.payee(d.user_id, d.payee_id) or {}
    acct = bank.account(d.user_id, d.from_account) or {}
    relation = payee.get("relation", "")
    who = f"{relation} {d.payee_name}" if relation and relation != "账单" else d.payee_name
    words = amount_words_zh(d.amount_cents)
    verb = "转" if d.kind == "transfer" else "缴"
    readback = f"您要给{who}{verb}{words}（{fmt_money(d.amount_cents)}），从{acct.get('name', '账户')}扣，对吗？"
    risk = d.risk
    return {
        "draft_id": d.draft_id,
        "digest": d.digest,
        "kind": d.kind,
        "title": "转账确认" if d.kind == "transfer" else "缴费确认",
        "payee_name": d.payee_name,
        "payee_relation": relation,
        "payee_account": payee.get("masked_account", ""),
        "amount": fmt_money(d.amount_cents),
        "amount_words": words,
        "amount_spoken_digits": amount_digits_spoken(d.amount_cents),
        "from_account": f"{acct.get('name', '')}（{d.from_account}）",
        "risk_level": risk.level.value if risk else "LOW",
        "reasons": risk.reasons if risk else [],
        "verify_question": risk.verify_question if risk else None,
        "cooldown_left": max(0, int(d.cooling_until - time.time())) if phase == Phase.COOLING else 0,
        "can_confirm": phase in (Phase.AWAITING_AUTH, Phase.COOLING) and (not risk or risk.level != RiskLevel.BLOCK),
        "readback": readback,
        "expires_at": int(d.expires_at),
    }


def receipt_text(d: Draft, receipt: dict) -> str:
    who = d.payee_name
    if d.kind == "transfer":
        return (f"已经转好了，{who}那边会马上收到。账户里还有 {fmt_money(receipt['balance_after_cents'])}。")
    return f"{who}已经缴好了，账户里还有 {fmt_money(receipt['balance_after_cents'])}。"
