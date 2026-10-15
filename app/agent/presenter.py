"""Turn a draft into a confirmation card and a spoken read-back.

The card is generated entirely by code from the draft and never rewritten by the model: what the user sees,
what they sign, and what gets executed are the same data.
"""
from __future__ import annotations

import time

from app.agent.textparse import amount_digits_spoken, amount_words_en
from app.bank.mock_bank import MockBank, price_sgd_cents
from app.models import Draft, Phase, RiskLevel, fmt_money


def product_line(p: dict, amount_cents: int) -> str:
    """One line under the product name on the card: what exactly is being bought."""
    if p.get("rate_pa"):
        return f"{p['rate_pa']:.2f}% a year for {p['tenor_months']} months · a deposit (demo rate)"
    unit = price_sgd_cents(p)
    units = amount_cents / unit if unit else 0
    if p.get("ticker"):
        px = f"US${p['price']:,.2f}" if p.get("currency") == "USD" else f"S${p['price']:,.2f}"
        return (f"{p['ticker']} on {p['exchange']} · about {units:,.2f} shares at {px} (demo price) · "
                f"risk {p['risk']} of 5, can lose value")
    if p["price"] != 1.0:
        return f"about {units:,.2f} units at S${p['price']:,.4g} (demo price) · risk {p['risk']} of 5, can lose value"
    return f"Risk {p['risk']} of 5 · not a deposit, can lose value"


def build_card(d: Draft, bank: MockBank, phase: Phase, care: bool = True) -> dict:
    invest = d.kind == "investment"
    payee = (bank.product(d.payee_id) if invest else bank.payee(d.user_id, d.payee_id)) or {}
    acct = bank.account(d.user_id, d.from_account) or {}
    relation = payee.get("relation", "")
    is_person = payee.get("type") == "person"
    own = payee.get("type") == "own"
    who = f"your {relation} {d.payee_name}" if relation and is_person else f"your {d.payee_name}" if own else d.payee_name
    bill = bank.bill(d.user_id, d.bill_id) if d.bill_id else None
    sched = d.schedule or {}
    words = amount_words_en(d.amount_cents)
    if invest:
        readback = (f"You want to invest {words} ({fmt_money(d.amount_cents)}) in the {d.payee_name}, "
                    f"a {d.asset_class.lower()}, from your {acct.get('name', 'account')}. Is that right?")
    else:
        verb = "move" if own else "send" if d.kind == "transfer" else "pay"
        when = f" {sched['label'][0].lower()}{sched['label'][1:]}" if sched else ""
        readback = (f"You want to {verb} {words} ({fmt_money(d.amount_cents)}) to {who}{when}, "
                    f"from your {acct.get('name', 'account')}. Is that right?")
    if not care:                                    # standard mode: the same card, a shorter read-back
        when = f", {sched['label'][0].lower()}{sched['label'][1:]}" if sched else ""
        readback = (f"{fmt_money(d.amount_cents)} {'in' if invest else 'to'} {d.payee_name}{when}, "
                    f"from {acct.get('name', 'your account')}.")
    risk = d.risk
    v = d.verification or {}
    return {
        "draft_id": d.draft_id,
        "digest": d.digest,
        "kind": d.kind,
        "title": ("Confirm regular transfer" if sched else "Move money between your accounts" if own else
                  {"transfer": "Confirm transfer", "bill": "Confirm bill payment", "investment": "Confirm investment"}[d.kind]),
        "schedule": sched.get("label", ""),
        "amount_note": (f"{d.grounding['heard'][0].upper()}{d.grounding['heard'][1:]}. Please check the amount."
                        if d.grounding.get("heard") else
                        f"{d.grounding['derived']}, worked out by the bank" if d.grounding.get("amount_source") == "derived"
                        else ("minimum payment due" if d.amount_cents == bill.get("min_due_cents") else
                         "full statement balance" if d.amount_cents == bill["amount_cents"] else
                         f"part of your statement of {fmt_money(bill['amount_cents'])}")
                        if bill and "min_due_cents" in bill else ""),
        "payee_name": d.payee_name,
        "payee_relation": relation if is_person or own else "",
        "payee_account": product_line(payee, d.amount_cents) if invest else payee.get("masked_account", ""),
        "asset_class": d.asset_class,
        "from_account_id": d.from_account,
        "verification": {"status": v.get("status", "missing"), "fields": v.get("fields", {}),
                         "mismatches": v.get("mismatches", []), "engine": v.get("engine", "")},
        "decision": d.decision,
        "secondary_required": d.decision.get("checks", {}).get("secondary_approval", {}).get("status") == "pending",
        "amount": fmt_money(d.amount_cents),
        "amount_words": words,
        "amount_spoken_digits": amount_digits_spoken(d.amount_cents),
        "from_account": f"{acct.get('name', '')} ({d.from_account})",
        "risk_level": risk.level.value if risk else "LOW",
        "reasons": risk.reasons if risk else [],
        "verify_question": risk.verify_question if risk else None,
        "verify_kind": risk.verify_kind if risk else None,
        "cooldown_left": max(0, int(d.cooling_until - time.time())) if phase == Phase.COOLING else 0,
        "can_confirm": phase in (Phase.AWAITING_AUTH, Phase.COOLING) and (not risk or risk.level != RiskLevel.BLOCK)
                       and v.get("status") == "match"
                       and d.decision.get("checks", {}).get("secondary_approval", {}).get("status") != "pending"
                       and d.decision.get("checks", {}).get("plan", {}).get("status") != "fail",
        "readback": readback,
        "expires_at": int(d.expires_at),
        "you_said": d.you_said,
        "you_said_audio": d.you_said_audio,
        "amount_from_user": d.grounding.get("amount", True),
        "amount_source": d.grounding.get("amount_source", "user"),
        "payee_from_user": d.grounding.get("payee", True),
    }


def receipt_text(d: Draft, receipt: dict) -> str:
    who = d.payee_name
    if d.kind == "investment":
        after = f"Your account now has {fmt_money(receipt['balance_after_cents'])}."
        if d.asset_class == "Fixed deposit":
            return f"Done. {fmt_money(d.amount_cents)} is now in your {who}. {after}"
        if d.asset_class.startswith("Shares"):
            return f"Done. You bought about {receipt.get('units', 0):,.2f} {who} for {fmt_money(d.amount_cents)}. {after}"
        return f"Done. You've invested {fmt_money(d.amount_cents)} in the {who}. {after}"
    if d.schedule:
        return (f"Done. {fmt_money(d.amount_cents)} will go to {who} {d.schedule['label'][0].lower()}"
                f"{d.schedule['label'][1:]}. Nothing has been taken today.")
    if d.kind == "transfer" and d.payee_id.startswith("own:"):
        return f"Done. {fmt_money(d.amount_cents)} is now in your {who}."
    if d.kind == "transfer":
        return (f"Done. {who} will receive it right away. "
                f"Your account now has {fmt_money(receipt['balance_after_cents'])}.")
    return f"{who} has been paid. Your account now has {fmt_money(receipt['balance_after_cents'])}."
