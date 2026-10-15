"""Deterministic rule engine: the same input always gives the same result. The model cannot call or bypass it.

Every rule has a code (for the audit log) and a plain-language reason (for the elderly user).
"""
from __future__ import annotations

import time
from datetime import datetime
from zoneinfo import ZoneInfo
from dataclasses import dataclass, field

from app.bank.mock_bank import MockBank
from app.config import settings
from app.kernel import protection as prot
from app.models import Draft, RiskDecision, RiskLevel, fmt_money

RULESET_VERSION = "rules-2026.10.14-v5"


@dataclass
class RuleContext:
    now: float = field(default_factory=time.time)
    scam_level: RiskLevel = RiskLevel.LOW          # from the scam assessment (can only go up)
    scam_reasons: list[str] = field(default_factory=list)
    local_hour: int | None = None                  # can be injected in tests
    grounding: object | None = None                # evidence.Grounding: is the draft backed by the user's words
    protection: str = "enhanced"                   # account protection level (kernel/protection.py)


def evaluate(draft: Draft, bank: MockBank, ctx: RuleContext | None = None) -> RiskDecision:
    ctx = ctx or RuleContext()
    level = RiskLevel.LOW
    reasons: list[str] = []
    hits: list[str] = []
    blocking: list[str] = []
    question = None

    def raise_to(new: RiskLevel, code: str, why: str):
        nonlocal level
        level = RiskLevel.max(level, new)
        hits.append(code)
        reasons.append(why)
        if new == RiskLevel.BLOCK:
            blocking.append(why)

    invest = draft.kind == "investment"
    payee = bank.product(draft.payee_id) if invest else bank.payee(draft.user_id, draft.payee_id)
    acct = bank.account(draft.user_id, draft.from_account)
    enhanced = ctx.protection == "enhanced"
    threshold = prot.high_threshold(ctx.protection)

    # ---- Hard checks (BLOCK) ----
    if payee is None and invest:
        raise_to(RiskLevel.BLOCK, "R06_UNKNOWN_PRODUCT", "I can't find this investment product.")
    elif payee is None:
        raise_to(RiskLevel.BLOCK, "R00_UNKNOWN_PAYEE", "This person is not in your saved payees, so I can't send money to them directly.")
    if acct is None:
        raise_to(RiskLevel.BLOCK, "R01_UNKNOWN_ACCOUNT", "I can't find the account to pay from.")
    if payee and payee.get("type") == "own" and payee.get("account_id") == draft.from_account:
        raise_to(RiskLevel.BLOCK, "R07_SAME_ACCOUNT", "Please choose two different accounts for an internal transfer.")
    if draft.amount_cents <= 0:
        raise_to(RiskLevel.BLOCK, "R02_BAD_AMOUNT", "The amount must be more than zero.")
    if acct and draft.amount_cents > acct["balance_cents"]:
        raise_to(RiskLevel.BLOCK, "R03_INSUFFICIENT",
                 f"Not enough money — your account only has {fmt_money(acct['balance_cents'])}.")
    if draft.amount_cents > settings.single_txn_hard_limit * 100:
        raise_to(RiskLevel.BLOCK, "R04_HARD_LIMIT",
                 f"Payments over {fmt_money(int(settings.single_txn_hard_limit * 100))} must be done at a branch or with customer service.")
    if draft.expires_at < ctx.now:
        raise_to(RiskLevel.BLOCK, "R05_EXPIRED", "This request has expired. Please say it again.")

    own = payee is not None and payee.get("type") == "own"
    if own and payee.get("account_id") == draft.from_account:
        raise_to(RiskLevel.BLOCK, "R07_SAME_ACCOUNT", "The money would go to the same account it comes from.")
    # ---- Credit card bill: between nothing and the full statement (DBS Bill Payments API) ----
    if draft.kind == "bill" and draft.bill_id:
        bill = bank.bill(draft.user_id, draft.bill_id)
        if bill and draft.amount_cents > bill["amount_cents"]:
            raise_to(RiskLevel.BLOCK, "R08_OVER_BILL",
                     f"That's more than the bill ({fmt_money(bill['amount_cents'])}).")
    # ---- Daily transfer limit (DBS Limits API): transfers to other people today, not own accounts ----
    if draft.kind == "transfer" and not own and not draft.schedule and payee is not None:
        lim = bank.limits(draft.user_id)["daily_transfer_cents"]
        used = bank.transferred_today(draft.user_id)
        if used + draft.amount_cents > lim:
            left = max(0, lim - used)
            raise_to(RiskLevel.BLOCK, "R13_DAILY_LIMIT",
                     f"This is over your daily transfer limit of {fmt_money(lim)}"
                     + (f" (you have {fmt_money(left)} left today)." if used else ".")
                     + " You can raise the limit, but a higher limit only starts after a waiting time.")

    if payee is not None and draft.kind == "transfer" and not own:
        history = bank.payee_history(draft.user_id, draft.payee_id)
        # ---- New payee (HIGH) ----
        if not history and payee.get("type") != "own":
            raise_to(RiskLevel.HIGH, "R10_NEW_PAYEE", "This is your first transfer to this person, so for safety we'll wait a little before confirming.")
        elif history:
            typical = max(history)
            if draft.amount_cents > typical * 2:
                raise_to(RiskLevel.MEDIUM, "R11_ABOVE_USUAL",
                         f"This is quite a bit more than you usually send to {payee['name']} ({fmt_money(typical)}).")
        # ---- Large amount (HIGH) ----
        if draft.amount_cents > threshold * 100:
            raise_to(RiskLevel.HIGH, "R12_ABOVE_THRESHOLD",
                     f"This is more than your limit of {fmt_money(int(threshold * 100))}, so we'll wait a little before confirming.")

    # ---- Investments: minimum, suitability (MAS-style), size ----
    if invest and payee is not None:
        if draft.amount_cents < payee["min_cents"]:
            raise_to(RiskLevel.BLOCK, "R71_BELOW_MINIMUM",
                     f"The minimum for {payee['name']} is {fmt_money(payee['min_cents'])}.")
        profile = bank.risk_profile(draft.user_id)
        if payee["risk"] > profile["max_product_risk"]:
            raise_to(RiskLevel.HIGH if enhanced else RiskLevel.MEDIUM, "R70_ABOVE_RISK_PROFILE",
                     (f"These shares have risk rating {payee['risk']} of 5, above your " if payee["asset_class"].startswith("Shares")
                      else f"This {payee['asset_class'] if payee['asset_class'].isupper() else payee['asset_class'].lower()} "
                           f"has risk rating {payee['risk']} of 5, above your ") +
                     f"{profile['label'].lower()} risk profile. The value can go down as well as up.")
        if draft.amount_cents > threshold * 100:
            raise_to(RiskLevel.HIGH, "R72_LARGE_INVESTMENT",
                     f"This is more than {fmt_money(int(threshold * 100))}, so we'll wait a little before confirming.")

    # ---- Time warning (MEDIUM) and hard transaction frequency limit (BLOCK) ----
    if ctx.local_hour is not None:
        hour = ctx.local_hour
    elif settings.fixed_hour is not None:
        hour = settings.fixed_hour
    else:
        # the customer's local time (Singapore), not the server's clock (Render runs in UTC)
        try:
            hour = datetime.fromtimestamp(ctx.now, ZoneInfo(settings.bank_timezone)).hour
        except Exception:  # noqa: BLE001 - no time zone data on the server: Singapore is UTC+8 all year
            hour = time.gmtime(ctx.now + 8 * 3600).tm_hour
    if enhanced and (hour >= settings.night_start or hour < settings.night_end):
        raise_to(RiskLevel.MEDIUM, "R20_NIGHT", "It's late at night, so let's double-check.")
    # Earlier steps of the same request (one sentence, each step signed on its own) don't count against the limit
    recent = bank.recent_exec_count(draft.user_id, settings.velocity_window_min * 60, plan_id=draft.plan_id)
    if recent >= settings.velocity_max:
        raise_to(RiskLevel.BLOCK, "R21_VELOCITY", "Too many payments in a short time. Please wait until the transaction window clears, then prepare a new request.")

    # ---- Fields from untrusted sources (MEDIUM) ----
    if draft.taint:
        raise_to(RiskLevel.MEDIUM, "R30_TAINTED", "Some details came from a picture or a text message. Please check each one.")

    # ---- Scam assessment: one-way escalation, can only get stricter ----
    if ctx.scam_level.rank > RiskLevel.LOW.rank:
        level = RiskLevel.max(level, ctx.scam_level)
        hits.append(f"R40_SCAM_{ctx.scam_level.value}")
        reasons.extend(ctx.scam_reasons)

    # ---- Evidence grounding: the model must not be the only source of the payee / amount ----
    g = ctx.grounding
    if g is not None and payee is not None and g.amount_source == "derived mismatch":
        raise_to(RiskLevel.BLOCK, "R53_WRONG_SHARE",
                 f"You asked for {g.derived}, but this is {fmt_money(draft.amount_cents)}. I won't prepare a different amount.")
    elif g is not None and payee is not None:
        if not g.payee and not g.amount:
            raise_to(RiskLevel.BLOCK, "R52_NOT_REQUESTED",
                     "I can't find this payment in anything you said, so I won't prepare it.")
        elif not g.payee:
            raise_to(RiskLevel.HIGH, "R51_PAYEE_NOT_SAID",
                     f"You didn't mention {payee['name']}. Please check who this money is going to.")
        elif not g.amount:
            raise_to(RiskLevel.MEDIUM, "R50_AMOUNT_NOT_SAID",
                     f"You didn't say the amount, so I filled in {fmt_money(draft.amount_cents)}. Please check it.")

    if level == RiskLevel.MEDIUM and set(hits) <= {"R50_AMOUNT_NOT_SAID"}:
        question = f"Is {fmt_money(draft.amount_cents)} the right amount?"
    elif level == RiskLevel.MEDIUM and set(hits) <= {"R70_ABOVE_RISK_PROFILE", "R50_AMOUNT_NOT_SAID"}:
        question = "Do you understand this investment can lose value, and do you still want it?"
    elif level == RiskLevel.MEDIUM:
        question = "Do you know this person, and is this payment your own idea?"
    cooldown = settings.cooldown_seconds if level == RiskLevel.HIGH else 0
    return RiskDecision(level=level, reasons=reasons, rule_hits=hits, blocking=blocking,
                        verify_question=question, cooldown_seconds=cooldown)
