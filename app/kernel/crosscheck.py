"""Dual-engine semantic audit, deterministic half: compare the draft with what the independent verifier extracted.

Engine 1 (agent/loop.py + tools.py) understands the request and drafts the transaction.
Engine 2 (agent/verifier.py) is a separate, read-only model call that sees ONLY the customer's own words (the
speech-to-text transcript) - never the draft - and extracts: intent, payee, amount, asset class, source account.

This module, which is plain code, compares the two field by field. Any field the customer stated that disagrees with
the draft freezes it (Phase.FROZEN): it can never be signed or executed, and the customer is told exactly what
didn't match. A field the customer didn't state is "not stated", not a mismatch (evidence grounding in
evidence.py and the rules handle that, e.g. "the usual amount").
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from app.models import Draft, fmt_money

_ASSET = {"cash": "cash", "money": "cash", "transfer": "cash", "fund": "unit trust", "funds": "unit trust",
          "unit trust": "unit trust", "unit trusts": "unit trust", "mutual fund": "unit trust",
          "etf": "etf", "etfs": "etf", "exchange traded fund": "etf", "index fund": "etf",
          "bond": "government bond", "bonds": "government bond", "savings bond": "government bond",
          "savings bonds": "government bond", "government bond": "government bond", "ssb": "government bond",
          "stock": "shares", "stocks": "shares", "shares": "shares", "share": "shares", "equity": "shares",
          "fixed deposit": "fixed deposit", "time deposit": "fixed deposit", "fd": "fixed deposit",
          "deposit": "fixed deposit"}
_GENERIC_ACCOUNT = {"account", "my account", "bank", "bank account", "my bank account", "the account", "default"}


def _words(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9&]+", " ", str(text).lower()).strip() + " "


def _names(entity: dict) -> list[str]:
    return [n for n in [entity.get("name", ""), entity.get("title", ""), *entity.get("aliases", [])] if n]


def resolve_targets(said: str, draft: Draft, bank) -> set[str]:
    """Which saved payees / bills / products could the customer's phrase refer to?"""
    w = _words(said)
    if draft.kind == "investment":
        pool = [(p["product_id"], _names(p)) for p in bank.products]
    else:
        pool = [(p["payee_id"], _names(p)) for p in bank.payees(draft.user_id)]
        pool += [(b["payee_id"], [b["title"]]) for b in bank.bills(draft.user_id, only_unpaid=False)]
    hits = set()
    for pid, names in pool:
        for n in names:
            nw = _words(n)
            if nw.strip() and (nw in w or (len(w.strip()) > 2 and w in nw)):
                hits.add(pid)
    return hits


def resolve_account(said: str, accounts: list[dict]) -> str | None:
    w = _words(said)
    if w.strip() in _GENERIC_ACCOUNT:
        return None
    for a in accounts:
        first = a["name"].split()[0].lower()            # "savings", "current"
        if f" {a['account_id'].lower()} " in w or f" {first} " in w or f" {first[:-1]} " in w and first.endswith("s"):
            return a["account_id"]
    return "?"                                          # stated, but not one of the customer's accounts


def _asset(s: str | None) -> str | None:
    if not s:
        return None
    k = re.sub(r"\s+", " ", str(s).lower().strip())
    return _ASSET.get(k, k)


def compare(draft: Draft, extracted: dict, bank) -> dict:
    fields: dict[str, str] = {}
    why: list[str] = []
    ex = extracted if isinstance(extracted, dict) else {}
    intent = str(ex.get("intent") or "none").lower()
    said_payee, said_amount = ex.get("payee"), ex.get("amount")

    # ---- Is there a request at all, and of the same type?
    if intent not in ("transfer", "bill", "bill_pay", "bill_payment", "payment", "invest", "investment") or (not said_payee and said_amount in (None, "")):
        fields["request"] = "mismatch"
        why.append("The independent check found no payment request in what you said.")
    else:
        is_invest = intent.startswith("invest")
        if is_invest != (draft.kind == "investment"):
            fields["type"] = "mismatch"
            why.append(f"Type: you asked for {'an investment' if is_invest else 'a payment'}, but this is "
                       f"{'an investment' if draft.kind == 'investment' else 'a payment'}.")
        else:
            fields["type"] = "match"

    # ---- Who / what
    if said_payee is not None and not isinstance(said_payee, str):
        fields["payee"] = "mismatch"
        why.append("The independent check returned an invalid recipient.")
    elif said_payee:
        targets = resolve_targets(str(said_payee), draft, bank)
        ok = draft.payee_id in targets
        fields["payee"] = "match" if ok else "mismatch"
        if not ok:
            label = f"“{said_payee}”"
            if len(targets) == 1 and draft.kind != "investment":
                p = bank.payee(draft.user_id, next(iter(targets))) or {}
                if p.get("type") == "person":
                    label = f"your {p['relation']} {p['name']}"
            why.append(f"Who: you asked for {label}, but this is for {draft.payee_name}.")
    else:
        fields["payee"] = "mismatch"
        why.append("The independent check could not confirm the recipient or product.")

    # ---- How much
    cents = None
    invalid = False
    if said_amount not in (None, ""):
        try:
            if isinstance(said_amount, bool) or not isinstance(said_amount, (int, float, str)):
                raise ValueError("Invalid amount type")
            amount = Decimal(str(said_amount).replace(",", "").replace("S$", "").replace("$", ""))
            if not amount.is_finite() or amount <= 0 or amount * 100 != (amount * 100).to_integral_value():
                raise ValueError("Invalid amount")
            cents = int(amount * 100)
        except (ValueError, InvalidOperation):
            invalid = True
    if invalid:
        fields["amount"] = "mismatch"
        why.append("The independent check returned an invalid amount; please say the amount again.")
    elif cents is not None:
        ok = cents == draft.amount_cents
        fields["amount"] = "match" if ok else "mismatch"
        if not ok:
            why.append(f"Amount: you said {fmt_money(cents)}, but this is for {fmt_money(draft.amount_cents)}.")
    elif draft.grounding.get("amount_source") == "user":
        fields["amount"] = "mismatch"
        why.append("The independent check could not confirm the amount you stated.")
    else:
        fields["amount"] = "not stated"

    # ---- Asset class
    said_asset, have = _asset(ex.get("asset_class")), _asset(draft.asset_class)
    if said_asset and not (draft.kind != "investment" and said_asset == "cash"):
        ok = said_asset == have or said_asset in have or have in said_asset
        fields["asset_class"] = "match" if ok else "mismatch"
        if not ok:
            why.append(f"Asset: you said {ex.get('asset_class')}, but this is {draft.asset_class}.")
    else:
        fields["asset_class"] = "not stated"

    # ---- From which account
    said_acct = ex.get("from_account")
    acct = resolve_account(str(said_acct), bank.accounts(draft.user_id)) if said_acct else None
    if acct:
        ok = acct == draft.from_account
        fields["from_account"] = "match" if ok else "mismatch"
        if not ok:
            have_name = (bank.account(draft.user_id, draft.from_account) or {}).get("name", draft.from_account)
            why.append(f"From: you said “{said_acct}”, but this takes the money from your {have_name}.")
    else:
        fields["from_account"] = "not stated"

    return {"status": "mismatch" if why else "match", "fields": fields, "mismatches": why}
