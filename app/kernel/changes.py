"""Account changes (DBS Payees, Limits, GIRO and Standing Instructions APIs).

Two kinds, decided by whether the change could help someone take money out:

* Risk-raising (add a payee, raise the daily transfer limit, set up a GIRO): handled exactly like a payment. The agent
  can only *request* it; the details must come from the customer's own words (deterministic grounding, no model);
  code builds the confirmation card; the customer's device signs the exact change; only then is it applied.
  A raised limit only takes effect after a delay, like lowering the account protection.
* Protective (lower the limit, cancel a GIRO or a standing instruction): applied at once and logged, like locking a
  card. Still grounded: the customer must have named what is being cancelled, so a hidden instruction in some data
  can't quietly switch off their arrangements.

In a conversation flagged as a likely scam, risk-raising changes are refused outright.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

from app.config import settings
from app.kernel.evidence import amounts_in, user_utterances
from app.kernel.signing import build_settings_challenge, canonical
from app.models import RiskLevel, fmt_money

RAISING = {"add_payee", "raise_limit", "giro_setup"}


class ChangeError(Exception):
    def __init__(self, message: str, code: str = "CHANGE_REFUSED"):
        super().__init__(message)
        self.code = code


def _said(s) -> list[str]:
    return user_utterances(s.messages)


def _mentions(utterances: list[str], names: list[str]) -> bool:
    low = " ".join(utterances).lower()
    return any(n and re.search(rf"(?<![a-z]){re.escape(n.lower())}(?![a-z])", low) for n in names)


def _digits_said(utterances: list[str], digits: str) -> bool:
    return any(digits in re.sub(r"\D", "", u) for u in utterances)


def _amount_said(utterances: list[str], cents: int) -> bool:
    return any(cents in amounts_in(u) for u in utterances)


def _quote(utterances: list[str], evidence: str) -> str:
    ev = (evidence or "").strip()
    if ev and any(ev.lower() in u.lower() for u in utterances):
        return ev[:160]
    return (utterances[-1] if utterances else "")[:160]


# ---------------------------------------------------------------------------------------------- risk-raising
def request(kernel, s, kind: str, data: dict, evidence: str = "") -> dict:
    """Validate and ground a risk-raising change, then put its confirmation card in front of the customer."""
    if kind not in RAISING:
        raise ChangeError("Unknown change.", "BAD_REQUEST")
    if s.scam_level.rank >= RiskLevel.HIGH.rank:
        raise ChangeError("For your safety I can't add payees, raise limits or set up GIRO in this conversation. "
                          "If someone is telling you to do this, please hang up and call the ScamShield helpline 1799.",
                          "SCAM_LOCK")
    bank, said = kernel.bank, _said(s)
    rows: list[list[str]] = []
    if kind == "add_payee":
        digits = re.sub(r"\D", "", data.get("account_number", ""))
        name = (data.get("name") or "").strip()
        if len(digits) < 6 or not _digits_said(said, digits):
            raise ChangeError("The account number must be exactly what you said. Please say it again, digit by digit.",
                              "NOT_SAID")
        if not name or not _mentions(said, [w for w in re.findall(r"[A-Za-z]{3,}", name)]):
            raise ChangeError("Please tell me the payee's name as it appears on their bank account.", "NOT_SAID")
        if any(re.sub(r"\D", "", p.get("masked_account", ""))[-4:] == digits[-4:] and p["name"].lower() == name.lower()
               for p in bank.payees(s.user_id)):
            raise ChangeError(f"{name} is already one of your payees.", "EXISTS")
        data = {"name": name, "bank": (data.get("bank") or "").strip()[:30] or "Other bank",
                "account_number": digits, "relation": (data.get("relation") or "").strip()[:30]}
        title = "Add a new payee"
        rows = [["Name", data["name"]], ["Bank", data["bank"]],
                ["Account number", " ".join(digits[i:i + 3] for i in range(0, len(digits), 3))]]
        if data["relation"]:
            rows.append(["Who they are", data["relation"]])
        note = ("Check every digit. Your first transfer to a new payee waits a little and is checked again. "
                "If someone you haven't met asked you to add them, stop and call your family.")
    elif kind == "raise_limit":
        lim = bank.limits(s.user_id)
        to_cents = int(data["to_cents"])
        if to_cents <= lim["daily_transfer_cents"]:
            raise ChangeError("That isn't higher than your current limit.", "NOT_HIGHER")
        if to_cents > settings.single_txn_hard_limit * 100 * 2:
            raise ChangeError(f"Limits above {fmt_money(int(settings.single_txn_hard_limit * 200))} must be changed at a "
                              "branch.", "TOO_HIGH")
        if not _amount_said(said, to_cents):
            raise ChangeError("The new limit must be the amount you said. Please tell me the amount.", "NOT_SAID")
        data = {"from_cents": lim["daily_transfer_cents"], "to_cents": to_cents}
        hours = max(1, round(settings.protection_delay / 3600))
        title = "Raise your daily transfer limit"
        rows = [["Daily limit now", fmt_money(data["from_cents"])], ["New daily limit", fmt_money(to_cents)],
                ["Takes effect", f"in {hours} hours"]]
        note = (f"For your safety a higher limit only starts after {hours} hours. You can keep the old limit at any "
                "time before then. Lowering it again is instant.")
    else:  # giro_setup
        biller = bank.payee(s.user_id, data.get("biller_payee_id", ""))
        if biller is None or biller.get("type") != "biller":
            raise ChangeError("Please choose one of your billing organisations (from get_bills).", "BAD_BILLER")
        bill_titles = [b["title"] for b in bank.bills(s.user_id, only_unpaid=False) if b["payee_id"] == biller["payee_id"]]
        if not _mentions(said, [biller["name"], *biller.get("aliases", []), *bill_titles]):
            raise ChangeError("Please tell me which bill you want paid by GIRO.", "NOT_SAID")
        if any(g["biller"] == biller["name"] and g["status"] != "cancelled" for g in bank.giro(s.user_id)):
            raise ChangeError(f"{biller['name']} already has a GIRO arrangement.", "EXISTS")
        limit = int(data["limit_cents"]) if data.get("limit_cents") else None
        if limit and not _amount_said(said, limit):
            raise ChangeError("The maximum must be the amount you said.", "NOT_SAID")
        acct = data.get("from_account") or bank.accounts(s.user_id)[0]["account_id"]
        if bank.account(s.user_id, acct) is None:
            raise ChangeError("Please choose one of your accounts.", "BAD_ACCOUNT")
        data = {"biller_payee_id": biller["payee_id"], "biller": biller["name"],
                "aliases": biller.get("aliases", []), "limit_cents": limit, "from_account": acct}
        title = "Set up GIRO (automatic bill payment)"
        rows = [["Billing organisation", biller["name"]],
                ["Pay from", f"{bank.account(s.user_id, acct)['name']} ({acct})"],
                ["Maximum each time", fmt_money(limit) if limit else "Each bill in full"]]
        note = "Approval usually takes a few working days. You can cancel a GIRO at any time."
    change_id = "c_" + secrets.token_hex(5)
    quote = _quote(said, evidence)
    card = {"change_id": change_id, "kind": kind, "title": title, "rows": rows, "you_said": quote, "note": note}
    card["digest"] = hashlib.sha256(canonical({"kind": kind, "data": data, "id": change_id}).encode()).hexdigest()
    s.pending_change = {"change_id": change_id, "kind": kind, "data": data, "card": card,
                        "created_at": time.time(), "expires_at": time.time() + settings.draft_ttl}
    s.add_trace("evidence", f"Change grounded in your words: {title}", {"you_said": quote})
    kernel.audit.append("change.requested", s.session_id, {"change_id": change_id, "kind": kind, "data": data})
    return card


def challenge(kernel, s, change_id: str) -> str:
    pc = _pending(s, change_id)
    payload = build_settings_challenge(s.session_id, s.user_id,
                                       {"change_id": change_id, "kind": pc["kind"], "data": pc["data"]})
    s.setting_challenges["change:" + change_id] = payload
    return payload


def apply(kernel, s, change_id: str, assertion: dict, site) -> dict:
    pc = _pending(s, change_id)
    issued = s.setting_challenges.get("change:" + change_id)
    if not issued or not isinstance(assertion, dict) or assertion.get("payload") != issued:
        raise ChangeError("Please confirm this change with your fingerprint.", "PAYLOAD_MISMATCH")
    if json.loads(issued)["expires_at"] < time.time():
        raise ChangeError("This confirmation expired. Please try again.", "EXPIRED")
    rec = kernel._signature(s, issued, assertion, site)
    s.setting_challenges.pop("change:" + change_id, None)
    bank, uid, d = kernel.bank, s.user_id, pc["data"]
    if pc["kind"] == "add_payee":
        p = bank.add_payee(uid, d["name"], d["bank"], d["account_number"], d["relation"])
        reply = (f"Done. {p['name']} ({p['masked_account']}) is now one of your payees. Your first transfer to them "
                 "will wait a little and be checked again.")
    elif pc["kind"] == "raise_limit":
        eff = time.time() + settings.protection_delay
        bank.set_daily_limit(uid, d["to_cents"], effective_at=eff)
        reply = (f"Done. Your daily transfer limit goes up to {fmt_money(d['to_cents'])} on "
                 f"{time.strftime('%d %b, %H:%M', time.localtime(eff))}. Until then it stays "
                 f"{fmt_money(d['from_cents'])}.")
    else:
        g = bank.add_giro(uid, d["biller"], d["aliases"], d["limit_cents"], d["from_account"])
        reply = (f"Done. GIRO for {g['biller']} is set up and waiting for approval, which usually takes a few working "
                 "days. Your bills will then be paid automatically.")
    s.pending_change = None
    s.add_trace("sign", f"Change signed on your device and applied: {pc['card']['title']}", {"method": rec["method"]})
    kernel.audit.append("change.applied", s.session_id, {"change_id": change_id, "kind": pc["kind"], "data": d,
                                                          "method": rec["method"], "key_id": rec.get("key_id")})
    return {"reply": reply, "method": rec["method"]}


def cancel(kernel, s, change_id: str) -> None:
    _pending(s, change_id)
    s.pending_change = None
    kernel.audit.append("change.cancelled", s.session_id, {"change_id": change_id})


def _pending(s, change_id: str) -> dict:
    pc = s.pending_change
    if not pc or pc["change_id"] != change_id:
        raise ChangeError("There is no change waiting for confirmation.", "NO_CHANGE")
    if pc["expires_at"] < time.time():
        s.pending_change = None
        raise ChangeError("This request has expired. Please ask again.", "EXPIRED")
    return pc


# ---------------------------------------------------------------------------------------------- protective
def lower_limit(kernel, s, to_cents: int) -> dict:
    lim = kernel.bank.limits(s.user_id)
    if to_cents >= lim["daily_transfer_cents"]:
        raise ChangeError("That isn't lower than your current limit.", "NOT_LOWER")
    if not _amount_said(_said(s), to_cents):
        raise ChangeError("The new limit must be the amount you said.", "NOT_SAID")
    new = kernel.bank.set_daily_limit(s.user_id, to_cents)
    kernel.audit.append("limit.lowered", s.session_id, {"from_cents": lim["daily_transfer_cents"], "to_cents": to_cents})
    s.add_trace("guard", f"Daily transfer limit lowered to {fmt_money(to_cents)} (protective, takes effect now)")
    return new


def cancel_standing_instruction(kernel, s, si_id: str) -> dict:
    bank = kernel.bank
    si = next((x for x in bank.standing_instructions(s.user_id) if x["si_id"] == si_id and x["status"] == "active"), None)
    if si is None:
        raise ChangeError(f"si_id={si_id} is not an active standing instruction. Call list_standing_instructions.",
                          "NOT_FOUND")
    payee = bank.payee(s.user_id, si["payee_id"]) or {}
    if not _mentions(_said(s), [payee.get("name", ""), *payee.get("aliases", []), si_id]):
        raise ChangeError("Please tell me which regular transfer you want to stop.", "NOT_SAID")
    out = bank.cancel_standing_instruction(s.user_id, si_id)
    kernel.audit.append("standing_instruction.cancelled", s.session_id, {"si_id": si_id})
    s.add_trace("guard", f"Standing instruction {si_id} cancelled (protective, takes effect now)")
    return out


def cancel_giro(kernel, s, giro_id: str) -> dict:
    bank = kernel.bank
    g = next((x for x in bank.giro(s.user_id) if x["giro_id"] == giro_id and x["status"] != "cancelled"), None)
    if g is None:
        raise ChangeError(f"giro_id={giro_id} is not an active GIRO. Call list_giro.", "NOT_FOUND")
    if not _mentions(_said(s), [g["biller"], *g.get("aliases", []), giro_id]):
        raise ChangeError("Please tell me which GIRO you want to cancel.", "NOT_SAID")
    out = bank.cancel_giro(s.user_id, giro_id)
    kernel.audit.append("giro.cancelled", s.session_id, {"giro_id": giro_id})
    s.add_trace("guard", f"GIRO with {g['biller']} cancelled (protective, takes effect now)")
    return out
