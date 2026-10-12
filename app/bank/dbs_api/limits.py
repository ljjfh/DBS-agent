"""DBS Limits API: the daily limit for transfers to other people. Lowering is instant; raising is signed + delayed."""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.bank.dbs_api.base import NoArgs, Tool
from app.models import fmt_money, to_cents


class SetLimitArgs(BaseModel):
    amount: float = Field(gt=0, description="The new daily transfer limit in SGD, exactly as the user said")
    evidence: str = Field(default="", max_length=200, description="Quote the user's exact words")


def get_limits(gw, s, _):
    lim = gw.bank.limits(s.user_id)
    used = gw.bank.transferred_today(s.user_id)
    out = {"daily_transfer_limit": fmt_money(lim["daily_transfer_cents"]), "used_today": fmt_money(used),
           "left_today": fmt_money(max(0, lim["daily_transfer_cents"] - used)),
           "applies_to": "transfers to other people (not your own accounts, bills or investments)"}
    if lim.get("pending"):
        out["scheduled_change"] = f"rising to {fmt_money(lim['pending']['to_cents'])}"
    return out


def set_daily_limit(gw, s, a: SetLimitArgs):
    cents, now = to_cents(a.amount), gw.bank.limits(s.user_id)["daily_transfer_cents"]
    if cents < now:
        gw.kernel.lower_limit(s, cents)
        return {"status": f"Lowered now: the daily transfer limit is {fmt_money(cents)}. Tell the user in one sentence."}
    card = gw.kernel.request_change(s, "raise_limit", {"to_cents": cents}, a.evidence)
    return {"change_id": card["change_id"], "status": "A higher limit needs the user's fingerprint and only starts after "
            "a waiting time. A confirmation card is shown; tell the user in one or two simple sentences."}


TOOLS = [
    Tool("get_limits", "read", "DBS Limits API: the daily limit for transfers to other people, how much is used and "
         "left today.", NoArgs, get_limits, api="Limits · GET /transaction-limits", group="limits"),
    Tool("set_daily_limit", "control", "DBS Limits API: change the daily transfer limit to the amount the user said. "
         "Lowering applies at once (protective). Raising shows a card the user must sign and starts after a delay.",
         SetLimitArgs, set_daily_limit, api="Limits · PUT /transaction-limits", group="limits"),
]
