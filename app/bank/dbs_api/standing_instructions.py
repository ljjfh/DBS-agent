"""DBS Standing Instructions API: scheduled transfers to saved payees.

Setting one up goes through draft_transfer with `repeat` (fund_transfer.py), so it gets the same card, independent
check and signature as any payment; the schedule is part of what is signed. Cancelling is protective and instant.
"""
from __future__ import annotations

import calendar
import datetime as dt

from pydantic import BaseModel, Field

from app.bank.dbs_api.base import NoArgs, Tool
from app.models import fmt_money

_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def _ordinal(n: int) -> str:
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def make_schedule(frequency: str, day: int | None, today: dt.date | None = None) -> dict:
    """{"frequency", "day", "first_date", "label"}: monthly on a day of the month (1-28), or weekly on a weekday."""
    today = today or dt.date.today()
    if frequency == "weekly":
        wd = (day or today.isoweekday())
        wd = min(max(wd, 1), 7)
        first = today + dt.timedelta(days=(wd - today.isoweekday()) % 7 or 7)
        return {"frequency": "weekly", "day": wd, "first_date": first.isoformat(),
                "label": f"Every {_DAYS[wd - 1]}, first on {first.strftime('%d %b %Y')}"}
    d = min(max(day or today.day, 1), 28)            # 29-31 don't exist every month
    y, m = today.year, today.month
    if today.day >= d:
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    first = dt.date(y, m, min(d, calendar.monthrange(y, m)[1]))
    return {"frequency": "monthly", "day": d, "first_date": first.isoformat(),
            "label": f"Every month on the {_ordinal(d)}, first on {first.strftime('%d %b %Y')}"}


class CancelSIArgs(BaseModel):
    si_id: str = Field(description="si_id from list_standing_instructions")


def list_standing_instructions(gw, s, _):
    out = []
    for si in gw.bank.standing_instructions(s.user_id):
        if si["status"] != "active":
            continue
        p = gw.bank.payee(s.user_id, si["payee_id"]) or {}
        when = (f"every month on the {_ordinal(si['day'])}" if si["frequency"] == "monthly"
                else f"every {_DAYS[si['day'] - 1]}")
        out.append({"si_id": si["si_id"], "to": p.get("name", si["payee_id"]), "relation": p.get("relation", ""),
                    "amount": fmt_money(si["amount_cents"]), "when": when, "next": si["next_date"],
                    "from_account": si["from_account"]})
    return out


def cancel_standing_instruction(gw, s, a: CancelSIArgs):
    si = gw.kernel.cancel_standing_instruction(s, a.si_id)
    return {"cancelled": si["description"], "status": "Stopped now; no more payments will be made. Tell the user in "
            "one sentence, and that they can set it up again any time."}


TOOLS = [
    Tool("list_standing_instructions", "read", "DBS Standing Instructions API: the user's regular scheduled "
         "transfers (who, how much, when, next date).", NoArgs, list_standing_instructions,
         api="Standing Instructions · GET /standing-instructions", group="regular"),
    Tool("cancel_standing_instruction", "control", "DBS Standing Instructions API: stop a regular transfer the user "
         "named. Protective, applies at once. To SET UP a regular transfer use draft_transfer with repeat.",
         CancelSIArgs, cancel_standing_instruction, api="Standing Instructions · DELETE /standing-instructions/{id}",
         group="regular"),
]
