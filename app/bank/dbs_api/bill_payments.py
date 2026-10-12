"""DBS Bill Payments API: utilities, town council, and credit cards (full statement, minimum, or an amount between)."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

from app.bank.dbs_api.base import MEANT_DESC, MISHEARD_DESC, NoArgs, Tool
from app.kernel.executor import KernelError
from app.models import fmt_money, to_cents


class DraftBillArgs(BaseModel):
    bill_id: str = Field(description="Must be a bill_id returned by get_bills")
    pay: Literal["full", "minimum", "amount"] = Field(
        default="full", description="Credit cards: 'full' statement, the 'minimum' due, or 'amount' (then give amount). "
                                    "Ask the user if they didn't say. Other bills: 'full'.")
    amount: Optional[float] = Field(default=None, gt=0, description="Only with pay='amount': what the user said")
    from_account: Optional[str] = Field(default=None, description="account_id, ONLY if the user said which account")
    evidence: str = Field(default="", max_length=200, description="Quote the user's exact words that asked for this payment")
    misheard: str = Field(default="", max_length=40, description=MISHEARD_DESC)
    meant: str = Field(default="", max_length=40, description=MEANT_DESC)


def get_bills(gw, s, _):
    out = []
    for b in gw.bank.bills(s.user_id):
        item = {"bill_id": b["bill_id"], "title": b["title"], "amount": fmt_money(b["amount_cents"]),
                "due": b["due"], "payee_id": b["payee_id"]}
        if "min_due_cents" in b:
            item["kind"] = "credit card"
            item["minimum_due"] = fmt_money(b["min_due_cents"])
            item["note"] = "Ask whether to pay the full statement or the minimum, unless the user said."
        out.append(item)
    return out


def draft_bill_payment(gw, s, a: DraftBillArgs):
    bill = gw.bank.bill(s.user_id, a.bill_id)
    if bill is None or bill["status"] != "unpaid":
        raise KernelError(f"bill_id={a.bill_id} is not an unpaid bill. Call get_bills first.")
    card_bill = "min_due_cents" in bill
    if a.pay == "minimum":
        if not card_bill or not bill.get("min_due_cents"):
            raise KernelError("This bill has no minimum payment; pay it in full.")
        cents = bill["min_due_cents"]
    elif a.pay == "amount":
        if not card_bill:
            raise KernelError("Only credit card bills can be paid in part; pay this bill in full.")
        if not a.amount:
            raise KernelError("Give the amount the user said, or use pay='full' / 'minimum'.")
        cents = to_cents(a.amount)
    else:
        cents = bill["amount_cents"]
    acct = gw._account(s, a.from_account)
    d = gw.kernel.create_draft(s, kind="bill", payee_id=bill["payee_id"], from_account=acct, amount_cents=cents,
                               bill_id=a.bill_id, evidence=a.evidence, verification=gw._verification(s),
                               heard=(a.misheard, a.meant))
    return gw._draft_result(d)


TOOLS = [
    Tool("get_bills", "read", "DBS Bill Payments API: unpaid bills (utilities, town council, credit card with its "
         "minimum due).", NoArgs, get_bills, api="Bill Payments · GET /bills"),
    Tool("draft_bill_payment", "draft", "DBS Bill Payments API: create a bill payment draft for the user to confirm. "
         "Credit cards: full statement, minimum, or an amount.", DraftBillArgs, draft_bill_payment,
         api="Bill Payments · POST /bill-payments (draft)"),
]
