"""DBS Fund Transfer API: to saved people, and between the customer's own accounts. With `repeat`, the same draft
sets up a standing instruction (standing_instructions.py) instead of paying today.

The agent only drafts. Everything after that is the kernel's: evidence grounding, the independent verifier, the
rules (incl. the daily limit), the code-built card, the customer's signature, and the execution gateway.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

from app.bank.dbs_api.base import Tool
from app.bank.dbs_api.standing_instructions import make_schedule
from app.kernel.executor import KernelError
from app.models import fmt_money, to_cents

_FROM = "Optional. account_id from get_balance, ONLY if the user said which account to pay from; else omit"


class DraftTransferArgs(BaseModel):
    payee_id: str = Field(description="Must be a payee_id returned by list_payees (own accounts start with 'own:')")
    amount: float = Field(gt=0, description="Amount in SGD, e.g. 200 or 50.5")
    from_account: Optional[str] = Field(default=None, description=_FROM)
    repeat: Optional[Literal["monthly", "weekly"]] = Field(
        default=None, description="ONLY if the user asked for a repeating transfer ('every month', 'weekly'); else omit")
    repeat_day: Optional[int] = Field(
        default=None, ge=1, le=31, description="monthly: the day of the month the user said (e.g. 1); weekly: "
                                               "1=Monday..7=Sunday; omit if the user didn't say")
    evidence: str = Field(default="", max_length=200, description="Quote the user's exact words that asked for this payment")
    note: str = Field(default="", max_length=60)


def draft_transfer(gw, s, a: DraftTransferArgs):
    payee = gw.bank.payee(s.user_id, a.payee_id)
    if payee is None:
        raise KernelError(f"payee_id={a.payee_id} is not in the user's saved payees. Only use a payee_id returned by "
                          "list_payees; to pay someone new, the user can add them as a payee first (request_add_payee).")
    if payee["type"] == "biller":
        raise KernelError("This payee is a biller. Use get_bills + draft_bill_payment instead.")
    acct = gw._account(s, a.from_account)
    if payee["type"] == "own":
        acct = acct or next((x["account_id"] for x in gw.bank.accounts(s.user_id)
                             if x["account_id"] != payee["account_id"]), None)
        if a.repeat:
            raise KernelError("Regular transfers between your own accounts aren't available here; a one-off move is.")
    schedule = make_schedule(a.repeat, a.repeat_day) if a.repeat else None
    what = f"{'Regular ' + a.repeat + ' transfer' if schedule else 'Transfer'} {fmt_money(to_cents(a.amount))} to " \
           f"{payee['name']} ({payee['relation']})"
    gw._run_judge(s, what)
    d = gw.kernel.create_draft(s, kind="transfer", payee_id=a.payee_id, amount_cents=to_cents(a.amount),
                               from_account=acct, evidence=a.evidence, verification=gw._verification(s),
                               schedule=schedule)
    return gw._draft_result(d)


TOOLS = [
    Tool("draft_transfer", "draft",
         "DBS Fund Transfer API: create a transfer draft (to a saved person, or between the user's own accounts) for "
         "the user to check on a confirmation card and authorize themselves. With repeat, it sets up a regular "
         "transfer (standing instruction) instead. You cannot execute transfers, only draft them.",
         DraftTransferArgs, draft_transfer, api="Fund Transfer · POST /fund-transfers (draft)"),
]
