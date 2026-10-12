"""DBS Fund Transfer API: one-off transfers to saved people, and between the customer's own accounts.
Regular transfers have their own API (standing_instructions.py) but share create_transfer_draft below, so they get
the same card, independent check and signature.

The agent only drafts. Everything after that is the kernel's: evidence grounding, the independent verifier, the
rules (incl. the daily limit), the code-built card, the customer's signature, and the execution gateway.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.bank.dbs_api.base import MEANT_DESC, MISHEARD_DESC, Tool
from app.kernel.executor import KernelError
from app.models import fmt_money, to_cents

_FROM = "Optional. account_id from get_balance, ONLY if the user said which account to pay from; else omit"


class DraftTransferArgs(BaseModel):
    model_config = ConfigDict(extra="allow")        # so a stray "repeat" gets a helpful answer, not silence
    payee_id: str = Field(description="Must be a payee_id returned by list_payees (own accounts start with 'own:')")
    amount: float = Field(gt=0, description="Amount in SGD, e.g. 200 or 50.5")
    from_account: Optional[str] = Field(default=None, description=_FROM)
    evidence: str = Field(default="", max_length=200, description="Quote the user's exact words that asked for this payment")
    misheard: str = Field(default="", max_length=40, description=MISHEARD_DESC)
    meant: str = Field(default="", max_length=40, description=MEANT_DESC)
    note: str = Field(default="", max_length=60)


def create_transfer_draft(gw, s, *, payee_id: str, amount: float, from_account: str | None, evidence: str,
                          heard: tuple[str, str], schedule: dict | None = None):
    """Shared by Fund Transfer (one-off) and Standing Instructions (regular)."""
    payee = gw.bank.payee(s.user_id, payee_id)
    if payee is None:
        raise KernelError(f"payee_id={payee_id} is not in the user's saved payees. Only use a payee_id returned by "
                          "list_payees; to pay someone new, the user can add them as a payee first (request_add_payee).")
    if payee["type"] == "biller":
        raise KernelError("This payee is a biller. Use get_bills + draft_bill_payment instead.")
    acct = gw._account(s, from_account)
    if payee["type"] == "own":
        if schedule:
            raise KernelError("Regular transfers between your own accounts aren't available here; a one-off move is.")
        acct = acct or next((x["account_id"] for x in gw.bank.accounts(s.user_id)
                             if x["account_id"] != payee["account_id"]), None)
    what = f"{'Regular ' + schedule['frequency'] + ' transfer' if schedule else 'Transfer'} " \
           f"{fmt_money(to_cents(amount))} to {payee['name']} ({payee['relation']})"
    gw._run_judge(s, what)
    d = gw.kernel.create_draft(s, kind="transfer", payee_id=payee_id, amount_cents=to_cents(amount),
                               from_account=acct, evidence=evidence, verification=gw._verification(s),
                               schedule=schedule, heard=heard)
    return gw._draft_result(d)


def draft_transfer(gw, s, a: DraftTransferArgs):
    if any(k in (a.model_extra or {}) for k in ("repeat", "repeat_day", "frequency", "day")):
        raise KernelError("draft_transfer is for one-off transfers. For a regular transfer ('every month'), use "
                          "draft_standing_instruction (DBS Standing Instructions API).")
    return create_transfer_draft(gw, s, payee_id=a.payee_id, amount=a.amount, from_account=a.from_account,
                                 evidence=a.evidence, heard=(a.misheard, a.meant))


TOOLS = [
    Tool("draft_transfer", "draft",
         "DBS Fund Transfer API: create a transfer draft (to a saved person, or between the user's own accounts) for "
         "the user to check on a confirmation card and authorize themselves. One-off only: for 'every month' use "
         "draft_standing_instruction. You cannot execute transfers, only draft them.",
         DraftTransferArgs, draft_transfer, api="Fund Transfer · POST /fund-transfers (draft)"),
]
