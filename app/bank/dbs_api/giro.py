"""DBS GIRO API: automatic deductions by billing organisations. Cancel = protective; set up = signed by the user."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from app.bank.dbs_api.base import NoArgs, Tool
from app.models import fmt_money, to_cents


class CancelGiroArgs(BaseModel):
    giro_id: str = Field(description="giro_id from list_giro")


class GiroSetupArgs(BaseModel):
    biller_payee_id: str = Field(description="payee_id of the billing organisation, from get_bills / list_payees")
    max_amount: Optional[float] = Field(default=None, gt=0, description="Maximum per deduction in SGD, ONLY if the user said one")
    from_account: Optional[str] = Field(default=None, description="account_id, only if the user said which account")
    evidence: str = Field(default="", max_length=200, description="Quote the user's exact words")


def list_giro(gw, s, _):
    return [{"giro_id": g["giro_id"], "biller": g["biller"], "aliases": g.get("aliases", []), "status": g["status"],
             "max_each_time": fmt_money(g["limit_cents"]) if g.get("limit_cents") else "each bill in full",
             "last_deduction": g["last_deduction"], "from_account": g["from_account"]}
            for g in gw.bank.giro(s.user_id) if g["status"] != "cancelled"]


def cancel_giro(gw, s, a: CancelGiroArgs):
    g = gw.kernel.cancel_giro(s, a.giro_id)
    return {"cancelled": g["biller"], "status": "Cancelled now; they can't deduct any more. Their future bills must be "
            "paid another way. Tell the user in one or two simple sentences."}


def request_giro_setup(gw, s, a: GiroSetupArgs):
    card = gw.kernel.request_change(s, "giro_setup", {
        "biller_payee_id": a.biller_payee_id, "limit_cents": to_cents(a.max_amount) if a.max_amount else None,
        "from_account": a.from_account}, a.evidence)
    return {"change_id": card["change_id"], "status": "A confirmation card is shown; the user confirms with their "
            "fingerprint. Tell them in one or two simple sentences."}


TOOLS = [
    Tool("list_giro", "read", "DBS GIRO API: billing organisations allowed to deduct from the user's account "
         "automatically (phone, gym, insurance...).", NoArgs, list_giro, api="GIRO · GET /giro-arrangements",
         group="regular"),
    Tool("cancel_giro", "control", "DBS GIRO API: cancel a GIRO the user named. Protective, applies at once.",
         CancelGiroArgs, cancel_giro, api="GIRO · DELETE /giro-arrangements/{id}", group="regular"),
    Tool("request_giro_setup", "draft", "DBS GIRO API: set up GIRO for one of the user's billing organisations. Shows "
         "a card the user must sign.", GiroSetupArgs, request_giro_setup, api="GIRO · POST /giro-arrangements",
         group="regular"),
]
