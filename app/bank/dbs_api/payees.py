"""DBS Payees API: list registered payees; add a new payee (signed by the customer, never by the agent alone)."""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.bank.dbs_api.base import NoArgs, Tool


class AddPayeeArgs(BaseModel):
    name: str = Field(max_length=60, description="The payee's name exactly as the user said it")
    bank: str = Field(default="", max_length=30, description="Their bank, e.g. DBS, POSB, OCBC, UOB")
    account_number: str = Field(max_length=30, description="The account number exactly as the user said it")
    relation: str = Field(default="", max_length=30, description="Who they are to the user, e.g. friend; empty if not said")
    evidence: str = Field(default="", max_length=200, description="Quote the user's exact words")


def list_payees(gw, s, _):
    return [{"payee_id": p["payee_id"], "name": p["name"], "relation": p["relation"], "type": p["type"],
             "aliases": p["aliases"], "account": p["masked_account"]} for p in gw.bank.payees(s.user_id)]


def request_add_payee(gw, s, a: AddPayeeArgs):
    card = gw.kernel.request_change(s, "add_payee", a.model_dump(), a.evidence)
    return {"change_id": card["change_id"], "status": "A confirmation card is now shown. The user checks every digit and "
            "confirms with their fingerprint; nothing is added before that. Tell them in one or two simple sentences."}


TOOLS = [
    Tool("list_payees", "read", "DBS Payees API: the user's saved payees (aliases such as 'daughter'), billers, and "
         "their own accounts (type 'own', for moving money between their own accounts, e.g. 'joint account'). "
         "Must be called before a transfer; use the returned payee_id.", NoArgs, list_payees,
         api="Payees · GET /payees"),
    Tool("request_add_payee", "draft", "DBS Payees API: ask to add a NEW payee the user named, with the bank and the "
         "account number they said. Shows a confirmation card the user must sign; the agent can't add it alone.",
         AddPayeeArgs, request_add_payee, api="Payees · POST /payees", group="add_payee"),
]
