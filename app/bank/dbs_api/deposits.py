"""DBS Deposit API: the customer's deposit accounts (savings, current, joint) and their details."""
from __future__ import annotations

from app.bank.dbs_api.base import NoArgs, Tool
from app.models import fmt_money


def list_accounts(gw, s, _):
    return [{"account_id": a["account_id"], "name": a["name"], "type": a.get("type", ""),
             "product": a.get("product", ""), "number": a.get("masked", ""), "balance": fmt_money(a["balance_cents"]),
             "interest": f"{a.get('interest_pct', 0):.2f}% a year (demo rate)", "holders": a.get("holders", [])}
            for a in gw.bank.accounts(s.user_id)]


TOOLS = [
    Tool("get_balance", "read", "DBS Deposit API: the customer's accounts (savings, current, joint) with balance, "
         "masked account number, interest rate and holders. Use the account_id as from_account.",
         NoArgs, list_accounts, api="Deposit · GET /deposit-accounts"),
]
