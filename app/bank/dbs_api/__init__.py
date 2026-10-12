"""Mock DBS APIs (named after the DBS developer catalogue). Add a module, then list it here."""
from app.bank.dbs_api import (bill_payments, deposits, fund_transfer, giro, limits, payees,  # noqa: F401
                              standing_instructions)

MODULES = [deposits, payees, limits, fund_transfer, bill_payments, standing_instructions, giro]


def all_tools():
    return [t for m in MODULES for t in m.TOOLS]
