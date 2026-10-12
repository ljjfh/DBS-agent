"""Mock bank: a fixed "test world". For a real integration, replace only this module; the Agent code stays the same.

Note: the Agent (model) never calls this directly. The tool gateway reads; writes go only through the execution
gateway (app/bank/gateway.py), which re-verifies the customer's signature before posting to the ledger.
"""
from __future__ import annotations

import copy
import threading
import time
import uuid

DEMO_USER = "u_chen"

_WORLD = {
    "users": {
        "u_chen": {
            "name": "Mdm Chen",
            "lang": "en",
            # MAS-style suitability: products riskier than this need extra care (rules R70)
            "risk_profile": {"label": "Conservative", "max_product_risk": 2},
            # Protection level is an ACCOUNT setting, not a screen setting (see kernel/protection.py)
            "protection": {"level": "enhanced", "pending": None},
            "accounts": [
                {"account_id": "SAV-001", "name": "Savings Account", "balance_cents": 325000, "currency": "SGD"},
                {"account_id": "CUR-002", "name": "Current Account", "balance_cents": 82000, "currency": "SGD"},
            ],
            "payees": [
                {"payee_id": "p_daughter", "name": "Chen Mei Ling", "relation": "daughter", "type": "person",
                 "aliases": ["daughter", "my girl", "ah girl", "mei ling", "meiling"],
                 "masked_account": "DBS ••••4821"},
                {"payee_id": "p_son", "name": "Chen Zhi Qiang", "relation": "son", "type": "person",
                 "aliases": ["son", "zhi qiang", "ah keong"],
                 "masked_account": "OCBC ••••1937"},
                # Two grandsons: "my grandson" is ambiguous on purpose, so the agent must ask (with buttons)
                {"payee_id": "p_grandson_wei", "name": "Chen Wei", "relation": "grandson", "type": "person",
                 "aliases": ["grandson", "ah wei", "chen wei"], "masked_account": "POSB ••••2290"},
                {"payee_id": "p_grandson_jun", "name": "Chen Jun", "relation": "grandson", "type": "person",
                 "aliases": ["grandson", "ah jun", "chen jun"], "masked_account": "DBS ••••6613"},
                {"payee_id": "p_sp", "name": "SP Group Utilities", "relation": "bill", "type": "biller",
                 "aliases": ["utilities", "utility", "electricity", "water", "sp", "sp group"],
                 "masked_account": "Bill no. ••••5502"},
                {"payee_id": "p_tc", "name": "Bukit Timah Town Council", "relation": "bill", "type": "biller",
                 "aliases": ["s&cc", "town council", "conservancy"],
                 "masked_account": "Bill no. ••••0718"},
            ],
            "bills": [
                {"bill_id": "b_sp_oct", "payee_id": "p_sp", "title": "October utilities bill",
                 "amount_cents": 8640, "due": "2026-10-20", "status": "unpaid"},
                {"bill_id": "b_tc_oct", "payee_id": "p_tc", "title": "October town council charges (S&CC)",
                 "amount_cents": 4200, "due": "2026-10-31", "status": "unpaid"},
            ],
            # units x current demo price = value; cost = what was paid
            "holdings": [
                {"product_id": "b_ssb", "units": 5000.0, "cost_cents": 500000},
                {"product_id": "s_d05", "units": 50.0, "cost_cents": 160000},
            ],
            "cards": [
                {"card_id": "c_debit", "name": "DBS Visa Debit Card", "masked": "•••• 7781", "status": "active"},
                {"card_id": "c_credit", "name": "DBS Live Fresh Card", "masked": "•••• 3304", "status": "active"},
            ],
            # Transaction history: negative = outgoing, positive = incoming
            "transactions": [
                {"date": "2026-10-01", "desc": "Pension payout CPF LIFE", "amount_cents": 98000, "payee_id": None},
                {"date": "2026-09-28", "desc": "Transfer to Chen Mei Ling", "amount_cents": -20000, "payee_id": "p_daughter"},
                {"date": "2026-09-15", "desc": "Transfer to Chen Zhi Qiang", "amount_cents": -10000, "payee_id": "p_son"},
                {"date": "2026-09-20", "desc": "Transfer to Chen Wei", "amount_cents": -5000, "payee_id": "p_grandson_wei"},
                {"date": "2026-09-18", "desc": "Transfer to Chen Jun", "amount_cents": -5000, "payee_id": "p_grandson_jun"},
                {"date": "2026-09-12", "desc": "SP Group Utilities", "amount_cents": -8230, "payee_id": "p_sp"},
                {"date": "2026-09-01", "desc": "Pension payout CPF LIFE", "amount_cents": 98000, "payee_id": None},
                {"date": "2026-08-27", "desc": "Transfer to Chen Mei Ling", "amount_cents": -20000, "payee_id": "p_daughter"},
                {"date": "2026-08-20", "desc": "NTUC FairPrice purchase", "amount_cents": -6450, "payee_id": None},
            ],
        }
    }
}

# What Star can buy, modelled on what DBS digibank offers (synthetic products, DEMO prices and rates).
# risk: 1 (lowest) .. 5 (highest). price is per unit in `currency`; units can be fractional in this demo.
USD_SGD = 1.30          # demo exchange rate
_PRODUCTS = [
    {"product_id": "d_fd12", "name": "DBS Fixed Deposit (12 months)", "asset_class": "Fixed deposit", "risk": 1,
     "min_cents": 100000, "currency": "SGD", "price": 1.0, "rate_pa": 1.80, "tenor_months": 12,
     "aliases": ["fixed deposit", "time deposit", "fd", "12 month deposit", "12-month deposit"]},
    {"product_id": "b_ssb", "name": "Singapore Savings Bonds", "asset_class": "Government bond", "risk": 1,
     "min_cents": 50000, "currency": "SGD", "price": 1.0,
     "aliases": ["savings bond", "savings bonds", "ssb", "government bond", "bonds"]},
    {"product_id": "f_income", "name": "DBS Income Fund", "asset_class": "Unit trust", "risk": 2,
     "min_cents": 10000, "currency": "SGD", "price": 1.0234, "aliases": ["income fund", "dbs income"]},
    {"product_id": "f_asia_div", "name": "DBS Asia Dividend Fund", "asset_class": "Unit trust", "risk": 3,
     "min_cents": 10000, "currency": "SGD", "price": 0.8712,
     "aliases": ["asia dividend", "asia fund", "dividend fund", "asian fund"]},
    {"product_id": "e_sti", "name": "SPDR STI ETF", "asset_class": "ETF", "risk": 4,
     "min_cents": 10000, "currency": "SGD", "price": 3.85,
     "aliases": ["sti", "sti etf", "straits times index", "singapore index", "etf"]},
    {"product_id": "s_d05", "name": "DBS Group Holdings shares", "asset_class": "Shares (SGX)", "risk": 5,
     "min_cents": 10000, "currency": "SGD", "price": 38.50, "ticker": "D05", "exchange": "SGX",
     "aliases": ["dbs shares", "dbs share", "dbs stock", "dbs group", "d05"]},
    {"product_id": "s_z74", "name": "Singtel shares", "asset_class": "Shares (SGX)", "risk": 5,
     "min_cents": 10000, "currency": "SGD", "price": 3.20, "ticker": "Z74", "exchange": "SGX",
     "aliases": ["singtel", "z74"]},
    {"product_id": "s_aapl", "name": "Apple Inc. shares", "asset_class": "Shares (US)", "risk": 5,
     "min_cents": 10000, "currency": "USD", "price": 228.40, "ticker": "AAPL", "exchange": "NASDAQ",
     "aliases": ["apple", "aapl"]},
    {"product_id": "s_msft", "name": "Microsoft Corp. shares", "asset_class": "Shares (US)", "risk": 5,
     "min_cents": 10000, "currency": "USD", "price": 415.20, "ticker": "MSFT", "exchange": "NASDAQ",
     "aliases": ["microsoft", "msft"]},
]


def price_sgd_cents(prod: dict) -> int:
    """Demo price of one unit in SGD cents."""
    return round(prod["price"] * (USD_SGD if prod.get("currency") == "USD" else 1) * 100)


class MockBank:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.world = copy.deepcopy(_WORLD)
            self.products = copy.deepcopy(_PRODUCTS)
            self.executed: dict[str, dict] = {}   # idempotency key -> receipt
            self.recent_exec_times: dict[str, list[float]] = {}

    # ---------- Demo customers per visitor ----------
    # On a shared online demo every browser gets its own copy of Mdm Chen ("u_chen~<visitor id>"), so one tester's
    # payments, resets and passkey never affect another's. Locally (no visitor id) everyone is plain "u_chen".
    MAX_VISITORS = 2000

    @staticmethod
    def visitor_user_id(visitor: str) -> str:
        return f"{DEMO_USER}~{visitor}"

    def _ensure(self, user_id: str) -> None:
        if user_id in self.world["users"] or not user_id.startswith(DEMO_USER + "~"):
            return
        with self._lock:
            users = self.world["users"]
            if user_id not in users:
                visitors = [u for u in users if "~" in u]
                for old in visitors[:max(0, len(visitors) - self.MAX_VISITORS + 1)]:   # forget the oldest
                    users.pop(old, None)
                users[user_id] = copy.deepcopy(_WORLD["users"][DEMO_USER])

    def reset_user(self, user_id: str) -> None:
        """Reset one demo customer's accounts, payees, bills, holdings and cards (nobody else's)."""
        with self._lock:
            self.world["users"][user_id] = copy.deepcopy(_WORLD["users"][DEMO_USER])
            self.recent_exec_times.pop(user_id, None)

    # ---------- Read-only ----------
    def user(self, user_id: str) -> dict:
        self._ensure(user_id)
        return self.world["users"][user_id]

    def accounts(self, user_id: str) -> list[dict]:
        return self.user(user_id)["accounts"]

    def account(self, user_id: str, account_id: str) -> dict | None:
        return next((a for a in self.accounts(user_id) if a["account_id"] == account_id), None)

    def payees(self, user_id: str) -> list[dict]:
        return self.user(user_id)["payees"]

    def payee(self, user_id: str, payee_id: str) -> dict | None:
        return next((p for p in self.payees(user_id) if p["payee_id"] == payee_id), None)

    def bills(self, user_id: str, only_unpaid: bool = True) -> list[dict]:
        bills = self.user(user_id)["bills"]
        return [b for b in bills if b["status"] == "unpaid"] if only_unpaid else bills

    def bill(self, user_id: str, bill_id: str) -> dict | None:
        return next((b for b in self.user(user_id)["bills"] if b["bill_id"] == bill_id), None)

    def transactions(self, user_id: str, limit: int = 10) -> list[dict]:
        return self.user(user_id)["transactions"][:limit]

    def payee_history(self, user_id: str, payee_id: str) -> list[int]:
        """Past amounts paid to this payee (positive, in cents). Used by the risk rules; never shown to the model."""
        return [-t["amount_cents"] for t in self.user(user_id)["transactions"]
                if t["payee_id"] == payee_id and t["amount_cents"] < 0]

    def product(self, product_id: str) -> dict | None:
        return next((p for p in self.products if p["product_id"] == product_id), None)

    def holdings(self, user_id: str) -> list[dict]:
        return self.user(user_id)["holdings"]

    def portfolio(self, user_id: str) -> list[dict]:
        out = []
        for h in self.holdings(user_id):
            p = self.product(h["product_id"]) or {}
            value = round(h["units"] * price_sgd_cents(p)) if p else h["cost_cents"]
            out.append({"product_id": h["product_id"], "name": p.get("name", h["product_id"]),
                        "asset_class": p.get("asset_class", ""), "units": h["units"], "value_cents": value,
                        "cost_cents": h["cost_cents"], "gain_cents": value - h["cost_cents"]})
        return out

    def cards(self, user_id: str) -> list[dict]:
        return self.user(user_id)["cards"]

    def card(self, user_id: str, card_id: str) -> dict | None:
        return next((c for c in self.cards(user_id) if c["card_id"] == card_id), None)

    # Locking a card is a protective action: allowed straight away (unlocking is not offered through Star)
    def lock_card(self, user_id: str, card_id: str) -> dict:
        with self._lock:
            c = self.card(user_id, card_id)
            if c is None:
                raise ValueError("Card not found")
            c["status"], c["locked_at"] = "locked", time.time()
            return dict(c)

    def risk_profile(self, user_id: str) -> dict:
        return self.user(user_id)["risk_profile"]

    def protection(self, user_id: str) -> dict:
        return self.user(user_id)["protection"]

    def recent_exec_count(self, user_id: str, window_sec: int) -> int:
        now = time.time()
        return sum(1 for t in self.recent_exec_times.get(user_id, []) if now - t <= window_sec)

    # ---------- Write: only the execution gateway may call these ----------
    def execute_investment(self, user_id: str, from_account: str, product_id: str, amount_cents: int,
                           idempotency_key: str) -> dict:
        with self._lock:
            if idempotency_key in self.executed:
                return {**self.executed[idempotency_key], "idempotent_replay": True}
            acct, prod = self.account(user_id, from_account), self.product(product_id)
            if acct is None or prod is None:
                raise ValueError("Account or product not found")
            if acct["balance_cents"] < amount_cents:
                raise ValueError("Insufficient balance")
            acct["balance_cents"] -= amount_cents
            units = round(amount_cents / price_sgd_cents(prod), 4)
            h = next((h for h in self.holdings(user_id) if h["product_id"] == product_id), None)
            if h:
                h["units"] += units
                h["cost_cents"] += amount_cents
            else:
                self.holdings(user_id).append({"product_id": product_id, "units": units, "cost_cents": amount_cents})
            self.user(user_id)["transactions"].insert(0, {
                "date": time.strftime("%Y-%m-%d"), "desc": f"Buy {prod['name']} ({prod['asset_class']})",
                "amount_cents": -amount_cents, "payee_id": product_id})
            receipt = {"txn_id": "TXN-" + uuid.uuid4().hex[:10].upper(), "status": "SUCCESS",
                       "amount_cents": amount_cents, "product_id": product_id, "units": units,
                       "balance_after_cents": acct["balance_cents"], "executed_at": time.time()}
            self.executed[idempotency_key] = receipt
            self.recent_exec_times.setdefault(user_id, []).append(time.time())
            return receipt

    def execute_payment(self, user_id: str, from_account: str, payee_id: str,
                        amount_cents: int, idempotency_key: str, bill_id: str | None = None) -> dict:
        with self._lock:
            if idempotency_key in self.executed:          # idempotent: a retry never debits twice
                return {**self.executed[idempotency_key], "idempotent_replay": True}
            acct = self.account(user_id, from_account)
            if acct is None:
                raise ValueError("Account not found")
            if acct["balance_cents"] < amount_cents:
                raise ValueError("Insufficient balance")
            payee = self.payee(user_id, payee_id)
            acct["balance_cents"] -= amount_cents
            self.user(user_id)["transactions"].insert(0, {
                "date": time.strftime("%Y-%m-%d"), "desc": f"Transfer to {payee['name']}" if payee["type"] == "person"
                else payee["name"], "amount_cents": -amount_cents, "payee_id": payee_id})
            if bill_id:
                b = self.bill(user_id, bill_id)
                if b:
                    b["status"] = "paid"
            receipt = {"txn_id": "TXN-" + uuid.uuid4().hex[:10].upper(), "status": "SUCCESS",
                       "amount_cents": amount_cents, "payee_id": payee_id,
                       "balance_after_cents": acct["balance_cents"], "executed_at": time.time()}
            self.executed[idempotency_key] = receipt
            self.recent_exec_times.setdefault(user_id, []).append(time.time())
            return receipt


bank = MockBank()
