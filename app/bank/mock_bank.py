"""Mock bank: a fixed "test world". For a real integration, replace only this module; the Agent code stays the same.

Note: the Agent (model) never calls this directly. The tool gateway reads; writes go only through the execution
gateway (app/bank/gateway.py), which re-verifies the customer's signature before posting to the ledger.
"""
from __future__ import annotations

import copy
import hashlib
import json

from app.bank.storage import LedgerStorage, atomic_write
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
            # DBS Deposit API: savings, current and a joint account (with her daughter)
            "accounts": [
                {"account_id": "SAV-001", "name": "Savings Account", "balance_cents": 325000, "currency": "SGD",
                 "type": "savings", "product": "POSB Passbook Savings", "masked": "POSB ••••3307",
                 "interest_pct": 0.05, "holders": ["Mdm Chen"]},
                {"account_id": "CUR-002", "name": "Current Account", "balance_cents": 82000, "currency": "SGD",
                 "type": "current", "product": "DBS Current Account", "masked": "DBS ••••7712",
                 "interest_pct": 0.0, "holders": ["Mdm Chen"]},
                {"account_id": "JNT-003", "name": "Joint Account", "balance_cents": 150000, "currency": "SGD",
                 "type": "joint", "product": "DBS Multiplier (joint)", "masked": "DBS ••••0451",
                 "interest_pct": 0.08, "holders": ["Mdm Chen", "Chen Mei Ling"]},
            ],
            # DBS Limits API: daily limit for transfers to other people (own-account moves and bills don't count)
            "limits": {"daily_transfer_cents": 300000, "pending": None},
            # DBS Standing Instructions API: scheduled transfers to saved payees
            "standing_instructions": [
                {"si_id": "SI-0001", "payee_id": "p_daughter", "amount_cents": 20000, "frequency": "monthly",
                 "day": 28, "from_account": "SAV-001", "next_date": "2026-10-28", "status": "active",
                 "description": "Monthly allowance to Chen Mei Ling"},
            ],
            # DBS GIRO API: billing organisations allowed to deduct automatically
            "giro": [
                {"giro_id": "GIRO-01", "biller": "StarHub Mobile", "aliases": ["starhub", "mobile", "phone bill", "handphone"],
                 "reference": "••••8821", "limit_cents": 8000, "frequency": "monthly", "from_account": "SAV-001",
                 "last_deduction": "2026-09-15 · S$42.90", "status": "active"},
                {"giro_id": "GIRO-02", "biller": "ActiveSG Gym", "aliases": ["gym", "activesg", "active sg", "fitness"],
                 "reference": "••••1190", "limit_cents": 3000, "frequency": "monthly", "from_account": "SAV-001",
                 "last_deduction": "2026-10-01 · S$25.00", "status": "active"},
                {"giro_id": "GIRO-03", "biller": "Income Insurance", "aliases": ["income insurance", "insurance", "ntuc income"],
                 "reference": "••••5536", "limit_cents": 15000, "frequency": "monthly", "from_account": "SAV-001",
                 "last_deduction": "2026-10-05 · S$118.40", "status": "active"},
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
                {"payee_id": "p_cc", "name": "DBS Cards", "relation": "bill", "type": "biller",
                 "aliases": ["credit card", "card bill", "live fresh", "credit card bill"],
                 "masked_account": "Live Fresh Card ••••3304"},
            ],
            "bills": [
                {"bill_id": "b_sp_oct", "payee_id": "p_sp", "title": "October utilities bill",
                 "amount_cents": 8640, "due": "2026-10-20", "status": "unpaid"},
                {"bill_id": "b_tc_oct", "payee_id": "p_tc", "title": "October town council charges (S&CC)",
                 "amount_cents": 4200, "due": "2026-10-31", "status": "unpaid"},
                # Credit card: pay the full statement, the minimum, or an amount in between (DBS Bill Payments API)
                {"bill_id": "b_cc_oct", "payee_id": "p_cc", "title": "DBS Live Fresh Card statement",
                 "amount_cents": 124050, "min_due_cents": 5000, "due": "2026-10-25", "status": "unpaid"},
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


class MockBank(LedgerStorage):
    def __init__(self, path=None):
        self._lock = threading.RLock()
        self.path = None
        self.world, self.executed, self.recent_exec_times, self.outbox = {}, {}, {}, []
        self.reset()
        self.path = path
        self._load()

    @atomic_write
    def reset(self):
        with self._lock:
            self.world = copy.deepcopy(_WORLD)
            self.products = copy.deepcopy(_PRODUCTS)
            self.executed: dict[str, dict] = {}   # idempotency key -> receipt
            self.recent_exec_times: dict[str, list[float]] = {}
            self.outbox = []

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

    @atomic_write
    def reset_user(self, user_id: str) -> None:
        """Reset one demo customer's accounts, payees, bills, holdings and cards (nobody else's)."""
        with self._lock:
            self.world["users"][user_id] = copy.deepcopy(_WORLD["users"][DEMO_USER])
            self.recent_exec_times.pop(user_id, None)
            self.executed = {k: r for k, r in self.executed.items() if r.get("user_id") != user_id}

    # ---------- Read-only ----------
    def user(self, user_id: str) -> dict:
        self._ensure(user_id)
        user = self.world["users"][user_id]
        for field in ("limits", "standing_instructions", "giro"):
            user.setdefault(field, copy.deepcopy(_WORLD["users"][DEMO_USER][field]))
        templates = {a["account_id"]: a for a in _WORLD["users"][DEMO_USER]["accounts"]}
        for account in user["accounts"]:
            for key, value in templates.get(account["account_id"], {}).items():
                if key != "balance_cents":
                    account.setdefault(key, copy.deepcopy(value))
        return user

    def accounts(self, user_id: str) -> list[dict]:
        accounts = self.user(user_id)["accounts"]
        # Synthetic, single-signatory joint account for the competition example.
        # This does not implement a real bank's joint-account mandate.
        if not any(a["account_id"] == "JNT-003" for a in accounts):
            accounts.append({"account_id": "JNT-003", "name": "Joint Account", "balance_cents": 0, "currency": "SGD"})
        return accounts

    def account(self, user_id: str, account_id: str) -> dict | None:
        return next((a for a in self.accounts(user_id) if a["account_id"] == account_id), None)

    _OWN_ALIASES = {"savings": ["savings account", "my savings account", "my savings"],
                    "current": ["current account", "my current account"],
                    "joint": ["joint account", "my joint account", "joint acc", "joint"]}

    def own_accounts_as_payees(self, user_id: str) -> list[dict]:
        """The customer's own accounts as transfer targets (DBS Fund Transfer API: own-account transfers)."""
        return [{"payee_id": f"own:{a['account_id']}", "name": a["name"], "relation": "own account", "type": "own",
                 "aliases": self._OWN_ALIASES.get(a.get("type", ""), []), "masked_account": a.get("masked", ""),
                 "account_id": a["account_id"]} for a in self.accounts(user_id)]

    def payees(self, user_id: str) -> list[dict]:
        return self.user(user_id)["payees"] + self.own_accounts_as_payees(user_id)

    def payee(self, user_id: str, payee_id: str) -> dict | None:
        return next((p for p in self.payees(user_id) if p["payee_id"] == payee_id), None)

    def bills(self, user_id: str, only_unpaid: bool = True) -> list[dict]:
        bills = self.user(user_id)["bills"]
        return [b for b in bills if b["status"] == "unpaid"] if only_unpaid else bills

    def bill(self, user_id: str, bill_id: str) -> dict | None:
        return next((b for b in self.user(user_id)["bills"] if b["bill_id"] == bill_id), None)

    def transactions(self, user_id: str, limit: int = 10) -> list[dict]:
        return self.user(user_id)["transactions"][:limit]

    def limits(self, user_id: str) -> dict:
        lim = self.user(user_id)["limits"]
        p = lim.get("pending")
        if p and p["effective_at"] <= time.time():          # a scheduled raise takes effect
            lim["daily_transfer_cents"], lim["pending"] = p["to_cents"], None
        return lim

    def transferred_today(self, user_id: str) -> int:
        """Sum of today's transfers to other people (what the daily limit counts)."""
        today = time.strftime("%Y-%m-%d")
        own = {f"own:{a['account_id']}" for a in self.accounts(user_id)}
        people = {p["payee_id"] for p in self.user(user_id)["payees"] if p["type"] == "person"}
        return sum(-t["amount_cents"] for t in self.user(user_id)["transactions"]
                   if t["date"] == today and t["amount_cents"] < 0 and t.get("payee_id") in people
                   and t.get("payee_id") not in own)

    def standing_instructions(self, user_id: str) -> list[dict]:
        return self.user(user_id)["standing_instructions"]

    def giro(self, user_id: str) -> list[dict]:
        return self.user(user_id)["giro"]

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
    @atomic_write
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

    @atomic_write
    def update_protection(self, user_id: str, level=None, pending=None):
        p = self.protection(user_id)
        if level is not None:
            p["level"] = level
        p["pending"] = pending
        return copy.deepcopy(p)

    def recent_exec_count(self, user_id: str, window_sec: int) -> int:
        now = time.time()
        return sum(1 for t in self.recent_exec_times.get(user_id, []) if now - t <= window_sec)

    def _check_velocity(self, user_id):
        # Called inside the atomic ledger lock: two signed requests cannot both take the last slot.
        from app.config import settings
        if self.recent_exec_count(user_id, settings.velocity_window_min * 60) >= settings.velocity_max:
            raise ValueError("R21_VELOCITY: transaction frequency limit reached; wait and prepare a new request")

    # ---------- Write: only the execution gateway may call these ----------
    @atomic_write
    def execute_investment(self, user_id: str, from_account: str, product_id: str, amount_cents: int,
                           idempotency_key: str, metadata: dict | None = None) -> dict:
        with self._lock:
            if type(amount_cents) is not int or amount_cents <= 0:
                raise ValueError("Amount must be a positive integer number of cents")
            if idempotency_key in self.executed:
                previous = self.executed[idempotency_key]
                if previous.get("user_id") != user_id or previous["amount_cents"] != amount_cents or (metadata and
                    previous.get("verifiable", {}).get("digest") != metadata.get("digest")):
                    raise ValueError("Idempotency key belongs to a different instruction")
                return {**copy.deepcopy(previous), "idempotent_replay": True}
            self._check_velocity(user_id)
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
            receipt.update(user_id=user_id, draft_id=idempotency_key)
            if metadata:
                body = {"receipt_version": 2, "txn_id": receipt["txn_id"], "status": receipt["status"],
                        "executed_at": int(receipt["executed_at"]), **metadata}
                body["receipt_sha256"] = hashlib.sha256(json.dumps(body, ensure_ascii=False,
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                receipt["verifiable"] = body
                for event in ("gateway.posted", "commit.executed"):
                    self.outbox.append({"event": event, "session_id": metadata.get("session_id", ""),
                        "data": {"draft_id": idempotency_key, "txn_id": receipt["txn_id"], "receipt": body}})
            self.executed[idempotency_key] = receipt
            self.recent_exec_times.setdefault(user_id, []).append(time.time())
            return receipt

    @atomic_write
    def execute_payment(self, user_id: str, from_account: str, payee_id: str,
                        amount_cents: int, idempotency_key: str, bill_id: str | None = None, metadata: dict | None = None) -> dict:
        with self._lock:
            if type(amount_cents) is not int or amount_cents <= 0:
                raise ValueError("Amount must be a positive integer number of cents")
            if idempotency_key in self.executed:          # idempotent: a retry never debits twice
                previous = self.executed[idempotency_key]
                if previous.get("user_id") != user_id or previous["amount_cents"] != amount_cents or (metadata and
                    previous.get("verifiable", {}).get("digest") != metadata.get("digest")):
                    raise ValueError("Idempotency key belongs to a different instruction")
                return {**copy.deepcopy(previous), "idempotent_replay": True}
            self._check_velocity(user_id)
            acct = self.account(user_id, from_account)
            if acct is None:
                raise ValueError("Account not found")
            if acct["balance_cents"] < amount_cents:
                raise ValueError("Insufficient balance")
            payee = self.payee(user_id, payee_id)
            if payee is None:
                raise ValueError("Payee not found")
            destination = None
            if payee.get("type") == "own":
                destination = self.account(user_id, payee["account_id"])
                if destination is None or destination["account_id"] == from_account or bill_id:
                    raise ValueError("Own-account transfer needs two different owned accounts and no bill")
            if bill_id:
                bill = self.bill(user_id, bill_id)
                if not bill or bill["status"] != "unpaid":
                    raise ValueError("This bill is already paid or unavailable")
                valid_amount = (0 < amount_cents <= bill["amount_cents"] if "min_due_cents" in bill
                                else bill["amount_cents"] == amount_cents)
                if bill["payee_id"] != payee_id or not valid_amount:
                    raise ValueError("Bill details changed; please prepare a new payment")
            acct["balance_cents"] -= amount_cents
            if destination is not None:
                destination["balance_cents"] += amount_cents
                self.user(user_id)["transactions"].insert(0, {
                    "date": time.strftime("%Y-%m-%d"), "desc": f"Internal credit to {destination['name']}",
                    "amount_cents": amount_cents, "payee_id": payee_id})
            self.user(user_id)["transactions"].insert(0, {
                "date": time.strftime("%Y-%m-%d"), "desc": f"Transfer to {payee['name']}" if payee["type"] in ("person", "own")
                else payee["name"], "amount_cents": -amount_cents, "payee_id": payee_id})
            if bill_id:
                b = self.bill(user_id, bill_id)
                if b and "min_due_cents" in b and amount_cents < b["amount_cents"]:
                    b["amount_cents"] -= amount_cents              # card bill paid in part: the rest stays due
                    b["min_due_cents"] = 0
                    b["paid_cents"] = b.get("paid_cents", 0) + amount_cents
                elif b:
                    b["status"] = "paid"
            receipt = {"txn_id": "TXN-" + uuid.uuid4().hex[:10].upper(), "status": "SUCCESS",
                       "amount_cents": amount_cents, "payee_id": payee_id,
                       "balance_after_cents": acct["balance_cents"], "executed_at": time.time()}
            receipt.update(user_id=user_id, draft_id=idempotency_key)
            if metadata:
                body = {"receipt_version": 2, "txn_id": receipt["txn_id"], "status": receipt["status"],
                        "executed_at": int(receipt["executed_at"]), **metadata}
                body["receipt_sha256"] = hashlib.sha256(json.dumps(body, ensure_ascii=False,
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                receipt["verifiable"] = body
                for event in ("gateway.posted", "commit.executed"):
                    self.outbox.append({"event": event, "session_id": metadata.get("session_id", ""),
                        "data": {"draft_id": idempotency_key, "txn_id": receipt["txn_id"], "receipt": body}})
            self.executed[idempotency_key] = receipt
            self.recent_exec_times.setdefault(user_id, []).append(time.time())
            return receipt

    @atomic_write
    def create_standing_instruction(self, user_id: str, from_account: str, payee_id: str, amount_cents: int,
                                    schedule: dict, idempotency_key: str, metadata: dict | None = None) -> dict:
        """Set up a scheduled transfer (DBS Standing Instructions API). No money moves until the first date."""
        with self._lock:
            if idempotency_key in self.executed:
                return {**self.executed[idempotency_key], "idempotent_replay": True}
            payee = self.payee(user_id, payee_id)
            if payee is None or self.account(user_id, from_account) is None:
                raise ValueError("Payee or account not found")
            si = {"si_id": "SI-" + uuid.uuid4().hex[:4].upper(), "payee_id": payee_id, "amount_cents": amount_cents,
                  "frequency": schedule["frequency"], "day": schedule["day"], "from_account": from_account,
                  "next_date": schedule["first_date"], "status": "active",
                  "description": f"{schedule['frequency'].capitalize()} transfer to {payee['name']}"}
            self.standing_instructions(user_id).append(si)
            receipt = {"txn_id": si["si_id"], "status": "SCHEDULED", "amount_cents": amount_cents, "payee_id": payee_id,
                       "first_date": si["next_date"], "balance_after_cents": self.account(user_id, from_account)["balance_cents"],
                       "executed_at": time.time()}
            receipt.update(user_id=user_id, draft_id=idempotency_key)
            if metadata:
                body = {"receipt_version": 2, "txn_id": receipt["txn_id"], "status": receipt["status"],
                        "executed_at": int(receipt["executed_at"]), **metadata}
                body["receipt_sha256"] = hashlib.sha256(json.dumps(body, ensure_ascii=False,
                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                receipt["verifiable"] = body
                for event in ("gateway.posted", "commit.executed"):
                    self.outbox.append({"event": event, "session_id": metadata.get("session_id", ""),
                        "data": {"draft_id": idempotency_key, "txn_id": receipt["txn_id"], "receipt": body}})
            self.executed[idempotency_key] = receipt
            return receipt

    # Protective and signed account changes (called by the kernel only)
    @atomic_write
    def cancel_standing_instruction(self, user_id: str, si_id: str) -> dict:
        with self._lock:
            si = next((x for x in self.standing_instructions(user_id) if x["si_id"] == si_id), None)
            if si is None:
                raise ValueError("Standing instruction not found")
            si["status"] = "cancelled"
            return dict(si)

    @atomic_write
    def cancel_giro(self, user_id: str, giro_id: str) -> dict:
        with self._lock:
            g = next((x for x in self.giro(user_id) if x["giro_id"] == giro_id), None)
            if g is None:
                raise ValueError("GIRO arrangement not found")
            g["status"] = "cancelled"
            return dict(g)

    @atomic_write
    def add_giro(self, user_id: str, biller: str, aliases: list[str], limit_cents: int | None, from_account: str) -> dict:
        with self._lock:
            g = {"giro_id": "GIRO-" + uuid.uuid4().hex[:3].upper(), "biller": biller, "aliases": aliases,
                 "reference": "pending", "limit_cents": limit_cents, "frequency": "per bill", "from_account": from_account,
                 "last_deduction": "none yet", "status": "pending approval"}
            self.giro(user_id).append(g)
            return dict(g)

    @atomic_write
    def add_payee(self, user_id: str, name: str, bank_name: str, account_number: str, relation: str) -> dict:
        with self._lock:
            p = {"payee_id": "p_" + uuid.uuid4().hex[:6], "name": name, "relation": relation or "payee",
                 "type": "person", "aliases": [name.lower(), *([relation.lower()] if relation else [])],
                 "masked_account": f"{bank_name} ••••{account_number[-4:]}", "added_at": time.time()}
            self.user(user_id)["payees"].append(p)
            return dict(p)

    @atomic_write
    def set_daily_limit(self, user_id: str, cents: int, effective_at: float | None = None) -> dict:
        with self._lock:
            lim = self.user(user_id)["limits"]
            if effective_at is None:
                lim["daily_transfer_cents"], lim["pending"] = cents, None
            else:
                lim["pending"] = {"to_cents": cents, "effective_at": effective_at}
            return dict(lim)


bank = MockBank()
