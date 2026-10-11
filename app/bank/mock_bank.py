"""Mock 银行：固定的“测试世界”。真实接入时只需替换这个模块，Agent 代码不变。

注意：Agent（模型）从不直接调用这里，只有工具网关（读）和执行器（写）能调用。
"""
from __future__ import annotations

import copy
import threading
import time
import uuid

_WORLD = {
    "users": {
        "u_chen": {
            "name": "陈阿姨",
            "lang": "zh",
            "accounts": [
                {"account_id": "SAV-001", "name": "储蓄账户", "balance_cents": 325000, "currency": "SGD"},
            ],
            "payees": [
                {"payee_id": "p_daughter", "name": "陈美玲", "relation": "女儿", "type": "person",
                 "aliases": ["女儿", "阿囡", "美玲", "daughter", "mei ling", "meiling"],
                 "masked_account": "DBS ••••4821"},
                {"payee_id": "p_son", "name": "陈志强", "relation": "儿子", "type": "person",
                 "aliases": ["儿子", "志强", "son", "ah keong"],
                 "masked_account": "OCBC ••••1937"},
                {"payee_id": "p_sp", "name": "SP Group 水电费", "relation": "账单", "type": "biller",
                 "aliases": ["水电", "电费", "水费", "sp", "sp group", "utilities"],
                 "masked_account": "账单号 ••••5502"},
                {"payee_id": "p_tc", "name": "Bukit Timah 市镇理事会", "relation": "账单", "type": "biller",
                 "aliases": ["杂费", "s&cc", "town council", "市镇理事会"],
                 "masked_account": "账单号 ••••0718"},
            ],
            "bills": [
                {"bill_id": "b_sp_oct", "payee_id": "p_sp", "title": "10 月水电费",
                 "amount_cents": 8640, "due": "2026-10-20", "status": "unpaid"},
                {"bill_id": "b_tc_oct", "payee_id": "p_tc", "title": "10 月市镇理事会杂费 (S&CC)",
                 "amount_cents": 4200, "due": "2026-10-31", "status": "unpaid"},
            ],
            # 历史流水：负数=支出，正数=收入
            "transactions": [
                {"date": "2026-10-01", "desc": "养老金入账 CPF LIFE", "amount_cents": 98000, "payee_id": None},
                {"date": "2026-09-28", "desc": "转账给 陈美玲", "amount_cents": -20000, "payee_id": "p_daughter"},
                {"date": "2026-09-15", "desc": "转账给 陈志强", "amount_cents": -10000, "payee_id": "p_son"},
                {"date": "2026-09-12", "desc": "SP Group 水电费", "amount_cents": -8230, "payee_id": "p_sp"},
                {"date": "2026-09-01", "desc": "养老金入账 CPF LIFE", "amount_cents": 98000, "payee_id": None},
                {"date": "2026-08-27", "desc": "转账给 陈美玲", "amount_cents": -20000, "payee_id": "p_daughter"},
                {"date": "2026-08-20", "desc": "NTUC FairPrice 消费", "amount_cents": -6450, "payee_id": None},
            ],
        }
    }
}


class MockBank:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.world = copy.deepcopy(_WORLD)
            self.executed: dict[str, dict] = {}   # 幂等键 -> 回执
            self.recent_exec_times: dict[str, list[float]] = {}

    # ---------- 只读 ----------
    def user(self, user_id: str) -> dict:
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
        """该收款人的历史支出金额（正数，分）。供风控比较，不进模型提示。"""
        return [-t["amount_cents"] for t in self.user(user_id)["transactions"]
                if t["payee_id"] == payee_id and t["amount_cents"] < 0]

    def recent_exec_count(self, user_id: str, window_sec: int) -> int:
        now = time.time()
        return sum(1 for t in self.recent_exec_times.get(user_id, []) if now - t <= window_sec)

    # ---------- 写：只允许执行器调用 ----------
    def execute_payment(self, user_id: str, from_account: str, payee_id: str,
                        amount_cents: int, idempotency_key: str, bill_id: str | None = None) -> dict:
        with self._lock:
            if idempotency_key in self.executed:          # 幂等：重试不会重复扣款
                return {**self.executed[idempotency_key], "idempotent_replay": True}
            acct = self.account(user_id, from_account)
            if acct is None:
                raise ValueError("账户不存在")
            if acct["balance_cents"] < amount_cents:
                raise ValueError("余额不足")
            payee = self.payee(user_id, payee_id)
            acct["balance_cents"] -= amount_cents
            self.user(user_id)["transactions"].insert(0, {
                "date": time.strftime("%Y-%m-%d"), "desc": f"转账给 {payee['name']}" if payee["type"] == "person"
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
