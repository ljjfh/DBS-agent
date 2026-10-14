"""Two demo customers, one risk engine: Mdm Chen (senior care) and Alex Tan (everyday)."""
import os
import unittest

os.environ.setdefault("RULE_FIXED_HOUR", "14")

from starlette.testclient import TestClient  # noqa: E402

from app.agent.prompts import system_prompt  # noqa: E402
from app.bank.mock_bank import MockBank, base_user  # noqa: E402
from app.kernel.contract import secondary_required  # noqa: E402
from app.server import app  # noqa: E402


class TestCustomers(unittest.TestCase):
    def test_same_rules_different_voice(self):
        senior, everyday = system_prompt("senior"), system_prompt("everyday")
        self.assertEqual(senior.split("[How to speak]")[0], everyday.split("[How to speak]")[0])   # same rules
        self.assertIn("two hundred dollars (S$200.00)", senior)
        self.assertIn("Be brief and direct", everyday)

    def test_alex_world_and_visitor_copies(self):
        bank = MockBank()
        self.assertEqual(base_user("u_alex~abc"), "u_alex")
        self.assertEqual(bank.user("u_alex~abc")["name"], "Alex Tan")
        self.assertEqual([a["account_id"] for a in bank.accounts("u_alex~abc")], ["SAV-001", "CUR-002"])  # no joint
        bank.reset_user("u_alex~abc")
        self.assertEqual(bank.user("u_alex~abc")["protection"]["level"], "standard")
        # same reviewer rule: mum has been paid before; a new payee needs it above Standard's S$3,000
        new = bank.add_payee("u_alex~abc", "Lim Supplies", "UOB", "5566778899", "supplier")["payee_id"]

        def card(p, c):
            return {"user_id": "u_alex~abc", "payee_id": p, "amount_cents": c, "kind": "transfer"}
        self.assertFalse(secondary_required(card("p_mum", 400000), bank))
        self.assertFalse(secondary_required(card(new, 250000), bank))
        self.assertTrue(secondary_required(card(new, 350000), bank))

    def test_switch_customer_over_http(self):
        c = TestClient(app, base_url="http://localhost")
        sid = c.post("/api/reset", json={"persona": "alex", "world": True}).json()["session_id"]
        st = c.get("/api/state", params={"session_id": sid}).json()
        self.assertEqual((st["user"], st["persona"], st["customer"]), ("Alex Tan", "everyday", "alex"))
        r = c.post("/api/chat", json={"session_id": sid, "text": "Send mum 500"}).json()
        self.assertEqual(r["ui"]["card"]["payee_name"], "Tan Li Hua")
        self.assertEqual(r["ui"]["card"]["readback"], "S$500.00 to Tan Li Hua, from Savings Account.")
        sid2 = c.post("/api/reset", json={"session_id": sid, "persona": "chen"}).json()["session_id"]
        self.assertEqual(c.get("/api/state", params={"session_id": sid2}).json()["user"], "Mdm Chen")
