"""Care mode: Star asks on arrival; a yes switches to the easier version (bigger text, simpler words, read aloud).
Only how Star looks and talks changes; every safety check is the same in both modes."""
import os
import unittest

os.environ.setdefault("RULE_FIXED_HOUR", "14")

from starlette.testclient import TestClient  # noqa: E402

from app.agent.loop import care_answer  # noqa: E402
from app.agent.prompts import system_prompt  # noqa: E402
from app.server import app  # noqa: E402


class TestCareMode(unittest.TestCase):
    def setUp(self):
        self.c = TestClient(app, base_url="http://localhost")
        self.sid = self.c.post("/api/reset", json={"world": True}).json()["session_id"]

    def chat(self, text):
        return self.c.post("/api/chat", json={"session_id": self.sid, "text": text}).json()

    def test_ask_on_arrival_then_yes_switches(self):
        offer = self.c.post("/api/care/offer", json={"session_id": self.sid}).json()
        self.assertIn("easier version", offer["offer"])
        self.assertEqual(len(offer["options"]), 2)
        r = self.chat("Yes, please")
        self.assertIs(r["ui"]["care_mode"], True)
        card = self.chat("Send 300 to my daughter")["ui"]["card"]
        self.assertIn("three hundred dollars", card["readback"])          # care: amounts in words

    def test_no_keeps_the_standard_view(self):
        self.c.post("/api/care/offer", json={"session_id": self.sid})
        self.assertIs(self.chat("No, thanks")["ui"]["care_mode"], False)
        card = self.chat("Send 300 to my daughter")["ui"]["card"]
        self.assertEqual(card["readback"], "S$300.00 to Chen Mei Ling, from Savings Account.")

    def test_a_request_instead_of_an_answer_is_just_a_request(self):
        self.c.post("/api/care/offer", json={"session_id": self.sid})
        r = self.chat("Send 300 to my daughter")
        self.assertNotIn("care_mode", r["ui"])
        self.assertEqual(r["ui"]["card"]["payee_name"], "Chen Mei Ling")

    def test_offer_only_once_and_switch_keeps_star_in_step(self):
        self.c.post("/api/care/offer", json={"session_id": self.sid})
        self.chat("No")
        self.assertIsNone(self.c.post("/api/care/offer", json={"session_id": self.sid}).json()["offer"])
        self.assertTrue(self.c.post("/api/care", json={"session_id": self.sid, "on": True}).json()["care_mode"])

    def test_same_safety_either_way(self):
        self.assertEqual(system_prompt("senior").split("[How to speak]")[0],
                         system_prompt("everyday").split("[How to speak]")[0])
        self.c.post("/api/care", json={"session_id": self.sid, "on": False})
        standard = self.chat("Send 1800 to my daughter")["ui"]["card"]
        sid2 = self.c.post("/api/reset", json={"world": True}).json()["session_id"]
        self.c.post("/api/care", json={"session_id": sid2, "on": True})
        care = self.c.post("/api/chat", json={"session_id": sid2, "text": "Send 1800 to my daughter"}).json()["ui"]["card"]
        self.assertEqual((standard["risk_level"], standard["reasons"]), (care["risk_level"], care["reasons"]))

    def test_answers(self):
        self.assertEqual([care_answer(t) for t in ("yes please", "OK", "No, thanks", "send 50 to my son")],
                         [True, True, False, None])
