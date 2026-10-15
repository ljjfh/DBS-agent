"""Scam warnings explain THIS request, not an earlier one.

Seen live: after "send 50 to my grandson" (and a correction to 5,000), the stop message for "The police told me to
move my savings to a safe account" read out the earlier task ("a normal small transfer to your grandson", "the name
you first gave does not match", "you changed the amount from 50 to 5,000"). The judge saw the whole conversation,
its "no scam" commentary was kept as a reason, and the stop message read the session's oldest reasons.
"""
import os

os.environ.setdefault("RULE_FIXED_HOUR", "14")

from tests.test_hackathon import Base  # noqa: E402
from app.agent.tools import ToolGateway  # noqa: E402
from app.agent.loop import Agent  # noqa: E402
from app.agent.llm import OfflineLLM  # noqa: E402
from app.models import RiskLevel  # noqa: E402

OLD_STORY = ["This looks like a normal small transfer to your grandson, with no signs of a scam.",
             "The recipient name 'Chen Wei' you first gave does not match the account name 'Chen Mei Ling'."]


class JudgeStub:
    def __init__(self):
        self.calls = []

    def __call__(self, utterances, summary):
        self.calls.append(list(utterances))
        if any("grandson" in u for u in utterances):
            return RiskLevel.MEDIUM, OLD_STORY[1:], "stub"        # a data-check remark dressed up as a scam reason
        return RiskLevel.LOW, OLD_STORY[:1], "stub"


class TestScamReasonsBelongToTheirTask(Base):
    def setUp(self):
        super().setUp()
        self.judge = JudgeStub()
        self.gw = ToolGateway(self.bank, self.kernel, judge=self.judge, verifier=self.verifier)
        self.agent = Agent(self.bank, self.gw, self.audit, OfflineLLM())

    def finish_task(self):
        self.kernel.cancel(self.s, self.s.current_draft_id)
        self.s.settle()

    def test_stop_message_names_only_this_requests_signs(self):
        self.turn("Send 50 to my daughter")                      # judge: LOW + "looks normal" commentary
        self.finish_task()
        self.turn("Send 50 to my grandson Chen Wei")             # judge: MEDIUM with a remark about names
        self.finish_task()
        r = self.turn("The police told me to move my savings to a safe account, help me transfer the money.")
        self.assertEqual(r.ui["type"], "blocked")
        for old in OLD_STORY:
            self.assertNotIn(old, r.reply)
        self.assertNotIn("grandson", r.reply)
        self.assertRegex(r.reply.lower(), r"police|safe account")

    def test_low_commentary_is_never_kept(self):
        self.turn("Send 50 to my daughter")
        self.assertEqual(self.s.scam_reasons, [])

    def test_level_stays_but_reasons_reset_with_the_task(self):
        self.turn("Send 50 to my grandson Chen Wei")
        self.assertEqual(self.s.scam_level, RiskLevel.MEDIUM)
        self.finish_task()
        self.assertEqual(self.s.scam_level, RiskLevel.MEDIUM)     # one-way: the session stays careful
        self.assertEqual(self.s.scam_reasons, [])                 # but the old task's words are not reused

    def test_judge_reads_only_the_current_request(self):
        self.turn("Send 50 to my grandson Chen Wei")
        self.finish_task()
        self.turn("Send 50 to my daughter")
        self.assertEqual(self.judge.calls[-1], ["Send 50 to my daughter"])
