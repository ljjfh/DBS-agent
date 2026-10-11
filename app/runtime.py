"""把各层装配起来（依赖注入的唯一位置）。"""
from app.agent import fraud
from app.agent.llm import OfflineLLM, OpenAICompatLLM, build_llm
from app.agent.loop import Agent
from app.agent.tools import ToolGateway
from app.bank.mock_bank import bank
from app.config import settings
from app.kernel.audit import AuditLog
from app.kernel.executor import Kernel
from app.kernel.state import sessions

audit = AuditLog(settings.audit_path)
kernel = Kernel(bank, audit)
llm = build_llm()

if settings.llm_enabled and settings.llm_judge_model:
    judge_llm = OpenAICompatLLM(settings.llm_base_url, settings.llm_api_key, settings.llm_judge_model,
                                settings.llm_timeout)
elif settings.llm_enabled:
    judge_llm = llm
else:
    judge_llm = OfflineLLM()


def _judge(utterances, summary):
    return fraud.llm_judge(judge_llm, utterances, summary)


gateway = ToolGateway(bank, kernel, judge=_judge)
agent = Agent(bank, gateway, audit, llm)

__all__ = ["audit", "bank", "kernel", "gateway", "agent", "sessions", "llm"]
