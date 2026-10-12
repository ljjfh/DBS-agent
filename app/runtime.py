"""Wire the layers together (the only place dependencies are injected)."""
from app.agent import fraud
from app.agent.llm import OfflineLLM, OpenAICompatLLM, build_llm
from app.agent.loop import Agent
from app.agent.tools import ToolGateway
from app.agent.verifier import Verifier
from app.bank.gateway import ExecutionGateway
from app.bank.mock_bank import bank
from app.config import settings
from app.kernel.audit import AuditLog
from app.kernel.credentials import CredentialRegistry
from app.kernel.executor import Kernel
from app.kernel.state import sessions

audit = AuditLog(settings.audit_path)
registry = CredentialRegistry(settings.passkey_path)
execution_gateway = ExecutionGateway(bank, registry, audit, allow_unsigned=settings.auth_mode == "mock")
kernel = Kernel(bank, audit, registry=registry, gateway=execution_gateway)
llm = build_llm()


def _second_model(name: str):
    return OpenAICompatLLM(settings.llm_base_url, settings.llm_api_key, name, settings.llm_timeout,
                           settings.llm_thinking)


if settings.llm_enabled:
    judge_llm = _second_model(settings.llm_judge_model) if settings.llm_judge_model else llm
    verifier_llm = _second_model(settings.llm_verifier_model) if settings.llm_verifier_model else judge_llm
else:
    judge_llm = verifier_llm = OfflineLLM()


def _judge(utterances, summary):
    return fraud.llm_judge(judge_llm, utterances, summary)


verifier = Verifier(verifier_llm, bank)
gateway = ToolGateway(bank, kernel, judge=_judge, verifier=verifier)
agent = Agent(bank, gateway, audit, llm)

__all__ = ["audit", "bank", "kernel", "gateway", "agent", "sessions", "llm", "registry", "verifier"]
