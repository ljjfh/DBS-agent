"""核心数据结构。金额一律用整数“分”（cents）保存，避免浮点误差。"""
from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


def to_cents(amount: float | str) -> int:
    return int(round(float(amount) * 100))


def fmt_money(cents: int, currency: str = "SGD") -> str:
    return f"S${cents / 100:,.2f}" if currency == "SGD" else f"{currency} {cents / 100:,.2f}"


class RiskLevel(str, Enum):
    LOW = "LOW"          # 一次生物识别
    MEDIUM = "MEDIUM"    # 生物识别 + 一个核验问题
    HIGH = "HIGH"        # 冷静期后再确认（可选家人同意）
    BLOCK = "BLOCK"      # 不允许执行

    @property
    def rank(self) -> int:
        return ["LOW", "MEDIUM", "HIGH", "BLOCK"].index(self.value)

    @staticmethod
    def max(*levels: "RiskLevel") -> "RiskLevel":
        return max(levels, key=lambda l: l.rank)


class Phase(str, Enum):
    """会话状态机的阶段：只能按允许的路径推进。"""
    IDLE = "IDLE"
    DRAFTED = "DRAFTED"            # 草稿已生成并通过规则判级
    COOLING = "COOLING"            # 高风险冷静期
    AWAITING_AUTH = "AWAITING_AUTH"
    EXECUTED = "EXECUTED"
    CANCELLED = "CANCELLED"
    BLOCKED = "BLOCKED"
    HANDOFF = "HANDOFF"            # 转人工


class RiskDecision(BaseModel):
    level: RiskLevel
    reasons: list[str] = Field(default_factory=list)       # 给用户看的白话理由
    rule_hits: list[str] = Field(default_factory=list)     # 给审计看的规则编号
    verify_question: Optional[str] = None
    cooldown_seconds: int = 0


class Draft(BaseModel):
    """交易草稿：Agent 能产生的最“远”的东西。执行只认这份草稿 + 用户签名。"""
    draft_id: str
    user_id: str
    kind: Literal["transfer", "bill"]
    from_account: str
    payee_id: str
    payee_name: str
    amount_cents: int
    currency: str = "SGD"
    note: str = ""
    bill_id: Optional[str] = None
    created_at: float
    expires_at: float
    nonce: str
    digest: str = ""                 # 确认卡内容的哈希，“所见即所签”
    risk: Optional[RiskDecision] = None
    cooling_until: float = 0.0
    taint: list[str] = Field(default_factory=list)  # 来自不可信来源的字段

    def card_fields(self) -> dict:
        """参与哈希的字段：确认卡上展示的每一项都在这里。"""
        return {
            "draft_id": self.draft_id, "user_id": self.user_id, "kind": self.kind,
            "from_account": self.from_account, "payee_id": self.payee_id,
            "payee_name": self.payee_name, "amount_cents": self.amount_cents,
            "currency": self.currency, "bill_id": self.bill_id,
            "nonce": self.nonce, "expires_at": int(self.expires_at),
        }
