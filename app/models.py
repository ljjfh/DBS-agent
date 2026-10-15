"""Core data structures. Amounts are always stored as integer cents to avoid floating-point errors."""
from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


def to_cents(amount: float | str) -> int:
    return int(round(float(amount) * 100))


def fmt_money(cents: int, currency: str = "SGD") -> str:
    return f"S${cents / 100:,.2f}" if currency == "SGD" else f"{currency} {cents / 100:,.2f}"


class RiskLevel(str, Enum):
    LOW = "LOW"          # one biometric check
    MEDIUM = "MEDIUM"    # biometric + one verification question
    HIGH = "HIGH"        # cooling-off; large external transactions additionally require bank review
    BLOCK = "BLOCK"      # not allowed to execute

    @property
    def rank(self) -> int:
        return ["LOW", "MEDIUM", "HIGH", "BLOCK"].index(self.value)

    @staticmethod
    def max(*levels: "RiskLevel") -> "RiskLevel":
        return max(levels, key=lambda l: l.rank)


class Phase(str, Enum):
    """Phases of the session state machine: can only advance along allowed paths."""
    IDLE = "IDLE"
    DRAFTED = "DRAFTED"            # draft created and graded by the rules
    COOLING = "COOLING"            # high-risk cooling-off period
    AWAITING_AUTH = "AWAITING_AUTH"
    EXECUTED = "EXECUTED"
    CANCELLED = "CANCELLED"
    BLOCKED = "BLOCKED"
    FROZEN = "FROZEN"              # the independent verifier disagreed with the draft: it can never be signed
    HANDOFF = "HANDOFF"            # handed off to a human


class RiskDecision(BaseModel):
    level: RiskLevel
    reasons: list[str] = Field(default_factory=list)       # plain-language reasons shown to the user
    rule_hits: list[str] = Field(default_factory=list)     # rule codes for the audit log
    verify_question: Optional[str] = None
    cooldown_seconds: int = 0
    blocking: list[str] = Field(default_factory=list)      # the reasons that stop it outright (BLOCK rules only)


class Draft(BaseModel):
    """Transaction draft: the furthest the Agent can go. Execution only accepts this draft + the user's signature."""
    draft_id: str
    user_id: str
    kind: Literal["transfer", "bill", "investment"]
    from_account: str
    payee_id: str                    # for an investment: the product_id of the fund / ETF / bond
    payee_name: str
    amount_cents: int
    currency: str = "SGD"
    note: str = ""
    bill_id: Optional[str] = None
    asset_class: str = "Cash"        # Cash for transfers and bills; e.g. "Unit trust", "ETF" for investments
    created_at: float
    expires_at: float
    nonce: str
    digest: str = ""                 # hash of the confirmation card content: "what you see is what you sign"
    risk: Optional[RiskDecision] = None
    cooling_until: float = 0.0
    taint: list[str] = Field(default_factory=list)  # fields that came from untrusted sources
    grounding: dict = Field(default_factory=dict)  # is payee/amount backed by the user's own words (kernel/evidence.py)
    you_said: str = ""                             # the user's own words this payment is based on (shown + signed)
    verification: dict = Field(default_factory=dict)  # independent verifier's verdict (kernel/crosscheck.py)
    schedule: Optional[dict] = None   # standing instruction: {"frequency", "day", "first_date", "label"}; None = one-off
    dependency_ids: list[str] = Field(default_factory=list)
    you_said_audio: list[str] = Field(default_factory=list)  # SHA-256 of the recordings you_said came from (signed)
    plan_id: str = ""                 # steps of ONE request the user said in one go share this id (signed with the card)
    decision: dict = Field(default_factory=dict)  # server-side evidence, not part of the customer's signed card

    def card_fields(self) -> dict:
        """Fields that go into the hash: every item shown on the confirmation card is here."""
        return {
            "draft_id": self.draft_id, "user_id": self.user_id, "kind": self.kind,
            "from_account": self.from_account, "payee_id": self.payee_id,
            "payee_name": self.payee_name, "amount_cents": self.amount_cents,
            "currency": self.currency, "bill_id": self.bill_id, "asset_class": self.asset_class,
            "you_said": self.you_said, "you_said_audio": self.you_said_audio, "schedule": self.schedule,
            "dependency_ids": self.dependency_ids, "plan_id": self.plan_id,
            "nonce": self.nonce, "expires_at": int(self.expires_at),
        }
