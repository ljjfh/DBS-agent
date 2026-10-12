"""Sessions and the state machine.

The state machine is the outer skeleton: it decides what is allowed in each phase. If the model tries to skip a step
(e.g. execute without confirmation), it is rejected here and logged.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from app.models import Draft, Phase, RiskLevel

ALLOWED = {
    Phase.IDLE: {Phase.DRAFTED, Phase.HANDOFF, Phase.BLOCKED},
    Phase.DRAFTED: {Phase.COOLING, Phase.AWAITING_AUTH, Phase.BLOCKED, Phase.FROZEN, Phase.CANCELLED},
    Phase.COOLING: {Phase.AWAITING_AUTH, Phase.CANCELLED},
    Phase.AWAITING_AUTH: {Phase.EXECUTED, Phase.CANCELLED},
    Phase.EXECUTED: {Phase.IDLE},
    Phase.CANCELLED: {Phase.IDLE},
    Phase.BLOCKED: {Phase.IDLE},
    Phase.FROZEN: {Phase.CANCELLED, Phase.IDLE},
    Phase.HANDOFF: {Phase.IDLE},
}


class IllegalTransition(Exception):
    pass


@dataclass
class Session:
    session_id: str
    user_id: str = "u_chen"
    lang: str = "en"
    phase: Phase = Phase.IDLE
    messages: list[dict] = field(default_factory=list)       # conversation history for the model
    drafts: dict[str, Draft] = field(default_factory=dict)
    current_draft_id: str | None = None
    scam_level: RiskLevel = RiskLevel.LOW                   # only goes up, valid for the session
    scam_reasons: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)           # follow-up tasks split out of a compound request
    trace: list[dict] = field(default_factory=list)
    public_key: dict | None = None                          # the user's device signing key (JWK, public half only)
    challenges: dict[str, str] = field(default_factory=dict) # draft_id -> exact payload bytes the device must sign
    signatures: dict[str, dict] = field(default_factory=dict) # draft_id -> verified signature (goes on the receipt)
    receipts: list[dict] = field(default_factory=list)       # verifiable receipts of payments made in this session
    task_start: int = 0                                      # index in messages where the current task began
    verifier_job: object = None                              # independent verifier running in parallel (agent/verifier.py)
    setting_challenges: dict[str, str] = field(default_factory=dict)  # signed settings changes (protection level)
    passkey_reg: dict | None = None                          # pending passkey registration challenge
    pending_choice: dict | None = None                       # "which one?" we just asked: request + candidate payees
    created_at: float = field(default_factory=time.time)

    # ---------- State machine ----------
    def transition(self, to: Phase) -> None:
        if to not in ALLOWED[self.phase]:
            raise IllegalTransition(f"{self.phase.value} -> {to.value} is not allowed")
        self.add_trace("state", f"{self.phase.value} → {to.value}")
        self.phase = to

    def settle(self) -> None:
        """Return to idle once a transaction ends (executed / cancelled / blocked / handed off)."""
        if self.phase in (Phase.EXECUTED, Phase.CANCELLED, Phase.BLOCKED, Phase.FROZEN, Phase.HANDOFF):
            self.transition(Phase.IDLE)
            self.current_draft_id = None
            self.task_start = len(self.messages)
            self.verifier_job = None

    @property
    def current_draft(self) -> Draft | None:
        return self.drafts.get(self.current_draft_id) if self.current_draft_id else None

    def escalate_scam(self, level: RiskLevel, reasons: list[str]) -> None:
        """One-way escalation: only accepts a higher level."""
        if level.rank > self.scam_level.rank:
            self.scam_level = level
        for r in reasons:
            if r not in self.scam_reasons:
                self.scam_reasons.append(r)

    def task_utterances(self) -> list[str]:
        """What the user said for the current task only (since the last payment finished): the verifier's transcript."""
        return [m["content"] for m in self.messages[self.task_start:] if m.get("role") == "user"]

    def add_trace(self, kind: str, label: str, detail=None) -> dict:
        item = {"t": round(time.time(), 3), "kind": kind, "label": label}
        if detail is not None:
            item["detail"] = detail
        self.trace.append(item)
        return item


class SessionStore:
    def __init__(self):
        self._s: dict[str, Session] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str | None) -> Session:
        with self._lock:
            if not session_id or session_id not in self._s:
                session_id = session_id or uuid.uuid4().hex[:12]
                self._s[session_id] = Session(session_id=session_id)
            return self._s[session_id]

    def reset(self, session_id: str) -> Session:
        with self._lock:
            self._s[session_id] = Session(session_id=session_id)
            return self._s[session_id]


sessions = SessionStore()
