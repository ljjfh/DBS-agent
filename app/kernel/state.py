"""Sessions and the state machine.

The state machine is the outer skeleton: it decides what is allowed in each phase. If the model tries to skip a step
(e.g. execute without confirmation), it is rejected here and logged.
"""
from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from pathlib import Path
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
    plan_references: dict[str, str] = field(default_factory=dict)  # raw child request -> parent draft id
    plan_specs: dict[str, dict] = field(default_factory=dict)      # queued step words -> the model planner's step
    plan_drafts: dict[int, str] = field(default_factory=dict)      # planner step number -> its draft id
    plan_raw: str = ""                                             # the user's original words for the current plan
    plan_pos: int | None = None                                    # planner step being drafted in this turn
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
    pending_change: dict | None = None                       # signed account change waiting for the fingerprint
    amount_hint: tuple | None = None                         # (cents, "half of your Savings Account (S$...)") this turn
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


_VISITOR = re.compile(r"^[a-f0-9]{8,32}$")
_VISITOR_SID = re.compile(r"^([a-f0-9]{8,32})\.[a-f0-9]{6,32}$")


def visitor_of(session_id: str | None) -> str | None:
    """Online demo: a session id "<visitor>.<random>" belongs to that browser's own demo customer."""
    m = _VISITOR_SID.match(session_id or "")
    return m.group(1) if m else None


def valid_visitor(v) -> str | None:
    v = str(v or "").lower()
    return v if _VISITOR.match(v) else None


class UnknownSession(Exception):
    pass


class SessionStore:
    MAX_SESSIONS = 5000

    def __init__(self, path=None):
        self.path = path
        self._bindings = {}
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, uid TEXT NOT NULL)")
                self._bindings.update(db.execute("SELECT sid, uid FROM sessions"))
        self._s: dict[str, Session] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _new(session_id: str) -> Session:
        from app.bank.mock_bank import DEMO_USER
        v = visitor_of(session_id)
        return Session(session_id=session_id, user_id=f"{DEMO_USER}~{v}" if v else DEMO_USER)

    def _trim(self) -> None:
        for old in list(self._s)[:max(0, len(self._s) - self.MAX_SESSIONS)]:
            self._s.pop(old, None)

    def _create(self, sid, uid):
        self._bindings[sid] = uid
        if self.path:
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?)", (sid, uid))
        self._s[sid] = Session(session_id=sid, user_id=uid)
        self._trim()
        return self._s[sid]

    def get(self, session_id: str | None) -> Session:
        with self._lock:
            if session_id is None:
                return self._create(uuid.uuid4().hex, "u_chen")
            if not isinstance(session_id, str) or not session_id:
                raise ValueError("session_id must be a non-empty string")
            if session_id not in self._s:
                if session_id not in self._bindings:
                    raise UnknownSession("Session not found. Please start a new demo session.")
                self._s[session_id] = Session(session_id=session_id, user_id=self._bindings[session_id])
            return self._s[session_id]

    def reset(self, session_id: str) -> Session:
        old = self.get(session_id)
        with self._lock:
            return self._create(uuid.uuid4().hex, old.user_id)

    def new_for_visitor(self, visitor: str) -> Session:
        # A client-chosen visitor label is not an identity or a credential.
        with self._lock:
            return self._create(uuid.uuid4().hex, "u_chen~" + uuid.uuid4().hex)


sessions = SessionStore()
