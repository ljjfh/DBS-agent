"""会话与状态机。

状态机是外层骨架：决定每个阶段“允许做什么”。模型想跳步（比如没确认就执行）会被这里拒绝并记录。
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from app.models import Draft, Phase, RiskLevel

ALLOWED = {
    Phase.IDLE: {Phase.DRAFTED, Phase.HANDOFF, Phase.BLOCKED},
    Phase.DRAFTED: {Phase.COOLING, Phase.AWAITING_AUTH, Phase.BLOCKED, Phase.CANCELLED},
    Phase.COOLING: {Phase.AWAITING_AUTH, Phase.CANCELLED},
    Phase.AWAITING_AUTH: {Phase.EXECUTED, Phase.CANCELLED},
    Phase.EXECUTED: {Phase.IDLE},
    Phase.CANCELLED: {Phase.IDLE},
    Phase.BLOCKED: {Phase.IDLE},
    Phase.HANDOFF: {Phase.IDLE},
}


class IllegalTransition(Exception):
    pass


@dataclass
class Session:
    session_id: str
    user_id: str = "u_chen"
    lang: str = "zh"
    phase: Phase = Phase.IDLE
    messages: list[dict] = field(default_factory=list)       # 给模型的对话历史
    drafts: dict[str, Draft] = field(default_factory=dict)
    current_draft_id: str | None = None
    scam_level: RiskLevel = RiskLevel.LOW                   # 只升不降，会话内有效
    scam_reasons: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)           # 复合指令拆出来的后续任务
    trace: list[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    # ---------- 状态机 ----------
    def transition(self, to: Phase) -> None:
        if to not in ALLOWED[self.phase]:
            raise IllegalTransition(f"{self.phase.value} -> {to.value} 不被允许")
        self.add_trace("state", f"{self.phase.value} → {to.value}")
        self.phase = to

    def settle(self) -> None:
        """一笔交易结束（执行/取消/拦截/转人工）后回到空闲。"""
        if self.phase in (Phase.EXECUTED, Phase.CANCELLED, Phase.BLOCKED, Phase.HANDOFF):
            self.transition(Phase.IDLE)
            self.current_draft_id = None

    @property
    def current_draft(self) -> Draft | None:
        return self.drafts.get(self.current_draft_id) if self.current_draft_id else None

    def escalate_scam(self, level: RiskLevel, reasons: list[str]) -> None:
        """单向升级：只接受更高的等级。"""
        if level.rank > self.scam_level.rank:
            self.scam_level = level
        for r in reasons:
            if r not in self.scam_reasons:
                self.scam_reasons.append(r)

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
