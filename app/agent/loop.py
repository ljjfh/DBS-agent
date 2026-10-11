"""Agent 主循环 = 受限 ReAct + Harness。

一轮对话的流程：
  0. 规划：复合指令（“交完电费再给女儿转 200”）拆成有序任务，先做第一件，其余排队（Plan-and-Execute）
  1. pre-hook：确定性诈骗话术扫描；命中高风险且涉及转钱，直接拦截，不进入模型
  2. 受限 ReAct：Thought → Action（工具网关）→ Observation，步数上限 settings.max_steps
  3. 输出校验：模型说的金额必须与草稿一致；不允许声称“已转好”
  4. 生成界面：确认卡/冷静期/拦截页 完全由程序从草稿生成
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app.agent import fraud, presenter
from app.agent.llm import LLMError, OfflineLLM, detect_intent
from app.agent.prompts import SYSTEM_PROMPT, state_summary
from app.agent.textparse import is_english, money_mentions
from app.agent.tools import ToolGateway
from app.bank.mock_bank import MockBank
from app.config import settings
from app.kernel.audit import AuditLog
from app.kernel.state import Session
from app.models import Phase, RiskLevel, fmt_money

_CLAIMS_DONE = re.compile(r"已(经)?(转|汇|付|缴|交)(好|完|出)|转账成功|缴费成功|has been (sent|paid|transferred)|"
                          r"successfully (sent|paid|transferred)", re.I)
_SPLIT = re.compile(r"(?:然后|之后|接着|再|and then|then)")


@dataclass
class TurnResult:
    reply: str
    ui: dict
    speak: str
    trace: list = field(default_factory=list)
    llm: str = ""

    def to_dict(self) -> dict:
        return {"reply": self.reply, "ui": self.ui, "speak": self.speak, "trace": self.trace, "llm": self.llm}


def split_plan(text: str) -> list[str]:
    parts = [p.strip(" ，,。") for p in _SPLIT.split(text) if p.strip(" ，,。")]
    if len(parts) > 1 and all(detect_intent(p) != "unknown" for p in parts):
        return parts
    return [text]


class Agent:
    def __init__(self, bank: MockBank, gateway: ToolGateway, audit: AuditLog, llm, fallback=None):
        self.bank, self.gateway, self.audit, self.llm = bank, gateway, audit, llm
        self.fallback = fallback or OfflineLLM()

    # ------------------------------------------------------------------ 一轮对话
    def run_turn(self, s: Session, text: str) -> TurnResult:
        s.settle()
        start = len(s.trace)
        s.add_trace("user", text)
        self.audit.append("user.utterance", s.session_id, {"text": text})

        # 0. 规划
        parts = split_plan(text)
        if len(parts) > 1:
            s.plan.extend(parts[1:])
            s.add_trace("plan", "复合指令拆分为有序任务", parts)
            text_now = parts[0]
        else:
            text_now = text

        # 1. pre-hook：确定性诈骗扫描
        level, reasons, cats = fraud.scan(text)
        if level != RiskLevel.LOW:
            s.escalate_scam(level, reasons)
            s.add_trace("guard", f"话术扫描命中：{', '.join(cats)} → {level.value}")
        # 这句话本身命中高风险话术且涉及转钱：不进入模型，直接拦截。
        # 会话之前被标记过的，后续请求交给模型，但工具网关已收缩工具集（不能再起草交易）。
        if level.rank >= RiskLevel.HIGH.rank and fraud.wants_money_move(text):
            return self._intercept(s, start, text)

        # 2. 受限 ReAct
        s.messages.append({"role": "user", "content": text_now})
        history = s.messages[-settings.max_history_turns * 2:]
        working: list[dict] = []
        draft_before = s.current_draft_id
        llm, llm_name = self.llm, getattr(self.llm, "name", "llm")
        seen_calls: set[str] = set()
        reply = None

        for step in range(settings.max_steps):
            # 固定前缀（系统提示）在前、动态状态在后：既兼容只接受一条 system 的接口，也利于提示缓存
            msgs = [{"role": "system", "content": SYSTEM_PROMPT + "\n\n" + state_summary(s, self.bank)},
                    *history, *working]
            try:
                msg = llm.chat(msgs, tools=self.gateway.schemas(s))
            except LLMError as e:          # 降级：线上模型不可用时改用离线模型，服务不中断
                s.add_trace("fallback", f"模型调用失败，降级为离线模式：{str(e)[:80]}")
                llm, llm_name = self.fallback, "offline(fallback)"
                msg = llm.chat(msgs, tools=self.gateway.schemas(s))
            tool_calls = msg.get("tool_calls") or []
            if msg.get("content") and tool_calls:
                s.add_trace("thought", msg["content"])
            if not tool_calls:
                reply = (msg.get("content") or "").strip()
                break
            working.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": tool_calls})
            for tc in tool_calls:
                name, args = tc["function"]["name"], tc["function"].get("arguments") or "{}"
                key = name + "|" + (args if isinstance(args, str) else json.dumps(args, sort_keys=True))
                s.add_trace("action", f"{name}({args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)})")
                if key in seen_calls:
                    result = {"ok": False, "error": "这个工具刚刚已经用同样的参数调用过了，请根据已有结果直接回答用户。"}
                else:
                    seen_calls.add(key)
                    result = self.gateway.call(s, name, args)
                s.add_trace("observation", self._summarize(result), result)
                self.audit.append("tool.call", s.session_id, {"tool": name, "args": args, "ok": result.get("ok"),
                                                              "error": result.get("error")})
                working.append({"role": "tool", "tool_call_id": tc["id"],
                                "content": json.dumps(result, ensure_ascii=False)})
        else:
            s.add_trace("guard", f"超过步数上限 {settings.max_steps}，转人工")
            reply = "这个问题我需要请同事帮忙，正在为您转接人工客服。"
            if s.phase == Phase.IDLE:
                s.transition(Phase.HANDOFF)

        # 3. 输出校验
        new_draft = s.current_draft if s.current_draft_id and s.current_draft_id != draft_before else None
        reply = self._validate_reply(s, reply, new_draft, text_now)
        s.messages.append({"role": "assistant", "content": reply})

        # 4. 界面
        ui = {"type": "text"}
        speak = reply
        if new_draft:
            card = presenter.build_card(new_draft, self.bank, s.phase)
            ui = {"type": {Phase.BLOCKED: "blocked", Phase.COOLING: "cooldown"}.get(s.phase, "confirm"),
                  "card": card}
            if s.phase != Phase.BLOCKED:
                speak = reply + " " + card["readback"]
        elif s.phase == Phase.HANDOFF:
            ui = {"type": "handoff"}
        self.audit.append("agent.reply", s.session_id, {"reply": reply, "ui": ui["type"], "llm": llm_name})
        return TurnResult(reply=reply, ui=ui, speak=speak, trace=s.trace[start:], llm=llm_name)

    # ------------------------------------------------------------------ 拦截
    def _intercept(self, s: Session, start: int, text: str) -> TurnResult:
        s.plan.clear()
        if s.phase == Phase.IDLE:
            s.transition(Phase.BLOCKED)
        reasons = s.scam_reasons[:3]
        en = is_english(text)
        reply = ("This looks like a scam, so I've stopped it. " + " ".join(reasons) +
                 " Please call the ScamShield helpline 1799 or talk to your family first.") if en else \
                ("为了您的安全，这笔我先帮您停下来了。" + "".join(reasons) +
                 "如果有人这样要求您，请先挂断电话，拨打反诈热线 1799，或者先问问家人。")
        s.messages.extend([{"role": "user", "content": text}, {"role": "assistant", "content": reply}])
        s.add_trace("guard", "高风险话术 + 涉及转钱：未进入模型，直接拦截", {"reasons": reasons})
        self.audit.append("scam.intercepted", s.session_id, {"text": text, "level": s.scam_level.value,
                                                             "reasons": reasons})
        return TurnResult(reply=reply, ui={"type": "blocked", "reasons": reasons, "hotline": "1799"},
                          speak=reply, trace=s.trace[start:], llm="guard")

    # ------------------------------------------------------------------ 校验
    def _validate_reply(self, s: Session, reply: str | None, draft, text: str) -> str:
        en = is_english(text)
        if draft:
            template = (f"Please check the card: {fmt_money(draft.amount_cents)} to {draft.payee_name}."
                        if en else f"请核对确认卡：给 {draft.payee_name} {fmt_money(draft.amount_cents)}。")
            if draft.risk and draft.risk.level == RiskLevel.BLOCK:
                template = ("I can't process this: " if en else "这笔不能办理：") + " ".join(draft.risk.reasons[:2])
            mentioned = money_mentions(reply or "")
            if not reply or any(abs(v * 100 - draft.amount_cents) > 0.5 for v in mentioned):
                s.add_trace("guard", "模型复述金额与草稿不一致，改用程序模板", {"model_reply": reply})
                return template
        if reply and _CLAIMS_DONE.search(reply):
            s.add_trace("guard", "模型声称已执行交易，但系统没有执行，已更正", {"model_reply": reply})
            return ("Nothing has been sent yet — please check and confirm the card." if en
                    else "钱还没有转出，需要您在确认卡上亲自确认。") if draft else \
                   ("I can't make payments by myself." if en else "我不能自己转账，需要您亲自确认才行。")
        return reply or ("Sorry, could you say that again?" if en else "不好意思，能再说一遍吗？")

    @staticmethod
    def _summarize(result: dict) -> str:
        if not result.get("ok"):
            return "错误：" + str(result.get("error"))[:80]
        data = result.get("data")
        if isinstance(data, list):
            return f"返回 {len(data)} 条记录"
        if isinstance(data, dict) and "draft_id" in data:
            return f"草稿 {data['draft_id']} · 风险 {data['risk_level']}"
        return str(data)[:80]
