"""Agent main loop = constrained ReAct + Harness.

One conversation turn:
  0. Plan: split a compound request ("pay the electricity bill, then send 200 to my daughter") into ordered
     tasks; do the first, queue the rest (Plan-and-Execute)
  1. pre-hook: deterministic scam-phrase scan; if it is high risk and involves moving money, block it
     directly without reaching the model
  2. Constrained ReAct: Thought → Action (tool gateway) → Observation, capped at settings.max_steps.
     In parallel, the independent verifier (agent/verifier.py) reads only the user's words; if the draft disagrees
     with it, the kernel freezes the draft (dual-engine audit)
  3. Output validation: amounts the model mentions must match the draft; it may not claim "already sent"
  4. UI: confirmation card / cooling-off / block / frozen page are generated entirely by code from the draft
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app.agent import fraud, presenter
from app.agent.llm import LLMError, OfflineLLM, detect_intent
from app.agent.prompts import SYSTEM_PROMPT, state_summary
from app.agent.textparse import money_mentions
from app.agent.tools import ToolGateway
from app.bank.mock_bank import MockBank
from app.config import settings
from app.kernel import protection as prot
from app.kernel.audit import AuditLog
from app.kernel.state import Session
from app.models import Phase, RiskLevel, fmt_money

_CLAIMS_DONE = re.compile(r"(has|have|was|were) been (sent|paid|transferred)|successfully (sent|paid|transferred)|"
                          r"\bi(?:'ve| have)? (just )?(sent|paid|transferred)\b|"
                          r"(transfer|payment) (is |was )?(complete|done|successful)", re.I)
_SPLIT = re.compile(r"\b(?:and then|after that|afterwards|then)\b", re.I)
_AND = re.compile(r",?\s+\band\b\s+(?:also\s+)?", re.I)
# The model says it prepared / set up a payment, but no draft was made this turn
_CLAIMS_PREPARED = re.compile(r"\b(i'?ve|i have|i)\s+(just\s+)?(prepared|drafted|set up|created|arranged)\b.{0,40}"
                              r"\b(transfer|payment|investment|card)\b|\bhere'?s your (transfer|payment|investment)\b", re.I)
_MONEY_INTENTS = ("transfer", "bill_pay", "invest")
_NOTE = re.compile(r"\s*\[system note:[^\]]*\]", re.I)
NUDGE = ("[Harness check] No draft exists: you did not call any draft tool in this turn, so nothing has been prepared. "
         "Do not say it is prepared. If you know who/what and how much, call list_payees (or list_investments) and then "
         "the draft tool now. Otherwise ask the user one short question.")
NUDGE_LOOKUP = ("[Harness check] You answered without calling any tool, so you have not checked anything. Never say a "
                "payee, product, bill or account doesn't exist without looking it up. Call the right tool now "
                "(list_payees, list_investments, get_bills, get_balance, get_portfolio, get_cards), then continue.")
_DATA_INTENTS = ("transfer", "bill_pay", "invest", "bill_query", "income", "balance", "spending", "portfolio", "card")


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
    """Split a compound request into ordered tasks, only when every part is a request on its own:
    "pay the bill, then send 200 to my daughter", "send 500 to my son and invest the rest in a fund".
    ("send 50 to my son and daughter" stays one task: "daughter" alone is not a request.)"""
    for rx in (_SPLIT, _AND):
        parts = [p.strip(" ,.") for p in rx.split(text) if p.strip(" ,.")]
        if len(parts) > 1 and all(detect_intent(p) != "unknown" for p in parts):
            return parts
    return [text]


class Agent:
    def __init__(self, bank: MockBank, gateway: ToolGateway, audit: AuditLog, llm, fallback=None):
        self.bank, self.gateway, self.audit, self.llm = bank, gateway, audit, llm
        self.fallback = fallback or OfflineLLM()

    # ------------------------------------------------------------------ One turn
    def run_turn(self, s: Session, text: str) -> TurnResult:
        s.settle()
        start = len(s.trace)
        s.add_trace("user", text)
        self.audit.append("user.utterance", s.session_id, {"text": text})

        # 0. Plan
        parts = split_plan(text)
        if len(parts) > 1:
            s.plan[:] = parts[1:]          # a restated compound request replaces what was queued before
            s.add_trace("plan", "Compound request split into ordered tasks", parts)
            text_now = parts[0]
        else:
            text_now = text

        # 1. pre-hook: deterministic scam scan (standard protection turns HIGH into a warning; BLOCK stops everyone)
        level_p = prot.effective(self.bank, s.user_id)
        raw_level, reasons, cats = fraud.scan(text)
        level = prot.cap_scam(raw_level, level_p)
        if level != RiskLevel.LOW:
            s.escalate_scam(level, reasons)
            s.add_trace("guard", f"Phrase scan hit: {', '.join(cats)} → {level.value}" +
                        (f" (standard protection: shown as a warning, was {raw_level.value})" if level != raw_level else ""))
        # This message itself hits high-risk phrases and involves moving money: block it without reaching the model.
        # If the session was flagged earlier, later requests go to the model, but the tool gateway has already
        # shrunk the tool set (no more drafting transactions).
        if level.rank >= RiskLevel.HIGH.rank and fraud.wants_money_move(text):
            return self._intercept(s, start, text)

        # 1b. A payment is still waiting for the user's fingerprint: never let a new request get lost or be confused
        #     with it. Show the waiting card again and queue the new request for afterwards (deterministic).
        pending = s.current_draft if s.phase in (Phase.AWAITING_AUTH, Phase.COOLING) else None
        if pending and detect_intent(text_now) in _MONEY_INTENTS:
            return self._still_pending(s, start, text_now, pending)

        # 2. Constrained ReAct
        s.messages.append({"role": "user", "content": text_now})
        verifier = self.gateway.verifier
        if verifier and s.phase == Phase.IDLE and self._money_related(s, text_now) and \
                any(t.tier == "draft" for t in self.gateway.available(s)):
            s.verifier_job = verifier.start(s)       # second engine starts now, alongside the ReAct loop
            s.add_trace("verify", f"Independent verifier started in parallel ({verifier.name}); it sees only your words")
        history = s.messages[-settings.max_history_turns * 2:]
        draft_before = s.current_draft_id
        intent = detect_intent(OfflineLLM._effective_text(s.messages))   # includes answers to our own questions
        reply, llm_name, gave_up = self._react(s, self.llm, history, draft_before, intent)
        if gave_up and s.current_draft_id == draft_before and s.phase == Phase.IDLE:
            # The model twice said "prepared" without ever calling a draft tool. Finish this turn with the
            # deterministic planner (same as when the model is down); everything after it is unchanged:
            # draft -> independent verifier -> rules -> card -> the user's own fingerprint.
            s.add_trace("fallback", "Model skipped the tools for a money request, even after being told; "
                                    "the rule-based planner finished this turn")
            reply, llm_name, _ = self._react(s, self.fallback, history, draft_before, intent)
            llm_name = "offline(fallback)"

        # 3. Output validation
        new_draft = s.current_draft if s.current_draft_id and s.current_draft_id != draft_before else None
        reply = self._validate_reply(s, reply, new_draft, text_now)
        # What the model sees next turn: the reply PLUS what really happened. Without this note the history looks like
        # "user asks -> assistant says 'I've prepared it'" (tool calls aren't kept), and the model learns to skip the tools.
        s.messages.append({"role": "assistant", "content": reply + self._what_happened(s, new_draft)})

        # 4. UI
        ui = {"type": "text"}
        speak = reply
        if new_draft:
            card = presenter.build_card(new_draft, self.bank, s.phase)
            ui = {"type": {Phase.BLOCKED: "blocked", Phase.COOLING: "cooldown", Phase.FROZEN: "frozen"}.get(
                s.phase, "confirm"), "card": card}
            if s.phase not in (Phase.BLOCKED, Phase.FROZEN):
                speak = reply + " " + card["readback"]
        elif pending and s.phase in (Phase.AWAITING_AUTH, Phase.COOLING):
            # Whatever the user asked, keep the waiting card in front of them (e.g. after "I'm ready")
            ui = {"type": "cooldown" if s.phase == Phase.COOLING else "confirm",
                  "card": presenter.build_card(pending, self.bank, s.phase), "reopened": True}
        elif s.phase == Phase.HANDOFF:
            ui = {"type": "handoff"}
        else:
            options = self._choices(s, reply)
            if options:   # tap instead of re-speaking: easier for elderly users, and no ASR error on the answer
                ui = {"type": "choose", "options": options}
                request = next((u for u in reversed(s.task_utterances()) if detect_intent(u) in _MONEY_INTENTS), text_now)
                s.pending_choice = {"request": request, "options": [
                    {"payee_id": p["payee_id"], "name": p["name"], "relation": p["relation"]}
                    for p in self.bank.payees(s.user_id) if p["name"] in [o["send"] for o in options]]}
                s.add_trace("ui", "Offered tap-to-choose buttons", [o["label"] for o in options])
        if ui["type"] != "choose":
            s.pending_choice = None
        if len(parts) > 1:
            ui["plan"] = parts          # "I'll do this in N steps; you confirm each one"
        self.audit.append("agent.reply", s.session_id, {"reply": reply, "ui": ui["type"], "llm": llm_name})
        return TurnResult(reply=reply, ui=ui, speak=speak, trace=s.trace[start:], llm=llm_name)

    def _react(self, s: Session, llm, history: list[dict], draft_before, intent: str = "unknown") -> tuple[str, str, bool]:
        """Constrained ReAct: Thought -> Action (tool gateway) -> Observation, capped at settings.max_steps.
        Harness checks on the model's final answer:
          * a money request must use tools: the first step asks the API to force a tool call (tool_choice=required)
          * answered a data question without any tool ("I can't find a grandson")  -> nudge once
          * said a payment is prepared but no draft tool ran                        -> nudge once
        Returns (reply, model name, gave_up): gave_up = a money request where the model still skipped the tools
        (or still claimed without a draft) after the nudge."""
        working: list[dict] = []
        llm_name = getattr(llm, "name", "llm")
        seen_calls: set[str] = set()
        nudged = False
        tools_used = 0
        money = intent in _MONEY_INTENTS and any(t.tier == "draft" for t in self.gateway.available(s))
        for step in range(settings.max_steps):
            # Fixed prefix (system prompt) first, dynamic state after: works with APIs that accept only one system
            # message, and helps prompt caching
            msgs = [{"role": "system", "content": SYSTEM_PROMPT + "\n\n" + state_summary(s, self.bank)},
                    *history, *working]
            kw = {"tool_choice": "required"} if (money and step == 0 and getattr(llm, "supports_tool_choice", False)) else {}
            try:
                msg = llm.chat(msgs, tools=self.gateway.schemas(s), **kw)
            except LLMError as e:      # fallback: if the online model is unavailable, switch to the offline model
                s.add_trace("fallback", f"Model call failed, falling back to offline mode: {str(e)[:80]}")
                llm, llm_name = self.fallback, "offline(fallback)"
                msg = llm.chat(msgs, tools=self.gateway.schemas(s))
            tool_calls = msg.get("tool_calls") or []
            if msg.get("content") and tool_calls:
                s.add_trace("thought", msg["content"])
            if not tool_calls:
                reply = (msg.get("content") or "").strip()
                no_draft = s.current_draft_id == draft_before
                claims = no_draft and bool(_CLAIMS_PREPARED.search(reply)) and \
                    any(t.tier == "draft" for t in self.gateway.available(s))
                skipped = tools_used == 0 and intent in _DATA_INTENTS
                if (claims or skipped) and not nudged:
                    nudged = True
                    why = ("said it prepared a payment without calling a draft tool" if claims
                           else f"answered a '{intent}' request without using any tool")
                    s.add_trace("guard", f"Model {why}; told it so and let it try again", {"model_reply": reply})
                    working += [{"role": "assistant", "content": reply},
                                {"role": "user", "content": NUDGE if claims else NUDGE_LOOKUP}]
                    continue
                # Still claiming, or a money request still answered without a single tool: give up on the model
                gave_up = nudged and no_draft and (claims or (money and tools_used == 0))
                return reply, llm_name, gave_up
            working.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": tool_calls})
            tools_used += len(tool_calls)
            for tc in tool_calls:
                name, args = tc["function"]["name"], tc["function"].get("arguments") or "{}"
                key = name + "|" + (args if isinstance(args, str) else json.dumps(args, sort_keys=True))
                s.add_trace("action", f"{name}({args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)})")
                if key in seen_calls:
                    result = {"ok": False, "error": "This tool was just called with the same arguments. Answer the user from the results you already have."}
                else:
                    seen_calls.add(key)
                    result = self.gateway.call(s, name, args)
                s.add_trace("observation", self._summarize(result), result)
                self.audit.append("tool.call", s.session_id, {"tool": name, "args": args, "ok": result.get("ok"),
                                                              "error": result.get("error")})
                working.append({"role": "tool", "tool_call_id": tc["id"],
                                "content": json.dumps(result, ensure_ascii=False)})
        s.add_trace("guard", f"Exceeded step limit {settings.max_steps}, handing off to a human")
        if s.phase == Phase.IDLE:
            s.transition(Phase.HANDOFF)
        return "I need a colleague to help with this. I'm connecting you to a staff member now.", llm_name, False

    @staticmethod
    def _what_happened(s: Session, d) -> str:
        if not d:
            return ""
        verb = {"transfer": "draft_transfer", "bill": "draft_bill_payment", "investment": "draft_investment"}[d.kind]
        state = {Phase.FROZEN: "frozen by the verifier", Phase.BLOCKED: "blocked by the rules",
                 Phase.COOLING: "in cooling-off"}.get(s.phase, "shown on the confirmation card")
        return (f"\n[system note: {verb} was called and created draft {d.draft_id}: {fmt_money(d.amount_cents)} "
                f"{'in' if d.kind == 'investment' else 'to'} {d.payee_name}, {state}. Nothing is paid until the user signs.]")

    @staticmethod
    def _money_related(s: Session, text: str) -> bool:
        if detect_intent(text) in ("transfer", "bill_pay", "invest") or fraud.wants_money_move(text):
            return True
        prev = next((m for m in reversed(s.messages[:-1]) if m["role"] == "assistant"), None)
        return bool(prev and prev["content"].rstrip().endswith("?"))     # answering "how much?" / "which one?"

    # ------------------------------------------------------------------ Choice buttons
    def _choices(self, s: Session, reply: str) -> list[dict]:
        """If the agent is asking "which one?" and names 2+ saved payees or bills, turn them into buttons.
        Options only ever come from the user's own saved payees / bills, never from the model's text."""
        if not reply or not reply.rstrip().endswith("?"):
            return []
        low = reply.lower()
        people = [p for p in self.bank.payees(s.user_id) if p["type"] == "person" and p["name"].lower() in low]
        if len(people) >= 2:
            return [{"label": f"{p['name']} ({p['relation']})", "detail": p["masked_account"], "send": p["name"]}
                    for p in people]
        bills = [b for b in self.bank.bills(s.user_id) if b["title"].lower() in low]
        if len(bills) >= 2:
            return [{"label": b["title"], "detail": fmt_money(b["amount_cents"]), "send": f"Pay the {b['title']}"}
                    for b in bills]
        return []

    def _still_pending(self, s: Session, start: int, text: str, d) -> TurnResult:
        prep = "in" if d.kind == "investment" else "to"
        if text not in s.plan:
            s.plan.insert(0, text)
        reply = (f"You still have one payment waiting: {fmt_money(d.amount_cents)} {prep} {d.payee_name}. "
                 f"Please confirm it with your fingerprint or cancel it first. Then I'll help with “{text}”.")
        s.messages.extend([{"role": "user", "content": text}, {"role": "assistant", "content": reply}])
        s.add_trace("guard", "A payment is still waiting for the user; showing its card again and queuing the new request",
                    {"pending": d.draft_id, "queued": text})
        self.audit.append("agent.reply", s.session_id, {"reply": reply, "ui": "confirm", "llm": "guard"})
        card = presenter.build_card(d, self.bank, s.phase)
        return TurnResult(reply=reply, ui={"type": "cooldown" if s.phase == Phase.COOLING else "confirm", "card": card,
                                           "reopened": True}, speak=reply, trace=s.trace[start:], llm="guard")

    # ------------------------------------------------------------------ Intercept
    def _intercept(self, s: Session, start: int, text: str) -> TurnResult:
        s.plan.clear()
        if s.phase == Phase.IDLE:
            s.transition(Phase.BLOCKED)
        reasons = s.scam_reasons[:3]
        reply = ("For your safety, I've stopped this one. " + " ".join(reasons) +
                 " If someone asked you to do this, please hang up and call the ScamShield helpline 1799, "
                 "or talk to your family first.")
        s.messages.extend([{"role": "user", "content": text}, {"role": "assistant", "content": reply}])
        s.add_trace("guard", "High-risk phrases + moving money: blocked without reaching the model", {"reasons": reasons})
        self.audit.append("scam.intercepted", s.session_id, {"text": text, "level": s.scam_level.value,
                                                             "reasons": reasons})
        return TurnResult(reply=reply, ui={"type": "blocked", "reasons": reasons, "hotline": "1799"},
                          speak=reply, trace=s.trace[start:], llm="guard")

    # ------------------------------------------------------------------ Validation
    def _validate_reply(self, s: Session, reply: str | None, draft, text: str) -> str:
        reply = _NOTE.sub("", reply or "").strip() or None
        if draft:
            prep = "in" if draft.kind == "investment" else "to"
            template = f"Please check the card: {fmt_money(draft.amount_cents)} {prep} {draft.payee_name}."
            if draft.risk and draft.risk.level == RiskLevel.BLOCK:
                template = "I can't process this: " + " ".join(draft.risk.reasons[:2])
            elif draft.verification.get("status") == "mismatch":
                # Frozen: always the code's wording, never the model's
                s.add_trace("guard", "Draft frozen by the independent verifier; using the code template", {"model_reply": reply})
                return ("I've stopped this before it reached you, because it doesn't match what you said. " +
                        " ".join(draft.verification["mismatches"][:2]) + " Please tell me again what you'd like to do.")
            # Amounts the reply may legitimately mention: the draft amount, plus any amount the rules quoted in their
            # reasons (balance, usual amount, limits). Anything else means the model got the number wrong.
            allowed = [draft.amount_cents] + [round(v * 100) for v in
                                              money_mentions(" ".join(draft.risk.reasons if draft.risk else []))]
            mentioned = money_mentions(reply or "")
            if not reply or any(all(abs(v * 100 - a) > 0.5 for a in allowed) for v in mentioned):
                s.add_trace("guard", "Amount in model reply doesn't match the draft; using the code template", {"model_reply": reply})
                return template
        if not draft and reply and _CLAIMS_PREPARED.search(reply):
            pend = s.current_draft if s.phase in (Phase.AWAITING_AUTH, Phase.COOLING) else None
            s.add_trace("guard", "Model claimed it prepared a payment, but no draft was made this turn; corrected",
                        {"model_reply": reply})
            if pend:
                prep = "in" if pend.kind == "investment" else "to"
                return (f"Your waiting payment is {fmt_money(pend.amount_cents)} {prep} {pend.payee_name}. "
                        "Please check the card and confirm it with your fingerprint, or cancel it.")
            return "I haven't prepared anything yet. Could you tell me again who to pay and how much?"
        # Only on payment turns: "your pension has been paid in" is a fine answer to an income question
        if reply and _CLAIMS_DONE.search(reply) and (draft or detect_intent(text) in ("transfer", "bill_pay", "invest")):
            s.add_trace("guard", "Model claimed the transaction was executed, but the system did not execute it; corrected",
                        {"model_reply": reply})
            return ("Nothing has been sent yet — please check and confirm the card yourself." if draft
                    else "I can't make payments by myself. You need to confirm them yourself.")
        return reply or "Sorry, could you say that again?"

    @staticmethod
    def _summarize(result: dict) -> str:
        if not result.get("ok"):
            return "Error: " + str(result.get("error"))[:80]
        data = result.get("data")
        if isinstance(data, list):
            return f"Returned {len(data)} records"
        if isinstance(data, dict) and "draft_id" in data:
            return f"Draft {data['draft_id']} · risk {data['risk_level']}"
        return str(data)[:80]
