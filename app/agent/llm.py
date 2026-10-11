"""模型客户端。

* OpenAICompatLLM：任何 OpenAI 兼容的 /chat/completions 接口（默认腾讯混元），支持 Function Calling。
* OfflineLLM：不需要 key 的规则“模型”，接口与真实模型完全相同（同样返回 tool_calls）。
  用途：① 没有 key 时先把整条链路跑通；② 线上模型超时/出错时的降级；③ 评测基线。
"""
from __future__ import annotations

import json
import re
import uuid

import requests

from app.agent import fraud
from app.agent.textparse import find_raw_account, is_english, match_payees, parse_amount
from app.config import settings


class LLMError(Exception):
    pass


class OpenAICompatLLM:
    name = "openai_compat"

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 30):
        self.base_url, self.api_key, self.model, self.timeout = base_url.rstrip("/"), api_key, model, timeout

    def chat(self, messages: list[dict], tools: list[dict] | None = None, json_mode: bool = False,
             model: str | None = None) -> dict:
        body = {"model": model or self.model, "messages": messages, "temperature": 0.1}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        try:
            r = requests.post(f"{self.base_url}/chat/completions", json=body, timeout=self.timeout,
                              headers={"Authorization": f"Bearer {self.api_key}"})
        except requests.RequestException as e:
            raise LLMError(f"网络错误：{e}") from e
        if r.status_code != 200:
            raise LLMError(f"HTTP {r.status_code}: {r.text[:300]}")
        msg = r.json()["choices"][0]["message"]
        return {"role": "assistant", "content": msg.get("content") or "",
                "tool_calls": msg.get("tool_calls") or []}


# ====================================================================== 离线模型
_RX = {
    "handoff": r"真人|人工|客服|human|real person|customer service",
    "bill": r"账单|水电|电费|水费|杂费|s&cc|bill|utilit",
    "pay": r"交|缴|付|pay",
    "transfer": r"转|汇|打钱|给.{0,6}钱|transfer|send",
    "income": r"养老金|退休金|到账|入账|cpf|pension|payout",
    "balance": r"余额|还有多少钱|有多少钱|balance|how much (money )?(do i have|left|is in)",
    "spending": r"花了|开销|支出|流水|记录|spent|spending|transactions|history",
}


def _has(key: str, text: str) -> bool:
    return bool(re.search(_RX[key], text, re.I))


def detect_intent(text: str) -> str:
    if _has("handoff", text):
        return "handoff"
    if _has("bill", text) and _has("pay", text):
        return "bill_pay"
    if _has("transfer", text):
        return "transfer"
    if _has("bill", text):
        return "bill_query"
    if _has("income", text):
        return "income"
    if _has("balance", text):
        return "balance"
    if _has("spending", text):
        return "spending"
    return "unknown"


class OfflineLLM:
    """确定性的“模型”：按 ReAct 的形状工作（先给 Thought，再给 Action），方便轨迹面板展示。"""
    name = "offline"

    def chat(self, messages: list[dict], tools: list[dict] | None = None, json_mode: bool = False,
             model: str | None = None) -> dict:
        if json_mode:   # 诈骗研判：离线时用关键词规则代替
            payload = json.loads(messages[-1]["content"])
            level, reasons, _ = fraud.scan(" ".join(payload.get("user_utterances", [])))
            return {"role": "assistant", "content": json.dumps({"level": level.value, "reasons": reasons},
                                                                ensure_ascii=False), "tool_calls": []}
        allowed = {t["function"]["name"] for t in tools or []}
        text, en = self._effective_text(messages), False
        en = is_english(text)
        results = self._turn_results(messages)
        intent = detect_intent(text)
        T = (lambda zh, eng: eng if en else zh)

        # 上一个工具报错：把可行动的错误转述给用户
        last = messages[-1]
        if last["role"] == "tool":
            data = json.loads(last["content"])
            if not data.get("ok"):
                return self._say(T(f"抱歉，{data['error']}", f"Sorry — {data['error']}"))

        if intent == "handoff":
            if "handoff_to_human" not in results:
                return self._call("handoff_to_human", {"reason": "用户要求人工服务"}, "用户想找真人，转人工。")
            return self._say(T("好的，正在为您转接客服人员，请稍等，不用重复说明情况。",
                               "Sure, connecting you to a staff member now. You won't need to repeat yourself."))

        if intent == "balance":
            if "get_balance" not in results:
                return self._call("get_balance", {}, "用户想知道余额，查询账户。")
            a = results["get_balance"]["data"][0]
            return self._say(T(f"您的{a['name']}现在有 {a['balance']}。", f"Your {a['name']} has {a['balance']}."))

        if intent in ("income", "spending"):
            if "get_recent_transactions" not in results:
                return self._call("get_recent_transactions", {"limit": 8}, "需要看最近的收支记录。")
            txns = results["get_recent_transactions"]["data"]
            if intent == "income":
                inc = next((t for t in txns if t["amount"].startswith("+")), None)
                if not inc:
                    return self._say(T("最近没有看到入账记录。", "I don't see any recent incoming payment."))
                return self._say(T(f"到了，{inc['date']} 收到 {inc['desc']}，金额 {inc['amount'][1:]}。",
                                   f"Yes — {inc['desc']} of {inc['amount'][1:]} arrived on {inc['date']}."))
            month = txns[0]["date"][:7] if txns else ""
            outs = [t for t in txns if t["amount"].startswith("-") and t["date"].startswith(month)]
            total = sum(float(t["amount"].replace("-S$", "").replace(",", "")) for t in outs)
            return self._say(T(f"{month} 这个月目前支出 {len(outs)} 笔，一共 S${total:,.2f}。",
                               f"In {month} you've spent S${total:,.2f} across {len(outs)} payments so far."))

        if intent in ("bill_query", "bill_pay"):
            if "get_bills" not in results:
                return self._call("get_bills", {}, "先看看有哪些待缴账单。")
            bills = results["get_bills"]["data"]
            if not bills:
                return self._say(T("目前没有待缴的账单。", "You have no unpaid bills right now."))
            if intent == "bill_query":
                lst = "；".join(f"{b['title']} {b['amount']}（{b['due']} 前）" for b in bills)
                return self._say(T(f"有 {len(bills)} 张待缴账单：{lst}。要帮您交吗？",
                                   f"You have {len(bills)} unpaid bills: {lst}. Shall I prepare a payment?"))
            picked = self._pick_bill(text, bills)
            if picked is None:
                lst = "、".join(b["title"] for b in bills)
                return self._say(T(f"有 {len(bills)} 张待缴账单：{lst}。您想交哪一张？",
                                   f"You have these bills: {lst}. Which one would you like to pay?"))
            if "draft_bill_payment" not in results:
                if "draft_bill_payment" not in allowed:
                    return self._say(T("您还有一笔交易在等待确认，请先确认或取消。",
                                       "You still have a payment waiting for confirmation."))
                return self._call("draft_bill_payment", {"bill_id": picked["bill_id"]},
                                  f"找到账单 {picked['title']}，起草缴费单，交给用户确认。")
            return self._draft_done(results["draft_bill_payment"], T)

        if intent == "transfer":
            raw_acct = find_raw_account(text)
            if "list_payees" not in results:
                return self._call("list_payees", {}, "用户想转账，先查收款人名单，确认称呼对应哪一位。")
            payees = [p for p in results["list_payees"]["data"] if p["relation"] != "账单"]
            hits = match_payees(text, payees)
            if not hits:
                if raw_acct:
                    return self._say(T("为了安全，我只能转给您已经保存的收款人。新的收款人需要先在银行添加，"
                                       "如果是有人让您转到陌生账号，请先跟家人商量。",
                                       "For your safety I can only send money to saved payees. "
                                       "Please add a new payee at the bank first."))
                names = "、".join(f"{p['relation']}{p['name']}" for p in payees)
                return self._say(T(f"已保存的收款人有：{names}。您要转给谁？",
                                   f"Your saved payees are {', '.join(p['name'] for p in payees)}. "
                                   f"Who would you like to send money to?"))
            if len(hits) > 1:
                return self._say(T("您说的是哪一位？" + "、".join(p["name"] for p in hits) + "？",
                                   "Which one do you mean: " + ", ".join(p["name"] for p in hits) + "?"))
            payee = hits[0]
            amount = parse_amount(text)
            if amount is None:
                return self._say(T(f"要给{payee['relation']}{payee['name']}转多少钱？",
                                   f"How much would you like to send to {payee['name']}?"))
            if "draft_transfer" not in results:
                if "draft_transfer" not in allowed:
                    return self._say(T("为了您的安全，这次对话里暂时不能新建转账。如果有人自称警察或银行要您转钱，"
                                       "请先挂断，拨打反诈热线 1799。",
                                       "For your safety I can't set up a transfer in this conversation. "
                                       "If someone asked you to send money, please call the ScamShield helpline 1799."))
                return self._call("draft_transfer", {"payee_id": payee["payee_id"], "amount": amount},
                                  f"“{payee['relation']}”对应 {payee['name']}（{payee['payee_id']}），金额 {amount:g}，起草转账。")
            return self._draft_done(results["draft_transfer"], T)

        return self._say(T("我可以帮您：查余额、查养老金到账、交水电费、给家人转账。您想做哪一样？",
                           "I can check your balance, pay bills, or send money to family. What would you like to do?"))

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _draft_done(res: dict, T) -> dict:
        d = res["data"]
        if d["risk_level"] == "BLOCK":
            why = d["reasons"][0] if d["reasons"] else ""
            return OfflineLLM._say(T(f"这笔不能办理：{why}", f"I can't process this one: {why}"))
        return OfflineLLM._say(T(f"好的，请看确认卡：给 {d['payee']} {d['amount']}。核对没错的话，按指纹确认。",
                                 f"Please check the card: {d['amount']} to {d['payee']}. Confirm with your fingerprint if it's right."))

    @staticmethod
    def _pick_bill(text: str, bills: list[dict]) -> dict | None:
        rules = [(r"电|水|sp|utilit", "p_sp"), (r"杂费|s&cc|town|理事会", "p_tc")]
        for rx, pid in rules:
            if re.search(rx, text, re.I):
                b = next((b for b in bills if b["payee_id"] == pid), None)
                if b:
                    return b
        return bills[0] if len(bills) == 1 else None

    @staticmethod
    def _effective_text(messages: list[dict]) -> str:
        """多轮补槽：如果当前这句没有意图（比如只说了“两百”），而上一轮助手在提问，就和上一句合并理解。"""
        users = [i for i, m in enumerate(messages) if m["role"] == "user"]
        if not users:
            return ""
        cur = messages[users[-1]]["content"]
        if detect_intent(cur) == "unknown" and len(users) >= 2:
            prev_asst = next((m for m in reversed(messages[:users[-1]]) if m["role"] == "assistant"
                              and m.get("content")), None)
            if prev_asst and re.search(r"[？?]\s*$", prev_asst["content"]):
                return messages[users[-2]]["content"] + " " + cur
        return cur

    @staticmethod
    def _turn_results(messages: list[dict]) -> dict:
        """本轮（最后一条用户消息之后）各工具的返回结果。"""
        last_user = max(i for i, m in enumerate(messages) if m["role"] == "user")
        names, out = {}, {}
        for m in messages[last_user:]:
            for tc in m.get("tool_calls") or []:
                names[tc["id"]] = tc["function"]["name"]
            if m["role"] == "tool":
                out[names.get(m["tool_call_id"], "?")] = json.loads(m["content"])
        return out

    @staticmethod
    def _call(name: str, args: dict, thought: str) -> dict:
        return {"role": "assistant", "content": thought, "tool_calls": [{
            "id": "call_" + uuid.uuid4().hex[:8], "type": "function",
            "function": {"name": name, "arguments": json.dumps(args, ensure_ascii=False)}}]}

    @staticmethod
    def _say(text: str) -> dict:
        return {"role": "assistant", "content": text, "tool_calls": []}


def build_llm():
    if settings.llm_enabled:
        return OpenAICompatLLM(settings.llm_base_url, settings.llm_api_key, settings.llm_model, settings.llm_timeout)
    return OfflineLLM()
