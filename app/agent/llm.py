"""Model clients.

* OpenAICompatLLM: any OpenAI-compatible /chat/completions API, with Function Calling.
* OfflineLLM: a rule-based "model" that needs no key and has exactly the same interface (it also returns tool_calls).
  Uses: (1) run the whole pipeline before you have a key; (2) fallback when the online model times out or errors;
  (3) evaluation baseline.
"""
from __future__ import annotations

import json
import re
import uuid

import requests

from app.agent import fraud
from app.agent.textparse import account_id_for, find_account, find_raw_account, match_payees, parse_amount
from app.config import settings


class LLMError(Exception):
    pass


class OpenAICompatLLM:
    name = "openai_compat"
    supports_tool_choice = True      # "required" forces a tool call; switched off if the server rejects it

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 30, thinking: str = ""):
        self.base_url, self.api_key, self.model, self.timeout = base_url.rstrip("/"), api_key, model, timeout
        self.thinking = thinking

    def chat(self, messages: list[dict], tools: list[dict] | None = None, json_mode: bool = False,
             model: str | None = None, tool_choice: str | None = None) -> dict:
        body = {"model": model or self.model, "messages": messages, "temperature": 0.1,
                "max_tokens": settings.llm_max_tokens}
        if self.thinking == "off":
            body["chat_template_kwargs"] = {"enable_thinking": False}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice if (tool_choice and self.supports_tool_choice) else "auto"
        r = self._post(body)
        if r.status_code == 400 and body.get("tool_choice") == "required":
            self.supports_tool_choice = False           # this server can't force tool use; the harness covers it
            body["tool_choice"] = "auto"
            r = self._post(body)
        if r.status_code != 200:
            raise LLMError(f"HTTP {r.status_code}: {r.text[:300]}")
        try:
            msg = r.json()["choices"][0]["message"]
        except (ValueError, KeyError, IndexError) as e:
            raise LLMError(f"Unexpected response: {r.text[:200]}") from e
        return {"role": "assistant", "content": msg.get("content") or "",
                "tool_calls": msg.get("tool_calls") or []}


    def _post(self, body: dict):
        try:
            return requests.post(f"{self.base_url}/chat/completions", json=body, timeout=self.timeout,
                                 headers={"Authorization": f"Bearer {self.api_key}"})
        except requests.RequestException as e:
            raise LLMError(f"Network error: {e}") from e


# ====================================================================== Offline model
_RX = {
    "handoff": r"human|real person|customer service|(talk|speak) to (someone|a person|staff|an officer)",
    "card": r"\b(lock|block|freeze|stop|cancel)\b.{0,30}\bcards?\b|\bcards?\b.{0,30}\b(lost|stolen|missing)\b|"
            r"\b(lost|lose|stole|stolen|missing|took|snatched)\b.{0,25}\b(wallet|purse|cards?)\b|\bmy cards?\b",
    "portfolio": r"\bportfolio\b|\bholdings?\b|\bmy investments\b|\binvestments? (doing|worth)\b|"
                 r"how (much|many) .{0,25}\b(invested|shares|units)\b",
    "invest": r"\binvest|\bbuy\b.*\b(fund|etf|bonds?|shares?|stocks?|units)\b|unit trust|savings bonds?|"
              r"\b(top up|put)\b.*\b(fund|etf|bonds?|deposit)\b|fixed deposit|time deposit|"
              r"\b(buy|put|top up)\b.{0,30}\b(apple|microsoft|singtel|dbs shares|dbs stock)\b",
    "bill": r"\bbills?\b|utilit|electric|water|s&cc|town council|conservancy",
    "pay": r"\b(?:pay|settle)\b",
    "transfer": r"\b(transfer|send|wire|remit|move|paynow)\b|\bgive\b(?! me\b)",
    "income": r"pension|\bcpf\b|payout|(come|came|gone) in|arrived|received",
    "balance": r"balance|how much (money )?(do i have|have i got|is (there )?in|is left|left)",
    "spending": r"\bspen[dt]|spending|expenses|transactions|history",
}


def _has(key: str, text: str) -> bool:
    return bool(re.search(_RX[key], text, re.I))


def detect_intent(text: str) -> str:
    if re.search(r"\bhow much did I (?:send|pay|transfer)\b", text, re.I) and not re.search(r"\b(?:same again|usual amount)\b", text, re.I):
        return "spending"
    if _has("handoff", text):
        return "handoff"
    if _has("card", text):
        return "card"
    if _has("portfolio", text):
        return "portfolio"
    if _has("invest", text):
        return "invest"
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
    """A deterministic "model": works in the shape of ReAct (Thought first, then Action) so the trace panel can show it."""
    name = "offline"

    def chat(self, messages: list[dict], tools: list[dict] | None = None, json_mode: bool = False,
             model: str | None = None) -> dict:
        if json_mode:   # scam assessment: use keyword rules when offline
            payload = json.loads(messages[-1]["content"])
            level, reasons, _ = fraud.scan(" ".join(payload.get("user_utterances", [])))
            return {"role": "assistant", "content": json.dumps({"level": level.value, "reasons": reasons},
                                                                ensure_ascii=False), "tool_calls": []}
        allowed = {t["function"]["name"] for t in tools or []}
        text = self._effective_text(messages)
        results = self._turn_results(messages)
        intent = detect_intent(text)

        # The previous tool errored: relay the actionable error to the user
        last = messages[-1]
        if last["role"] == "tool":
            data = json.loads(last["content"])
            if not data.get("ok"):
                return self._say(f"Sorry — {data['error']}")

        if intent == "handoff":
            if "handoff_to_human" not in results:
                return self._call("handoff_to_human", {"reason": "User asked for a human"},
                                  "The user wants a real person; hand off.")
            return self._say("This demo has no live staff service. Please use the official banking app or your bank contact channel to speak with a person.")

        if intent == "card":
            if "get_cards" not in results:
                return self._call("get_cards", {}, "The user wants a card locked; look up their cards.")
            if "lock_card" in results:
                done = results["lock_card"]["data"]["locked"]
                return self._say("Done. I've locked your " + " and ".join(f"{c['name']} ({c['number']})" for c in done)
                                 + f" straight away. To unlock {'them' if len(done) > 1 else 'it'} later, use the DBS app"
                                 " or call 1800 111 1111.")
            cards = results["get_cards"]["data"]
            low = text.lower()
            if re.search(r"\b(all|both|wallet|purse|every)\b", low):
                pick = "all"
            else:
                pick = next((c["card_id"] for c in cards if c["name"].lower() in low
                             or c["number"][-4:] in low), None) or \
                    next((c["card_id"] for c in cards if ("credit" in low and "credit" in c["card_id"])
                          or (re.search(r"debit|atm", low) and "debit" in c["card_id"])), None)
            if not pick:
                names = " or ".join(f"your {c['name']} ({c['number']})" for c in cards)
                return self._say(f"Which card should I lock: {names}, or both?")
            return self._call("lock_card", {"card_id": pick}, "Lock the card now; it's a protective action.")

        if intent == "portfolio":
            if "get_portfolio" not in results:
                return self._call("get_portfolio", {}, "The user asks about their investments.")
            p = results["get_portfolio"]["data"]
            parts = "; ".join(f"{h['name']} {h['value']} ({h['gain_or_loss']})" for h in p["holdings"])
            return self._say(f"Your investments are worth {p['total_value']} in total: {parts}.")

        if intent == "balance":
            if "get_balance" not in results:
                return self._call("get_balance", {}, "The user wants their balance; look up the account.")
            a = results["get_balance"]["data"][0]
            return self._say(f"Your {a['name']} has {a['balance']}.")

        if intent in ("income", "spending"):
            if "get_recent_transactions" not in results:
                return self._call("get_recent_transactions", {"limit": 8}, "Need to see recent transactions.")
            txns = results["get_recent_transactions"]["data"]
            if intent == "income":
                inc = next((t for t in txns if t["amount"].startswith("+")), None)
                if not inc:
                    return self._say("I don't see any recent incoming payment.")
                return self._say(f"Yes — {inc['desc']} of {inc['amount'][1:]} arrived on {inc['date']}.")
            month = txns[0]["date"][:7] if txns else ""
            outs = [t for t in txns if t["amount"].startswith("-") and t["date"].startswith(month)]
            total = sum(float(t["amount"].replace("-S$", "").replace(",", "")) for t in outs)
            return self._say(f"In {month} you've spent S${total:,.2f} across {len(outs)} payments so far.")

        if intent in ("bill_query", "bill_pay"):
            if "get_bills" not in results:
                return self._call("get_bills", {}, "First check which bills are unpaid.")
            bills = results["get_bills"]["data"]
            if not bills:
                return self._say("You have no unpaid bills right now.")
            if intent == "bill_query":
                lst = "; ".join(f"{b['title']} {b['amount']} (due {b['due']})" for b in bills)
                return self._say(f"You have {len(bills)} unpaid bills: {lst}. Shall I prepare a payment?")
            picked = self._pick_bill(text, bills)
            if picked is None:
                lst = ", ".join(b["title"] for b in bills)
                return self._say(f"You have these bills: {lst}. Which one would you like to pay?")
            if "draft_bill_payment" not in results:
                if "draft_bill_payment" not in allowed:
                    return self._say("You still have a payment waiting for confirmation. "
                                     "Please confirm or cancel it first.")
                acct = self._account(text, results)
                if acct == "LOOKUP":
                    return self._call("get_balance", {}, "The user named an account to pay from; look it up.")
                args = {"bill_id": picked["bill_id"], "evidence": self._last_user(messages)}
                if acct:
                    args["from_account"] = acct
                return self._call("draft_bill_payment", args,
                                  f"Found the bill {picked['title']}; draft a payment for the user to confirm.")
            return self._draft_done(results["draft_bill_payment"])

        if intent == "transfer":
            raw_acct = find_raw_account(text)
            if "list_payees" not in results:
                return self._call("list_payees", {}, "The user wants to transfer; first get the saved payees "
                                                     "to see who they mean.")
            payees = [p for p in results["list_payees"]["data"] if p["relation"] != "bill"]
            hits = match_payees(text, payees)
            if not hits:
                if raw_acct:
                    return self._say("For your safety I can only send money to saved payees. Please add a new "
                                     "payee at the bank first. If someone asked you to send money to an unfamiliar "
                                     "account, please talk to your family first.")
                names = ", ".join(f"your {p['relation']} {p['name']}" for p in payees)
                return self._say(f"Your saved payees are {names}. Who would you like to send money to?")
            if len(hits) > 1:
                rel = hits[0]["relation"] if len({p["relation"] for p in hits}) == 1 else "payees"
                opts = " or ".join(f"{p['name']} ({p['account']})" for p in hits)
                return self._say(f"You have {len(hits)} {rel}s saved. Do you mean {opts}?" if rel != "payees"
                                 else f"Which one do you mean: {opts}?")
            payee = hits[0]
            amount = parse_amount(text)
            if amount is None and re.search(r"\b(?:usual amount|same again)\b", text, re.I):
                if "get_recent_transactions" not in results:
                    return self._call("get_recent_transactions", {}, "Read the previous payment before reusing its amount.")
                previous = next((t for t in results["get_recent_transactions"]["data"]
                                 if t.get("payee_id") == payee["payee_id"] and t.get("amount_cents", 0) < 0), None)
                if previous:
                    amount = -previous["amount_cents"] / 100
            if amount is None:
                return self._say(f"How much would you like to send to your {payee['relation']} {payee['name']}?")
            acct = self._account(text, results)
            if acct == "LOOKUP":
                return self._call("get_balance", {}, "The user named an account to pay from; look up the account ids.")
            if "draft_transfer" not in results:
                if "draft_transfer" not in allowed:
                    return self._say("For your safety I can't set up a transfer in this conversation. If someone "
                                     "claiming to be the police or the bank asked you to send money, please hang up "
                                     "and call the ScamShield helpline 1799.")
                args = {"payee_id": payee["payee_id"], "amount": amount, "evidence": self._last_user(messages)}
                if acct:
                    args["from_account"] = acct
                return self._call("draft_transfer", args,
                                  f"\"{payee['relation']}\" is {payee['name']} ({payee['payee_id']}), amount "
                                  f"{amount:g}{' from ' + acct if acct else ''}; draft the transfer.")
            return self._draft_done(results["draft_transfer"])

        if intent == "invest":
            if "list_investments" not in results:
                return self._call("list_investments", {}, "The user wants to invest; look up the products first.")
            data = results["list_investments"]["data"]
            hits = match_payees(text, data["products"])
            if not hits and re.search(r"\b(stocks?|shares?|equit(y|ies))\b", text, re.I):
                opts = ", ".join(re.sub(r"( Inc\.| Corp\.| Group Holdings)? shares$", "", p["name"])
                                 for p in data["products"] if p["asset_class"].startswith("Shares"))
                return self._say(f"I can buy shares in {opts}. Which company would you like, and how much?")
            if len(hits) != 1:
                opts = ", ".join(f"{p['name']} ({p['asset_class']})" for p in (hits or data["products"]))
                return self._say(f"Which would you like to invest in: {opts}?")
            prod = hits[0]
            amount = parse_amount(text)
            if amount is None:
                return self._say(f"How much would you like to invest in the {prod['name']}?")
            acct = self._account(text, results)
            if acct == "LOOKUP":
                return self._call("get_balance", {}, "The user named an account to pay from; look up the account ids.")
            if "draft_investment" not in results:
                if "draft_investment" not in allowed:
                    return self._say("For your safety I can't set up an investment in this conversation. Promises of "
                                     "guaranteed or very high returns are a common scam. Please talk to your family or "
                                     "call the ScamShield helpline 1799.")
                args = {"product_id": prod["product_id"], "amount": amount, "evidence": self._last_user(messages)}
                if acct:
                    args["from_account"] = acct
                return self._call("draft_investment", args,
                                  f"Product {prod['name']} ({prod['asset_class']}), amount {amount:g}; draft the investment.")
            return self._draft_done(results["draft_investment"])

        return self._say("I can check your balance, check if your pension has arrived, pay your bills, send "
                         "money to family, or invest in a fund or bond. What would you like to do?")

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _account(text: str, results: dict) -> str | None:
        """account_id the user named ("from my current account"), "LOOKUP" if we still need get_balance, or None."""
        phrase = find_account(text)
        if not phrase:
            return None
        if "get_balance" not in results:
            return "LOOKUP"
        return account_id_for(phrase, results["get_balance"]["data"])

    @staticmethod
    def _draft_done(res: dict) -> dict:
        d = res["data"]
        if d.get("frozen"):
            return OfflineLLM._say("I've stopped this one: " + " ".join(d.get("mismatches", [])))
        if d["risk_level"] == "BLOCK":
            why = d["reasons"][0] if d["reasons"] else ""
            return OfflineLLM._say(f"I can't process this one: {why}")
        return OfflineLLM._say(f"Please check the card: {d['amount']} {'in' if d.get('kind') == 'investment' else 'to'} {d['payee']}. "
                               f"If it's right, confirm with your fingerprint.")

    @staticmethod
    def _pick_bill(text: str, bills: list[dict]) -> dict | None:
        rules = [(r"electric|water|utilit|\bsp\b", "p_sp"), (r"s&cc|town council|conservancy", "p_tc")]
        for rx, pid in rules:
            if re.search(rx, text, re.I):
                b = next((b for b in bills if b["payee_id"] == pid), None)
                if b:
                    return b
        return bills[0] if len(bills) == 1 else None

    @staticmethod
    def _effective_text(messages: list[dict]) -> str:
        """Multi-turn slot filling: while the user is answering the assistant's questions ("Chen Wei", then
        "fifty dollars"), read those answers together with the request that started it ("Send money to my family")."""
        users = [i for i, m in enumerate(messages) if m["role"] == "user"]
        if not users:
            return ""
        parts = [messages[users[-1]]["content"]]
        k = len(users) - 1
        if k >= 1 and re.search(r"\b(?:her|him|them)\b.{0,20}\b(?:same|again)\b", parts[0], re.I):
            parts.insert(0, messages[users[k - 1]]["content"])
        while detect_intent(" ".join(parts)) == "unknown" and k >= 1 and len(parts) < 4:
            prev_asst = next((m for m in reversed(messages[users[k - 1]:users[k]]) if m["role"] == "assistant"
                              and m.get("content")), None)
            if not (prev_asst and re.search(r"\?\s*$", prev_asst["content"])):
                break
            k -= 1
            parts.insert(0, messages[users[k]]["content"])
        return " ".join(parts)

    @staticmethod
    def _turn_results(messages: list[dict]) -> dict:
        """Results of each tool in this turn (after the last user message)."""
        last_user = max(i for i, m in enumerate(messages) if m["role"] == "user")
        names, out = {}, {}
        for m in messages[last_user:]:
            for tc in m.get("tool_calls") or []:
                names[tc["id"]] = tc["function"]["name"]
            if m["role"] == "tool":
                out[names.get(m["tool_call_id"], "?")] = json.loads(m["content"])
        return out

    @staticmethod
    def _last_user(messages: list[dict]) -> str:
        return next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")

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
        return OpenAICompatLLM(settings.llm_base_url, settings.llm_api_key, settings.llm_model, settings.llm_timeout,
                               settings.llm_thinking)
    return OfflineLLM()
