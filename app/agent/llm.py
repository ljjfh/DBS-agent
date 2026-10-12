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
from app.agent.textparse import (account_id_for, find_account, find_raw_account, frequency_in, match_payees,
                                 parse_amount, repeat_day_in)
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
    "bill": r"\bbills?\b|utilit|electric|water|s&cc|town council|conservancy|credit card|card statement",
    "pay": r"\bpay",
    "transfer": r"\b(transfer|send|wire)\b|\bgive\b(?! me\b)|\bmove\b.{0,40}\b(to|into)\b",
    # DBS Limits / Payees / GIRO / Standing Instructions APIs
    "limits": r"\blimits?\b",
    "add_payee": r"\b(add|register|save|new)\b.{0,25}\bpayees?\b|\badd\b.{0,60}\b(account (number|no)|as a payee)",
    "giro_setup": r"\b(set ?up|start|apply( for)?|arrange|use|pay (it |them )?by)\b.{0,30}\bgiro\b",
    "regular": r"\bgiro\b|standing (instruction|order)s?|regular (payment|transfer)s?|recurring|"
               r"automatic (payment|deduction)s?|direct debit|subscriptions?|\b(monthly|weekly) (transfer|allowance|payment)",
    "stop": r"\b(stop|cancel|end|terminate|remove)\b",
    "income": r"pension|\bcpf\b|payout|(come|came|gone) in|arrived|received",
    "balance": r"balance|how much (money )?(do i have|have i got|is (there )?in|is left|left)|"
               r"\b(what|which|my) (bank )?accounts\b",
    "spending": r"\bspen[dt]|spending|expenses|transactions|history",
}


def _has(key: str, text: str) -> bool:
    return bool(re.search(_RX[key], text, re.I))


def detect_intent(text: str) -> str:
    if _has("handoff", text):
        return "handoff"
    if _has("card", text):
        return "card"
    if _has("limits", text):
        return "limits"
    if _has("add_payee", text):
        return "add_payee"
    if _has("giro_setup", text):
        return "giro_setup"
    if _has("regular", text) and _has("stop", text):
        return "regular_cancel"
    if _has("regular", text) and not (_has("transfer", text) and parse_amount(text)):
        return "regular"
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
            return self._say("Sure, connecting you to a staff member now. You won't need to repeat yourself.")

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

        if intent == "limits":
            amt = parse_amount(text)
            if amt and re.search(r"\b(lower|reduce|decrease|cut|drop|set|change|raise|increase|higher|up|make)\b", text, re.I):
                if "set_daily_limit" not in results:
                    if "set_daily_limit" not in allowed:
                        return self._say("I can't change limits right now. Please finish what's on the card first.")
                    return self._call("set_daily_limit", {"amount": amt, "evidence": self._last_user(messages)},
                                      "The user wants a different daily transfer limit; lowering is instant, raising "
                                      "needs their signature.")
                if "change_id" in results["set_daily_limit"]["data"]:
                    return self._say(f"A higher limit needs your fingerprint, and for your safety it only starts after "
                                     f"a waiting time. Please check the card.")
                return self._say(f"Done. Your daily transfer limit is now S${amt:,.0f}, starting right away.")
            if "get_limits" not in results:
                return self._call("get_limits", {}, "The user asks about their transfer limit.")
            d = results["get_limits"]["data"]
            return self._say(f"Your daily limit for transfers to other people is {d['daily_transfer_limit']}. "
                             f"You've used {d['used_today']} today, so {d['left_today']} is left.")

        if intent in ("regular", "regular_cancel"):
            if "list_standing_instructions" not in results:
                return self._call("list_standing_instructions", {}, "Look up the user's regular transfers.")
            if "list_giro" not in results:
                return self._call("list_giro", {}, "And their GIRO arrangements.")
            sis, giros = results["list_standing_instructions"]["data"], results["list_giro"]["data"]
            low = text.lower()
            if intent == "regular":
                parts = [f"{x['amount']} to your {x['relation']} {x['to']} {x['when']}" for x in sis]
                parts += [f"GIRO for {g['biller']}" for g in giros]
                if not parts:
                    return self._say("You have no regular payments set up.")
                return self._say("Your regular payments are: " + "; ".join(parts) + ". Would you like to change any?")
            for done in ("cancel_giro", "cancel_standing_instruction"):
                if done in results:
                    what = results[done]["data"]["cancelled"]
                    what = f"the {what[0].lower()}{what[1:]}" if done == "cancel_standing_instruction" else f"the GIRO for {what}"
                    return self._say(f"Done. I've stopped {what}. You can set it up again any time.")
            g_hits = [g for g in giros if any(re.search(rf"(?<![a-z]){re.escape(a)}(?![a-z])", low)
                                              for a in [g["biller"].lower(), *g.get("aliases", [])])]
            s_hits = [x for x in sis if x["relation"] and re.search(rf"\b{re.escape(x['relation'])}\b", low)
                      or x["to"].lower() in low]
            if len(g_hits) == 1 and ("giro" in low or not s_hits):
                return self._call("cancel_giro", {"giro_id": g_hits[0]["giro_id"]}, "Cancel the GIRO the user named.")
            if len(s_hits) == 1:
                return self._call("cancel_standing_instruction", {"si_id": s_hits[0]["si_id"]},
                                  "Stop the regular transfer the user named.")
            opts = [f"the {x['amount']} {x['when']} to {x['to']}" for x in sis] + [f"GIRO for {g['biller']}" for g in giros]
            return self._say("Which one should I stop: " + ", or ".join(opts) + "?")

        if intent == "add_payee":
            if "request_add_payee" in results:
                return self._say("Please check the card and every digit of the account number. If it's right, "
                                 "confirm with your fingerprint.")
            raw = " ".join(m["content"] for m in messages if m["role"] == "user")[-400:]
            num = find_raw_account(text)
            bank_m = re.search(r"\b(DBS|POSB|OCBC|UOB|Maybank|Citibank|HSBC|Standard Chartered|Trust|GXS)\b", raw, re.I)
            name_m = re.search(r"\bpayee[:,]?\s+(?:called |named )?([A-Z][a-zA-Z'-]+(?:\s+[A-Z][a-zA-Z'-]+){0,3})", raw) or \
                re.search(r"\badd\s+(?:my \w+\s+)?([A-Z][a-zA-Z'-]+(?:\s+[A-Z][a-zA-Z'-]+){0,3})", raw)
            name = name_m.group(1) if name_m else ""
            name = re.sub(r"\s+(DBS|POSB|OCBC|UOB|Maybank|Citibank|HSBC)$", "", name)
            if not (num and name and bank_m):
                return self._say("To add a new payee I need their name, their bank and their account number. "
                                 "What are they?")
            if "request_add_payee" not in allowed:
                return self._say("For your safety I can't add a payee in this conversation.")
            rel = re.search(r"\bmy (friend|neighbou?r|niece|nephew|cousin|sister|brother|helper|doctor)\b", raw, re.I)
            return self._call("request_add_payee", {"name": name, "bank": bank_m.group(1).upper() if len(bank_m.group(1)) <= 5
                                                    else bank_m.group(1), "account_number": num,
                                                    "relation": rel.group(1).lower() if rel else "",
                                                    "evidence": self._last_user(messages)},
                              "Ask to add the payee the user described; they must sign it.")

        if intent == "giro_setup":
            if "request_giro_setup" in results:
                return self._say("Please check the card. If it's right, confirm with your fingerprint.")
            if "list_payees" not in results:
                return self._call("list_payees", {}, "Find the billing organisation the user means.")
            billers = [p for p in results["list_payees"]["data"] if p.get("type") == "biller"]
            hits = match_payees(text, billers)
            if len(hits) != 1:
                return self._say("Which bill should be paid by GIRO: " + ", ".join(p["name"] for p in billers) + "?")
            if "request_giro_setup" not in allowed:
                return self._say("For your safety I can't set up GIRO in this conversation.")
            args = {"biller_payee_id": hits[0]["payee_id"], "evidence": self._last_user(messages)}
            if parse_amount(text):
                args["max_amount"] = parse_amount(text)
            return self._call("request_giro_setup", args, "Ask to set up GIRO for this biller; the user signs it.")

        if intent == "balance":
            if "get_balance" not in results:
                return self._call("get_balance", {}, "The user wants their balance; look up the account.")
            accts = results["get_balance"]["data"]
            if re.search(r"\baccounts\b", text, re.I):
                return self._say("You have " + "; ".join(f"your {a['name']} ({a['number']}) with {a['balance']}"
                                                          for a in accts) + ".")
            a = accts[0]
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
                pay = "full"
                if picked.get("minimum_due"):                       # credit card: full, minimum or an amount
                    amt = parse_amount(text)
                    if re.search(r"\bmin(imum)?\b", text, re.I):
                        pay = "minimum"
                    elif re.search(r"\b(full|whole|everything|all of it|statement balance|in full)\b", text, re.I):
                        pay = "full"
                    elif amt and f"S${amt:,.2f}" != picked["amount"]:
                        pay = "amount"
                    elif not amt:
                        return self._say(f"Your {picked['title']} is {picked['amount']}, and the minimum payment is "
                                         f"{picked['minimum_due']}. Would you like to pay the full amount or the minimum?")
                acct = self._account(text, results)
                if acct == "LOOKUP":
                    return self._call("get_balance", {}, "The user named an account to pay from; look it up.")
                args = {"bill_id": picked["bill_id"], "evidence": self._last_user(messages)}
                if pay != "full":
                    args["pay"] = pay
                if pay == "amount":
                    args["amount"] = parse_amount(text)
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
            amount = parse_amount(text) or self._bank_amount(messages)
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
                freq = frequency_in(text)
                if freq:                                     # "every month" -> a standing instruction
                    args["repeat"] = freq
                    if repeat_day_in(text, freq):
                        args["repeat_day"] = repeat_day_in(text, freq)
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
            amount = parse_amount(text) or self._bank_amount(messages)
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

        return self._say("I can check your balance, pay your bills, send money to family or between your accounts, "
                         "set up or stop regular payments and GIRO, change your daily limit, or invest. "
                         "What would you like to do?")

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
        return OfflineLLM._say(f"Please check the card: {d['amount']} {'in' if d.get('kind') == 'investment' else 'to'} {d['payee']}"
                               + (f", {d['repeats'][0].lower()}{d['repeats'][1:]}" if d.get("repeats") else "") + ". "
                               f"If it's right, confirm with your fingerprint.")

    @staticmethod
    def _pick_bill(text: str, bills: list[dict]) -> dict | None:
        rules = [(r"electric|water|utilit|\bsp\b", "p_sp"), (r"s&cc|town council|conservancy", "p_tc"),
                 (r"credit card|card bill|card statement|live fresh", "p_cc")]
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
    def _bank_amount(messages: list[dict]) -> float | None:
        """'Use amount 812.50 exactly' from the session state (a relative amount the bank worked out)."""
        sysmsg = messages[0]["content"] if messages and messages[0]["role"] == "system" else ""
        m = re.search(r"Use amount (\d+(?:\.\d+)?) exactly", sysmsg)
        return float(m.group(1)) if m else None

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
