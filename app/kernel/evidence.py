"""Evidence grounding: is every important field of a draft backed by something the USER actually said?

The model chooses the payee and amount, but it must not be the only source of truth for them. This module
checks the draft against the user's own recent words - deterministically, without asking the model:

  * payee  - one of the payee's saved names / aliases appears in what the user said
  * amount - the exact amount appears in what the user said (digits or words), or, for a bill,
             the amount comes from the bill itself and the bill was mentioned

What happens when a field is NOT grounded is decided by the rules engine (see rules.py, R50-R52):
  amount not said  -> MEDIUM (elderly users say "the usual amount"; we allow it but flag it on the card)
  payee not said   -> HIGH   (cooling-off: the model picked someone the user never mentioned)
  neither          -> BLOCK  (nothing in the conversation supports this payment, e.g. an injected instruction)

Idea adapted from a teammate's prototype (evidence quotes + independent evidence rules).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.agent.textparse import _MONEY_RE, _UNIT_WORDS, _word_runs, parse_amount, words_to_number

WINDOW = 6   # how many recent user messages count as "what the user said" for the current task


@dataclass
class Grounding:
    payee: bool
    amount: bool
    amount_source: str = "user"          # "user" | "bill" | "not said"
    quote: str = ""                      # the user's own words that best support this payment
    said_amounts: list[float] = field(default_factory=list)

    @property
    def fully_grounded(self) -> bool:
        return self.payee and self.amount

    def as_dict(self) -> dict:
        return {"payee": self.payee, "amount": self.amount, "amount_source": self.amount_source,
                "quote": self.quote}


def amounts_in(text: str) -> set[int]:
    """Every amount (in cents) that appears in a piece of text, in digits or words. Generous on purpose:
    grounding asks "did the user say this number at all", not "which number is the amount"."""
    found: set[int] = set()
    for m in _MONEY_RE.finditer(text):
        digits, cents, unit = m.group(1), m.group(2), (m.group(3) or "").lower()
        raw = digits.replace(",", "")
        if len(raw) >= 7 and not unit:          # account / phone numbers are not amounts
            continue
        val = float(raw + (f".{cents}" if cents else ""))
        if unit in ("k", "thousand", "grand"):
            val *= 1000
        found.add(round(val * 100))
    for run, _rest in _word_runs(text):
        v = words_to_number(run)
        if v:
            found.add(round(v * 100))
    whole = parse_amount(text)                  # catches "twenty dollars fifty" -> 20.50
    if whole:
        found.add(round(whole * 100))
    return found


def _mentions(text: str, names: list[str]) -> bool:
    low = f" {text.lower()} "
    return any(n and re.search(rf"(?<![a-z]){re.escape(n.lower())}(?![a-z])", low) for n in names)


def user_utterances(messages: list[dict], window: int = WINDOW) -> list[str]:
    return [m["content"] for m in messages if m.get("role") == "user"][-window:]


def ground(utterances: list[str], payee: dict | None, amount_cents: int, kind: str,
           bill: dict | None = None, model_quote: str = "") -> Grounding:
    names = ([payee["name"], *payee.get("aliases", [])] if payee else [])
    if bill:
        names += [bill.get("title", "")]
    payee_ok = bool(payee) and any(_mentions(u, names) for u in utterances)

    if kind == "bill" and bill is not None and amount_cents in (bill.get("amount_cents"), bill.get("min_due_cents")):
        amount_ok, source = True, "bill"        # authoritative amount from the bill (full or minimum), not the model
    else:
        amount_ok = any(amount_cents in amounts_in(u) for u in utterances)
        source = "user" if amount_ok else "not said"

    # Best supporting quote: the model's quote if it really is the user's words, else the latest utterance
    # that mentions the payee or the amount.
    # Across turns ("Send money to my son" ... "three hundred") the quote joins both pieces.
    quote = ""
    covers_both = (model_quote and _mentions(model_quote, names)
                   and (kind == "bill" or amount_cents in amounts_in(model_quote)))
    if covers_both and any(_norm(model_quote) in _norm(u) for u in utterances):
        quote = model_quote.strip()
    else:
        who = next((u for u in reversed(utterances) if _mentions(u, names)), "")
        how_much = next((u for u in reversed(utterances) if amount_cents in amounts_in(u)), "")
        parts = [p for p in dict.fromkeys([who, how_much]) if p]
        parts.sort(key=lambda p: max(i for i, u in enumerate(utterances) if u == p))   # in the order they were said
        quote = " … ".join(p.strip() for p in parts)
    said = sorted({c / 100 for u in utterances for c in amounts_in(u)})
    return Grounding(payee=payee_ok, amount=amount_ok, amount_source=source, quote=quote[:160], said_amounts=said)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s$.]", "", s.lower())).strip()


__all__ = ["Grounding", "ground", "amounts_in", "user_utterances", "_UNIT_WORDS"]
