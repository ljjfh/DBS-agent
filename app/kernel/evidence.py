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

import difflib
import re
from dataclasses import dataclass, field

from app.agent.textparse import (_MONEY_RE, _NUM_WORDS, _UNIT_WORDS, _word_runs, account_id_for, find_account, is_percent,
                                 parse_amount, relative_in, words_to_number)

WINDOW = 6   # how many recent user messages count as "what the user said" for the current task


@dataclass
class Grounding:
    payee: bool
    amount: bool
    amount_source: str = "user"          # "user" | "bill" | "derived" | "derived mismatch" | "not said"
    quote: str = ""                      # the user's own words that best support this payment
    said_amounts: list[float] = field(default_factory=list)
    derived: str = ""                    # how the bank computed a relative amount ("half of your Savings Account ...")
    heard: str = ""                      # the model's reading of a speech slip, once checked ("we heard ... and read ...")

    @property
    def fully_grounded(self) -> bool:
        return self.payee and self.amount

    def as_dict(self) -> dict:
        return {"payee": self.payee, "amount": self.amount, "amount_source": self.amount_source,
                "quote": self.quote, "derived": self.derived,
                "heard": self.heard}


def amounts_in(text: str) -> set[int]:
    """Every amount (in cents) that appears in a piece of text, in digits or words. Generous on purpose:
    grounding asks "did the user say this number at all", not "which number is the amount"."""
    found: set[int] = set()
    for m in _MONEY_RE.finditer(text):
        digits, cents, unit = m.group(1), m.group(2), (m.group(3) or "").lower()
        if is_percent(text, m.end(1) + (len(cents) + 1 if cents else 0)):
            continue
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


_YES = re.compile(r"^\W*(yes|yeah|yep|yup|ya|correct|right|that'?s right|that'?s correct|exactly|ok(ay)?|sure|"
                  r"yes please|yes,? (that'?s )?(it|right|correct)|confirm(ed)?)\b[\w\s,']{0,20}\W*$", re.I)


def confirmed_proposal(messages: list[dict]) -> str:
    """The assistant's question just before the user's latest words, if those words are a plain yes."""
    users = [i for i, m in enumerate(messages) if m.get("role") == "user"]
    if not users or not _YES.match(messages[users[-1]]["content"]):
        return ""
    before = [m for m in messages[:users[-1]] if m.get("role") == "assistant" and m.get("content")
              and not m.get("tool_calls")]
    return before[-1]["content"] if before and "?" in before[-1]["content"] else ""


def user_utterances(messages: list[dict], window: int = WINDOW) -> list[str]:
    return [m["content"] for m in messages if m.get("role") == "user"][-window:]


def ground(utterances: list[str], payee: dict | None, amount_cents: int, kind: str,
           bill: dict | None = None, model_quote: str = "", accounts: list[dict] | None = None,
           from_account: str | None = None, heard: tuple[str, str] | None = None,
           proposal: str = "") -> Grounding:
    names = ([payee["name"], *payee.get("aliases", [])] if payee else [])
    if bill:
        names += [bill.get("title", "")]
    payee_ok = bool(payee) and any(_mentions(u, names) for u in utterances)

    if kind == "bill" and bill is not None and amount_cents in (bill.get("amount_cents"), bill.get("min_due_cents")):
        amount_ok, source = True, "bill"        # authoritative amount from the bill (full or minimum), not the model
    else:
        amount_ok = any(amount_cents in amounts_in(u) for u in utterances)
        source = "user" if amount_ok else "not said"
    derived, rel_said, heard_note = "", "", ""
    if not amount_ok and proposal and amount_cents in amounts_in(proposal):
        # the assistant asked "Did you mean a grand (S$1,000)?" and the user's latest words were "yes"
        amount_ok, source = True, "confirmed"
        asked = next((q for q in re.split(r"(?<=[.!?])\s+", proposal.strip())
                      if q.endswith("?") and amount_cents in amounts_in(q)), proposal)
        heard_note = f"you said yes when I asked: “{asked.strip()[:90]}”"
    if not amount_ok and heard and all(heard):
        # The model's reading of a speech slip ("a grant" -> "a grand"). The model does the understanding; code only
        # checks it: the misheard words really are in what the user said, they sound like what the model says was
        # meant, and what was meant is exactly this amount. Otherwise the amount stays "not said".
        said_as, meant = heard
        if (any(_norm(said_as) and _norm(said_as) in _norm(u) for u in utterances) and amount_cents in amounts_in(meant)
                and sounds_alike(said_as, meant)):
            amount_ok, source = True, "heard"
            heard_note = f"we heard “{said_as.strip()}” and read it as “{meant.strip()}”"
    if not amount_ok and accounts:
        # "half of my money": the bank computes it; the model's number must match the bank's
        hit = next(((c, why) for c, why in derived_amounts(utterances, accounts, from_account)
                    if abs(c - amount_cents) <= 1), None)
        recent = derived_amounts(utterances[-2:], accounts, from_account)
        if hit:
            amount_ok, source, derived = True, "derived", hit[1]
        elif recent:
            source, derived = "derived mismatch", f"{recent[0][1]}, which is {_fmt(recent[0][0])}"
        rel_said = next((u for u in reversed(utterances) if relative_in(u)), "")

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
        how_much = next((u for u in reversed(utterances) if amount_cents in amounts_in(u)), "") or rel_said or \
            next((u for u in reversed(utterances) if heard and heard[0] and _norm(heard[0]) in _norm(u)), "")
        parts = [p for p in dict.fromkeys([who, how_much]) if p]
        parts.sort(key=lambda p: max(i for i, u in enumerate(utterances) if u == p))   # in the order they were said
        quote = " … ".join(p.strip() for p in parts)
    said = sorted({c / 100 for u in utterances for c in amounts_in(u)})
    return Grounding(payee=payee_ok, amount=amount_ok, amount_source=source, quote=quote[:160], said_amounts=said,
                     derived=derived, heard=heard_note)


def sounds_alike(heard: str, meant: str) -> bool:
    """Could speech recognition have turned `meant` into `heard`? A spelling-level check ("a grant"/"a grand",
    "Agree"/"a grand", "fifty"/"fifteen"), not a meaning check: every number word in what was meant must sound like
    something that was heard, so a reading can't add a number ("a grant" -> "ten grand")."""
    def sq(x):
        return re.sub(r"[^a-z0-9]", "", x.lower())
    whole = sq(heard)
    if not whole or not sq(meant):
        return False
    heard_tokens = [sq(t) for t in heard.split() if sq(t)] + [whole]
    numberish = [sq(t) for t in meant.split() if sq(t) in _NUM_WORDS - {"one"} or sq(t).isdigit()]
    if not numberish:
        return False

    def close(a, b):
        return difflib.SequenceMatcher(None, a, b).ratio() >= 0.5 or (len(b) >= 3 and b[:3] in a)
    return all(any(close(h, n) for h in heard_tokens) for n in numberish) and \
        difflib.SequenceMatcher(None, whole, sq(meant)).ratio() >= 0.5


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s$.]", "", s.lower())).strip()


__all__ = ["Grounding", "ground", "amounts_in", "user_utterances", "_UNIT_WORDS"]


def _fmt(cents: int) -> str:
    return f"S${cents / 100:,.2f}"


def derived_amounts(utterances: list[str], accounts: list[dict], from_account: str | None) -> list[tuple[int, str]]:
    """Relative amounts the user asked for, computed by code: [(cents, "half of your Savings Account (S$1,625.00)")].
    'of it' uses the amount said just before; otherwise the account named in that sentence, else the account the
    money comes from. The most recent sentence comes first."""
    out: list[tuple[int, str]] = []
    by_id = {a["account_id"]: a for a in accounts}
    for i in range(len(utterances) - 1, -1, -1):
        u = utterances[i]
        rel = relative_in(u)
        if not rel:
            continue
        frac, label, base = rel
        if base == "it":
            earlier = [c for k in range(i, -1, -1) for c in sorted(amounts_in(utterances[k])) if c > 0]
            if earlier:
                out.append((int(frac * earlier[0]), f"{label} of {_fmt(earlier[0])}"))
            continue
        acct = by_id.get(account_id_for(find_account(u), accounts) or "") or by_id.get(from_account or "") or \
            (accounts[0] if accounts else None)
        if acct:
            out.append((int(frac * acct["balance_cents"]),
                        f"{label} of your {acct['name']} ({_fmt(acct['balance_cents'])})"))
    return out
