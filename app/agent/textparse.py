"""Spoken-language parsing: amounts in digits or words, payee alias matching, amounts read back as words.

Used by the offline model and by the output validator (to check that the amount the model repeats
matches the draft).
"""
from __future__ import annotations

import re

_ONES = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
         "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
         "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19}
_TENS = {"twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80,
         "ninety": 90}
_SCALES = {"hundred": 100, "thousand": 1000, "k": 1000, "grand": 1000}
_UNIT_WORDS = {"dollar", "dollars", "buck", "bucks", "sgd"}
_NUM_WORDS = set(_ONES) | set(_TENS) | set(_SCALES)


def words_to_number(tokens: list[str]) -> float | None:
    """['two', 'hundred', 'and', 'fifty'] -> 250, ['a', 'thousand'] -> 1000, ['twelve', 'point', 'five'] -> 12.5"""
    if not tokens:
        return None
    total, current, frac, seen = 0, 0, "", False
    in_frac = False
    for i, t in enumerate(tokens):
        if in_frac:
            if t in _ONES and _ONES[t] < 10:
                frac += str(_ONES[t])
                continue
            return None
        if t == "point":
            in_frac = True
        elif t == "and":
            continue
        elif t == "a" and i + 1 < len(tokens) and tokens[i + 1] in _SCALES:
            current = 1
        elif t in _ONES:
            current += _ONES[t]
            seen = True
        elif t in _TENS:
            current += _TENS[t]
            seen = True
        elif t == "hundred":
            current = (current or 1) * 100
            seen = True
        elif t in ("thousand", "k", "grand"):
            total += (current or 1) * 1000
            current, seen = 0, True
        else:
            return None
    if not seen:
        return None
    value = total + current
    return float(f"{value}.{frac}") if frac else float(value)


_MONEY_RE = re.compile(
    r"(?:S?\$|sgd\s*)?\s*(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?\s*(k\b|thousand|grand|dollars?|bucks?|sgd)?",
    re.I)
_TOKEN_RE = re.compile(r"[a-z]+")


def _word_runs(text: str):
    """Yield (tokens_of_number_run, token_after_run, tokens_after_that) for each run of number words."""
    toks = _TOKEN_RE.findall(text.lower().replace("-", " "))
    i = 0
    while i < len(toks):
        t = toks[i]
        starts = t in _NUM_WORDS - {"k", "grand"} or (t == "a" and i + 1 < len(toks) and toks[i + 1] in _SCALES)
        if not starts:
            i += 1
            continue
        j = i
        run = []
        while j < len(toks) and (toks[j] in _NUM_WORDS or toks[j] == "point"
                                 or (toks[j] == "a" and j + 1 < len(toks) and toks[j + 1] in _SCALES)
                                 or (toks[j] == "and" and run and j + 1 < len(toks) and toks[j + 1] in _NUM_WORDS)
                                 or (run and run[-1] == "point" and toks[j] in _ONES)):
            run.append(toks[j])
            j += 1
        yield run, toks[j:]
        i = j


def parse_amount(text: str) -> float | None:
    """Extract an amount (SGD) from one sentence. Returns None if there isn't one. Never guesses."""
    # An explicit self-correction supersedes the earlier amount.
    fixed = re.search(r"\b(?:change|correct|revise)\s+(?:the\s+)?amount\s+to\s+(.+)|\bmake\s+(?:it|that)\s+(.+)|\b(?:no|sorry|actually|I mean)\s*[,;]?\s+(.+)", text, re.I)
    if fixed:
        text = next(g for g in fixed.groups() if g)
    text = re.sub(r"\ba couple of hundred\b", "two hundred", text, flags=re.I)
    fraction = re.search(r"\b(half|a quarter)\s+(?:of\s+)?(.+)", text, re.I)
    if fraction:
        base = parse_amount(fraction[2])
        if base is None:
            return None
        from decimal import Decimal
        cents = Decimal(str(base)) * 100 / (2 if fraction[1].lower() == "half" else 4)
        return float(cents / 100) if cents == cents.to_integral_value() else None
    for m in _MONEY_RE.finditer(text):
        digits, cents, unit = m.group(1), m.group(2), (m.group(3) or "").lower()
        # Skip long numbers that look like account numbers, phone numbers or dates
        raw = digits.replace(",", "")
        if len(raw) >= 7 and not unit:
            continue
        val = float(raw + (f".{cents}" if cents else ""))
        if unit in ("k", "thousand", "grand"):
            val *= 1000
        return val
    for run, rest in _word_runs(text):
        base = words_to_number(run)
        if base is None or base == 0:
            continue
        has_unit = bool(rest) and rest[0] in _UNIT_WORDS
        # A lone "two" / "five" with no "dollars" is probably not an amount
        # (e.g. ASR heard "two hundred" as "two hundread") — better to ask than to guess
        if len(run) == 1 and base < 10 and not has_unit:
            continue
        if has_unit:   # "twenty dollars fifty" / "twenty dollars and fifty cents" -> 20.5
            after = rest[1:]
            if after and after[0] == "and":
                after = after[1:]
            cents_run = []
            while after and after[0] in set(_ONES) | set(_TENS):
                cents_run.append(after.pop(0))
            c = words_to_number(cents_run)
            if c is not None and 0 < c < 100:
                base += c / 100
        return base
    return None


def find_raw_account(text: str) -> str | None:
    m = re.search(r"(?<!\d)(\d[\d\- ]{6,}\d)(?!\d)", text)
    if not m:
        return None
    digits = re.sub(r"\D", "", m.group(1))
    return digits if len(digits) >= 7 else None


_ACCOUNT_RE = re.compile(r"\b(current|savings?)\s+(account|acct|a/c)\b|\bfrom (?:my |the )?(current|savings?)\b", re.I)


def find_account(text: str) -> str | None:
    """Which of the customer's accounts they named ("from my current account"), as words; None if not said.
    ("savings bonds" is a product, not the savings account.)"""
    source = re.search(r"\bfrom (?:my |the )?(current|savings?|joint)(?:\s+account)?\b", text, re.I)
    if source:
        return source[1].lower().rstrip('s') + ('s account' if source[1].lower().startswith('saving') else ' account')
    if re.search(r"\bto (?:my |the )?(current|savings?|joint)\s+account\b", text, re.I):
        return None
    m = _ACCOUNT_RE.search(text)
    if not m:
        return None
    word = (m.group(1) or m.group(3)).lower()
    return "current account" if word == "current" else "savings account"


def account_id_for(phrase: str | None, accounts: list[dict]) -> str | None:
    if not phrase:
        return None
    first = phrase.split()[0].lower().rstrip("s")
    return next((a["account_id"] for a in accounts if a["name"].lower().startswith(first)), None)


def match_payees(text: str, payees: list[dict]) -> list[dict]:
    """Find payees by alias in the text; return every hit (the caller must ask if there's more than one)."""
    low = re.sub(r"\bd\s+b\s+s\b", "dbs", text.lower())
    # Source accounts are not recipients of an internal transfer.
    low = re.sub(r"\bfrom (?:my |the )?(?:savings?|current|joint)(?:\s+account)?\b", "", low)
    hits = []
    for p in payees:
        names = [p["name"].lower(), *[a.lower() for a in p.get("aliases", [])]]
        if any(n and re.search(rf"(?<![a-z]){re.escape(n)}(?![a-z])", low) for n in names):
            hits.append(p)
    if len(hits) > 1:
        # "my grandson ... Chen Wei": a name only one candidate has beats a word they all share
        shared = set.intersection(*({p["name"].lower(), *map(str.lower, p.get("aliases", []))} for p in hits))
        specific = [p for p in hits
                    if any(n not in shared and re.search(rf"(?<![a-z]){re.escape(n)}(?![a-z])", low)
                           for n in [p["name"].lower(), *map(str.lower, p.get("aliases", []))])]
        if len(specific) == 1:
            return specific
    return hits


# ---------------------------------------------------------------- Amounts as words
_ONES_W = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
           "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"]
_TENS_W = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]


def _int_to_en(n: int) -> str:
    if n < 20:
        return _ONES_W[n]
    if n < 100:
        t, o = divmod(n, 10)
        return _TENS_W[t] + (f"-{_ONES_W[o]}" if o else "")
    if n < 1000:
        h, r = divmod(n, 100)
        return f"{_ONES_W[h]} hundred" + (f" and {_int_to_en(r)}" if r else "")
    for scale, name in ((1_000_000, "million"), (1000, "thousand")):
        if n >= scale:
            hi, lo = divmod(n, scale)
            rest = ("" if not lo else (" and " if lo < 100 else " ") + _int_to_en(lo))
            return f"{_int_to_en(hi)} {name}{rest}"
    return str(n)


def amount_words_en(cents: int) -> str:
    """20000 -> 'two hundred dollars'; 8640 -> 'eighty-six dollars and forty cents'. For the card and read-back."""
    dollars, rem = divmod(cents, 100)
    parts = []
    if dollars:
        parts.append(f"{_int_to_en(dollars)} dollar{'s' if dollars != 1 else ''}")
    if rem:
        parts.append(f"{_int_to_en(rem)} cent{'s' if rem != 1 else ''}")
    return " and ".join(parts) or "zero dollars"


def amount_digits_spoken(cents: int) -> str:
    """Read digit by digit so it can't be misheard: 20000 -> 'two, zero, zero'."""
    return ", ".join(_ONES_W[int(c)] for c in str(cents // 100))


def money_mentions(text: str) -> list[float]:
    """Extract every number that looks like an amount (for the output validator)."""
    vals = []
    for m in re.finditer(r"(?:S?\$)\s*(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?", text):
        vals.append(float(m.group(1).replace(",", "") + (f".{m.group(2)}" if m.group(2) else "")))
    return vals
