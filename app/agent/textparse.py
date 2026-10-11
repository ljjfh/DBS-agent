"""口语解析工具：中文数字金额、收款人别名匹配、金额转中文读法。

既给离线模型用，也给输出校验器用（核对模型复述的金额是否与草稿一致）。
"""
from __future__ import annotations

import re

_DIGITS = {"零": 0, "〇": 0, "一": 1, "幺": 1, "二": 2, "两": 2, "俩": 2, "三": 3, "四": 4,
           "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
_UNITS = {"十": 10, "拾": 10, "百": 100, "佰": 100, "千": 1000, "仟": 1000}
_BIG = {"万": 10000, "萬": 10000}
_ZH_NUM_CHARS = "".join(_DIGITS) + "".join(_UNITS) + "".join(_BIG) + "点"


def zh_to_number(s: str) -> float | None:
    """'两百五' -> 250, '一万二' -> 12000, '三千零五' -> 3005, '二十块五' 由调用方处理。"""
    s = s.strip()
    if not s or any(c not in _ZH_NUM_CHARS for c in s):
        return None
    if "点" in s:
        a, b = s.split("点", 1)
        ia = zh_to_number(a) if a else 0
        frac = "".join(str(_DIGITS[c]) for c in b if c in _DIGITS)
        return None if ia is None else float(f"{int(ia)}.{frac or 0}")
    total, section, num = 0, 0, 0
    last_unit = 1
    for c in s:
        if c in _DIGITS:
            num = _DIGITS[c]
        elif c in _UNITS:
            u = _UNITS[c]
            section += (num if num else (1 if u == 10 else 0)) * u
            num, last_unit = 0, u
        elif c in _BIG:
            total += (section + num) * _BIG[c]
            section, num, last_unit = 0, 0, _BIG[c]
    # “两百五”=250、“一万二”=12000：末尾单个数字按上一个单位的十分之一
    if num and last_unit >= 100 and len(s) >= 2 and s[-1] in _DIGITS and s[-2] in {**_UNITS, **_BIG}:
        num *= last_unit // 10
    return float(total + section + num)


_MONEY_RE = re.compile(
    r"(?:S?\$|sgd\s*)?\s*(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?\s*(k|千|万|块|元|新元|新币|dollars?|bucks?|sgd)?",
    re.I)
_ZH_MONEY_RE = re.compile(rf"([{_ZH_NUM_CHARS}]+)\s*(块|元|新元|新币|蚊)?([一二两三四五六七八九])?")


def parse_amount(text: str) -> float | None:
    """从一句话里提取金额（新元）。找不到返回 None。不会猜。"""
    t = text.replace("，", ",")
    for m in _MONEY_RE.finditer(t):
        digits, cents, unit = m.group(1), m.group(2), (m.group(3) or "").lower()
        # 排除像账号、电话、日期这样的长数字
        raw = digits.replace(",", "")
        if len(raw) >= 7 and not unit:
            continue
        val = float(raw + (f".{cents}" if cents else ""))
        if unit in ("k", "千"):
            val *= 1000
        elif unit == "万":
            val *= 10000
        return val
    for m in _ZH_MONEY_RE.finditer(t):
        base = zh_to_number(m.group(1))
        if base is None or base == 0 and m.group(1) in ("零", "〇"):
            continue
        if len(m.group(1)) == 1 and not m.group(2):    # 单个“一/两/五”且没有“块/元”：多半不是金额
            continue                                    # （例如 ASR 把“两百”听成“两白”），宁可追问也不猜
        if m.group(2) and m.group(3):                    # “二十块五” -> 20.5
            base += _DIGITS[m.group(3)] / 10
        return base
    return None


def find_raw_account(text: str) -> str | None:
    m = re.search(r"(?<!\d)(\d[\d\- ]{6,}\d)(?!\d)", text)
    if not m:
        return None
    digits = re.sub(r"\D", "", m.group(1))
    return digits if len(digits) >= 7 else None


def match_payees(text: str, payees: list[dict]) -> list[dict]:
    """按别名在文本里找收款人；返回全部命中（多于一个时调用方必须追问）。"""
    low = text.lower()
    hits = []
    for p in payees:
        names = [p["name"].lower(), *[a.lower() for a in p.get("aliases", [])]]
        if any(n and n in low for n in names):
            hits.append(p)
    return hits


# ---------------------------------------------------------------- 金额读法
_ZH_D = "零一二三四五六七八九"


def _int_to_zh(n: int) -> str:
    if n == 0:
        return "零"
    if n >= 10000:
        hi, lo = divmod(n, 10000)
        rest = _int_to_zh(lo) if lo else ""
        return _int_to_zh(hi) + "万" + (("零" if lo < 1000 else "") + rest if lo else "")
    parts, zero = [], False
    for unit_val, unit in ((1000, "千"), (100, "百"), (10, "十"), (1, "")):
        d, n = divmod(n, unit_val)
        if d:
            if zero:
                parts.append("零")
                zero = False
            ch = "两" if d == 2 and unit in ("千", "百") else _ZH_D[d]
            parts.append(ch + unit)
        elif parts:
            zero = True
    s = "".join(parts)
    return s[1:] if s.startswith("一十") else s


def amount_words_zh(cents: int) -> str:
    """20000 -> '两百元'；8640 -> '八十六元四角'。用于确认卡与语音复述。"""
    yuan, rem = divmod(cents, 100)
    jiao, fen = divmod(rem, 10)
    s = _int_to_zh(yuan).replace("两十", "二十") + "元" if yuan else ""
    if jiao:
        s += _ZH_D[jiao] + "角"
    if fen:
        s += _ZH_D[fen] + "分"
    return s or "零元"


def amount_digits_spoken(cents: int) -> str:
    """逐位读，防止听错：20000 -> '二、零、零'。"""
    yuan = str(cents // 100)
    return "、".join(_ZH_D[int(c)] for c in yuan)


def money_mentions(text: str) -> list[float]:
    """提取文本中所有像金额的数字（给输出校验器用）。"""
    vals = []
    for m in re.finditer(r"(?:S?\$)\s*(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?", text):
        vals.append(float(m.group(1).replace(",", "") + (f".{m.group(2)}" if m.group(2) else "")))
    return vals


def is_english(text: str) -> bool:
    return not re.search(r"[一-鿿]", text)
