"""Protection level: an ACCOUNT setting, never a screen setting.

Senior mode / standard view only change how the app looks. How careful the bank is lives here, because a scammer
on the phone can easily say "tap Standard view" - but cannot make the account less protected in a hurry:

  * raising protection (standard -> enhanced) takes effect immediately
  * lowering it (enhanced -> standard) must be signed on the customer's device AND only takes effect after a delay
    (PROTECTION_LOWER_DELAY, 24 h by default). It can be cancelled at any time before then.

What the level changes is only the SOFT friction. The hard safety boundary is the same for everyone:
the agent can only draft, drafts must match what the user said, the independent verifier can freeze a draft,
every payment is signed on the device, and the execution gateway refuses anything unsigned.

                         enhanced (seniors)                 standard (everyone else)
  cooling-off above      RULE_HIGH_THRESHOLD (S$1,000)      RULE_HIGH_THRESHOLD_STANDARD (S$3,000)
  scam phrases (HIGH)    stopped before reaching the model   a warning + "is this your own idea?" question
  scam phrases (BLOCK)   stopped                             stopped ("safe account" etc. stop everyone)
  late-night payments    extra question                      no extra question
  risky investments      cooling-off                         a warning + question
"""
from __future__ import annotations

import time

from app.config import settings
from app.models import RiskLevel

LEVELS = ("standard", "enhanced")


def effective(bank, user_id: str, now: float | None = None) -> str:
    """Current level, applying a scheduled lowering once its time has come."""
    p = bank.protection(user_id)
    pend = p.get("pending")
    if pend and (now or time.time()) >= pend["effective_at"]:
        p["level"], p["pending"] = pend["to"], None
    return p["level"]


def status(bank, user_id: str) -> dict:
    level = effective(bank, user_id)
    pend = bank.protection(user_id).get("pending")
    return {"level": level, "pending": dict(pend) if pend else None, "delay_seconds": settings.protection_delay,
            "high_threshold": high_threshold(level)}


def high_threshold(level: str) -> float:
    return settings.user_high_threshold if level == "enhanced" else settings.user_high_threshold_standard


def cap_scam(level: RiskLevel, protection: str) -> RiskLevel:
    """Standard protection turns a HIGH scam signal into a warning (MEDIUM). BLOCK-level signals stop everyone."""
    if protection == "standard" and level == RiskLevel.HIGH:
        return RiskLevel.MEDIUM
    return level


def raise_now(bank, user_id: str) -> dict:
    p = bank.protection(user_id)
    p["level"], p["pending"] = "enhanced", None
    return status(bank, user_id)


def schedule_lowering(bank, user_id: str, now: float | None = None) -> dict:
    p = bank.protection(user_id)
    if effective(bank, user_id) == "standard":
        return status(bank, user_id)
    p["pending"] = {"to": "standard", "effective_at": int((now or time.time()) + settings.protection_delay),
                    "requested_at": int(now or time.time())}
    return status(bank, user_id)
