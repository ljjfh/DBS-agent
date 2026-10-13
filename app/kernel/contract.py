"""Deterministic transaction contract. Evidence is produced by the same gates that authorize payment.

Decision records are server observations, NOT a customer's signature over the risk assessment.
The demo reviewer models a separate bank role; it is not a real callback/KYC service.
"""
from __future__ import annotations

import copy
import secrets
import threading
import time

from app.kernel import protection

POLICY_VERSION = "star-contract-1.0"


def secondary_required(card, bank):
    payee = bank.payee(card["user_id"], card["payee_id"]) or {}
    return (payee.get("type") != "own" and
            card["amount_cents"] > protection.high_threshold(protection.effective(bank, card["user_id"])) * 100)


class SecondaryReviews:
    """Server-owned, digest-bound approvals. Lost on restart, like pending drafts: fail closed."""
    def __init__(self):
        self.records = {}
        self.lock = threading.RLock()

    def approve(self, user_id, session_id, draft_id, digest, expires_at):
        with self.lock:
            self.records = {key: value for key, value in self.records.items() if value["expires_at"] > time.time()}
            rec = {"approval_id": "review_" + secrets.token_hex(12), "user_id": user_id,
                   "session_id": session_id, "draft_id": draft_id, "digest": digest,
                   "expires_at": min(expires_at, time.time() + 300), "approved_at": time.time(),
                   "policy_version": POLICY_VERSION, "method": "simulated bank reviewer"}
            self.records[(session_id, draft_id)] = rec
            return copy.deepcopy(rec)

    def valid(self, user_id, session_id, draft_id, digest):
        with self.lock:
            rec = self.records.get((session_id, draft_id), {})
            return copy.deepcopy(rec) if (rec.get("user_id") == user_id and rec.get("digest") == digest
                and rec.get("expires_at", 0) > time.time() and rec.get("policy_version") == POLICY_VERSION) else None

    def revoke(self, session_id, draft_id):
        with self.lock:
            self.records.pop((session_id, draft_id), None)


def decision(draft, session, bank, reviews, *, stage="before_authorization", signature=False,
             verify_answer=False, execution=False, rejection=None):
    """Build a fail-closed decision. Only explicit observations produce a pass."""
    check = lambda status, detail: {"status": status, "detail": detail}
    v = draft.verification
    checks = {}
    checks["intent"] = check("pass" if v.get("status") == "match" else
        "fail" if v.get("status") == "mismatch" else "pending",
        "; ".join(v.get("mismatches", [])) or "Verifier: " + v.get("engine", "not available"))
    missing = [ref for ref in draft.dependency_ids if not
        ((bank.transaction(draft.user_id, ref) or {}).get("status") == "SUCCESS")]
    checks["plan"] = check("fail" if missing else "pass" if draft.dependency_ids else "not_applicable",
        "Uncompleted dependencies: " + ", ".join(missing) if missing else
        "Completed ledger receipts: " + ", ".join(draft.dependency_ids) if draft.dependency_ids else "No prior transaction is required.")
    risk = draft.risk
    blocked = not risk or risk.level.value == "BLOCK"
    cooling = draft.cooling_until > time.time()
    question = bool(risk and risk.verify_question and not verify_answer)
    checks["policy"] = check("fail" if blocked else "pending" if cooling or question else "pass",
        " ".join(risk.reasons) if risk and risk.reasons else "Transaction rules passed." if risk else "Rules have not run.")
    required = secondary_required(draft.card_fields(), bank)
    approval = reviews.valid(draft.user_id, session.session_id, draft.draft_id, draft.digest)
    checks["secondary_approval"] = check("pass" if required and approval else "pending" if required else "not_applicable",
        "Simulated bank reviewer approved this exact card." if required and approval else
        "A separate demo reviewer must approve this exact card." if required else "Not required by this policy.")
    checks["authorization"] = check("pass" if signature else "pending", "Device signature verified." if signature else "Waiting for the customer's signature.")
    checks["execution"] = check("pass" if execution else "fail" if rejection else "pending",
        "Gateway verified and ledger committed." if execution else rejection or "No execution has been confirmed.")
    if rejection:
        action = "reject"
    elif v.get("status") == "mismatch":
        action = "freeze"
    elif missing or blocked:
        action = "reject"
    elif v.get("status") != "match":
        action = "wait_for_validation"
    elif cooling:
        action = "wait"
    elif required and not approval:
        action = "wait_for_secondary_approval"
    elif question:
        action = "clarify"
    else:
        action = "executed" if execution else "execute" if signature else "request_signature"
    required_evidence = [k for k, c in checks.items() if c["status"] == "pending" and k != "execution"]
    return {"policy_version": POLICY_VERSION, "transaction_id": draft.draft_id,
            "session_id": session.session_id, "digest": draft.digest, "stage": stage,
            "action": action, "checks": checks, "reason_codes": list(risk.rule_hits) if risk else [],
            "required_evidence": required_evidence, "recorded_at": time.time(),
            "secondary_approval": approval if required else None,
            "dependency_ids": list(draft.dependency_ids),
            "raw_text": "\n".join(m.get("raw_content") or m["content"] for m in session.messages[session.task_start:]
                                     if m.get("role") == "user") or draft.you_said,
            "draft": {"payee": draft.payee_name, "amount_cents": draft.amount_cents, "from_account": draft.from_account},
            "verifier": {"engine": v.get("engine", "unavailable"), "extracted": v.get("extracted"),
                         "mode": "offline_shared_parser" if "offline" in v.get("engine", "").lower() else "model_or_test_fixture"},
            "evidence_scope": "Server observations; the customer signs the transaction card, not this report."}
