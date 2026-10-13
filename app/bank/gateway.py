"""Zero-trust execution gateway: the ONLY way to write to the ledger.

It sits in front of the bank's posting functions and trusts nobody upstream - not the agent (which can't reach it
at all), and not even the kernel. Every instruction must carry the customer's own device signature, and the gateway
checks it again itself before a single cent moves:

  1. the card it is asked to execute hashes to the digest that was signed      (what was shown = what is executed)
  2. the signed payload is a payment challenge for exactly this card            (payee, amount, account, asset, session)
  3. the signature verifies against a credential ENROLLED for this customer    (looked up here, not passed in)
     - a passkey (device biometric, UV flag required) or, only if the customer has no passkey, a browser key
  4. the signed payload has not been used before                                (its own replay list)
  5. the signature is fresh                                                     (challenge expiry + small grace)

Anything missing -> rejected with a code, logged, nothing posted. A conversation request with no signature from
the customer's device can never execute, however it reaches this point.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
import time
from urllib.parse import urlparse

from app.config import settings
from app.kernel.contract import SecondaryReviews, secondary_required
from app.kernel.signing import CHALLENGE_DOMAIN, SignatureError, Site, canonical, check_signature

GRACE_SECONDS = 60


class GatewayError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


class ExecutionGateway:
    def __init__(self, bank, registry, audit=None, allow_unsigned: bool = False):
        self._bank, self.registry, self.audit = bank, registry, audit
        self.allow_unsigned = allow_unsigned          # only for quick scripts in AUTH_MODE=mock; never in the demo
        self.reviews = SecondaryReviews()
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def execute(self, *, user_id: str, session_id: str, card: dict, digest: str, auth: dict | None,
                idempotency_key: str, verification: dict | None = None, decision: dict | None = None) -> dict:
        try:
            method = self._check(user_id, session_id, card, digest, auth)
            approval = self.reviews.valid(user_id, session_id, card["draft_id"], digest)
            if secondary_required(card, self._bank) and not approval:
                raise GatewayError("The independent demo review is missing or expired.", "GW_SECONDARY_APPROVAL_REQUIRED")
            for ref in card.get("dependency_ids", []):
                if (self._bank.transaction(user_id, ref) or {}).get("status") != "SUCCESS":
                    raise GatewayError("A required earlier transaction is not complete.", "GW_DEPENDENCY_NOT_COMPLETED")
        except GatewayError as e:
            self._log("gateway.rejected", session_id, {"draft_id": card.get("draft_id"), "reason": e.code})
            raise
        metadata = {"session_id": session_id, "verification": verification or {}, "card": card, "digest": digest, "authorization": auth or {"method": "demo authenticator (unsigned)"}}
        if decision:
            recorded = copy.deepcopy(decision)
            recorded.update(stage="executed", action="executed", required_evidence=[], recorded_at=time.time())
            recorded["checks"]["authorization"] = {"status": "pass" if auth else "not_applicable",
                "detail": "Gateway independently verified the device signature." if auth else "Unsigned test fixture."}
            recorded["checks"]["execution"] = {"status": "pass", "detail": "Gateway verified; this record is stored atomically with the ledger commit."}
            recorded["secondary_approval"] = approval
            metadata["decision"] = recorded
        try:
            if card.get("schedule"):
                receipt = self._bank.create_standing_instruction(user_id, card["from_account"], card["payee_id"],
                    card["amount_cents"], card["schedule"], idempotency_key=idempotency_key, metadata=metadata)
            elif card["kind"] == "investment":
                receipt = self._bank.execute_investment(user_id, card["from_account"], card["payee_id"],
                    card["amount_cents"], idempotency_key=idempotency_key, metadata=metadata)
            else:
                receipt = self._bank.execute_payment(user_id, card["from_account"], card["payee_id"], card["amount_cents"],
                    idempotency_key=idempotency_key, bill_id=card.get("bill_id"), metadata=metadata)
        except (ValueError, OSError) as e:
            raise GatewayError(str(e), "GW_LEDGER_REJECTED") from e
        if self.audit:
            self._bank.flush_audit(self.audit)
        return receipt

    # ------------------------------------------------------------------ checks
    def _check(self, user_id: str, session_id: str, card: dict, digest: str, auth: dict | None) -> str:
        if hashlib.sha256(canonical(card).encode()).hexdigest() != digest or card.get("user_id") != user_id:
            raise GatewayError("The instruction doesn't match the signed card.", "GW_DIGEST_MISMATCH")
        if not auth or "payload" not in auth:
            if self.allow_unsigned:
                return "unsigned (mock mode)"
            raise GatewayError("No signature from the customer's device. Refused.", "GW_UNSIGNED")
        try:
            signed = json.loads(auth["payload"])
        except (TypeError, ValueError) as e:
            raise GatewayError("Malformed signed payload.", "GW_MALFORMED") from e
        expected = {"domain": CHALLENGE_DOMAIN, "session_id": session_id, "draft_id": card["draft_id"],
                    "digest": digest, "kind": card["kind"], "payee": card["payee_name"],
                    "amount_cents": card["amount_cents"], "currency": card["currency"],
                    "asset_class": card["asset_class"], "from_account": card["from_account"],
                    "schedule": card.get("schedule")}
        if any(signed.get(k) != v for k, v in expected.items()):
            raise GatewayError("The signature is for a different payment.", "GW_PAYLOAD_MISMATCH")
        if signed.get("expires_at", 0) + GRACE_SECONDS < time.time():
            raise GatewayError("The signature is too old.", "GW_EXPIRED")
        try:
            rec = check_signature(self.registry, user_id=user_id, session_id=session_id, payload=auth["payload"],
                                  assertion={**auth, "type": "webauthn" if auth.get("method") == "passkey" else None},
                                  site=self._site(auth), check_counter=False)
        except SignatureError as e:
            raise GatewayError(f"Signature check failed at the gateway: {e}", "GW_" + e.code) from e
        key = hashlib.sha256(auth["payload"].encode()).hexdigest()
        with self._lock:
            if key in self._consumed:
                raise GatewayError("This signature was already used.", "GW_REPLAY")
            self._consumed.add(key)
        return rec["method"]

    @staticmethod
    def _site(auth: dict) -> Site:
        """Passkeys: the rp id must be one of our own hosts and the origin must be that same host."""
        if auth.get("method") != "passkey":
            return Site()
        rp_id = auth.get("rp_id", "")
        if rp_id not in settings.allowed_hosts:
            raise GatewayError("Passkey for an unknown site.", "GW_RP_MISMATCH")
        try:
            cd = json.loads(base64.urlsafe_b64decode(auth["client_data_json"] + "=" * (-len(auth["client_data_json"]) % 4)))
            origin = cd.get("origin", "")
        except Exception as e:  # noqa: BLE001
            raise GatewayError("Malformed passkey data.", "GW_MALFORMED") from e
        if urlparse(origin).hostname != rp_id.strip("[]"):
            raise GatewayError("Passkey used from another website.", "GW_ORIGIN_MISMATCH")
        return Site(rp_id, frozenset({origin}))

    def _log(self, event: str, session_id: str, data: dict):
        if self.audit:
            self.audit.append(event, session_id, data)
