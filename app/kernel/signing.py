"""What You See Is What You Sign.

1. When a draft is created, compute a digest over every field on the confirmation card.
2. After the user passes the biometric check on their device, the authenticator issues a one-time
   authorization token for the digest the user saw.
3. The executor only moves money if the token is valid + unused + the digest in the token == the digest
   recomputed on the server.

The user's device signs the exact challenge: with a passkey (WebAuthn, the device's own fingerprint / face check)
when the device has one, otherwise with a non-extractable browser key. check_signature() below is the one place
that verifies either kind; the kernel AND the execution gateway each call it on their own.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field

from app.config import settings
from app.kernel import p256, webauthn
from app.models import Draft

BIOMETRIC_REQUIRED = ("This payment needs your fingerprint, face or device PIN. Open the page in Safari (iPhone) or "
                      "Chrome (Android, Windows, Mac) on a device with screen lock, not inside an app like WeChat.")
CHALLENGE_DOMAIN = "STAR-DCTA-AUTH-V1"   # binds signatures to this purpose so they can't be reused elsewhere
SETTINGS_DOMAIN = "STAR-SETTINGS-V1"     # signed account-setting changes (lowering the protection level)


@dataclass(frozen=True)
class Site:
    """The website the passkey is bound to (WebAuthn rp id) and the exact origins allowed to use it."""
    rp_id: str = "localhost"
    origins: frozenset = field(default_factory=lambda: frozenset({"http://localhost:8000"}))


DEFAULT_SITE = Site()


class SignatureError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def browser_key_allowed(registry) -> bool:
    """A registry can carry its own policy (the security lab's sandbox simulates a browser-key device); otherwise the
    server setting decides."""
    own = getattr(registry, "allow_browser_key", None)
    return settings.allow_browser_key if own is None else bool(own)


def check_signature(registry, *, user_id: str, session_id: str, payload: str, assertion: dict, site: Site,
                    check_counter: bool = True) -> dict:
    """Verify that `assertion` is a valid signature over exactly `payload` by a credential enrolled for this
    customer. Returns the signature record that goes on the receipt. Raises SignatureError.
    No downgrade: if the customer has a passkey for this site, a plain browser-key signature is refused."""
    if not isinstance(assertion, dict) or assertion.get("payload") != payload:
        raise SignatureError("The signed content isn't exactly what was shown to you. Rejected.", "PAYLOAD_MISMATCH")
    if assertion.get("type") == "webauthn":
        cred = registry.passkey(user_id, site.rp_id, assertion.get("credential_id", ""))
        if not cred:
            raise SignatureError("This fingerprint key isn't enrolled for your account.", "UNKNOWN_CREDENTIAL")
        try:
            count = webauthn.verify_assertion(
                public_key=cred["public_key"], payload=payload, authenticator_data=assertion.get("authenticator_data"),
                client_data_json=assertion.get("client_data_json"), signature=assertion.get("signature"),
                rp_id=site.rp_id, origins=set(site.origins),
                prev_sign_count=cred.get("sign_count", 0) if check_counter else 0)
        except webauthn.WebAuthnError as e:
            raise SignatureError(str(e), e.code) from e
        return {"method": "passkey", "alg": f"WebAuthn {cred['public_key'].get('alg', 'ES256')}, user verified on the device", "payload": payload,
                "credential_id": cred["credential_id"], "authenticator_data": assertion["authenticator_data"],
                "client_data_json": assertion["client_data_json"], "signature": assertion["signature"],
                "public_key": cred["public_key"], "key_id": webauthn.key_id(cred["public_key"]),
                "rp_id": site.rp_id, "sign_count": count}
    if registry.passkeys(user_id, site.rp_id):
        raise SignatureError("This account uses fingerprint / face signing. A plain browser key isn't enough.",
                             "PASSKEY_REQUIRED")
    if not browser_key_allowed(registry):
        raise SignatureError(BIOMETRIC_REQUIRED, "BIOMETRIC_REQUIRED")
    jwk = registry.device_key(session_id)
    if not jwk:
        raise SignatureError("This device has no registered signing key yet.", "NO_KEY")
    if not verify_device_signature(jwk, payload, assertion.get("signature") or ""):
        raise SignatureError("A valid signature from your device is required.", "INVALID_SIGNATURE")
    return {"method": "device_key", "alg": "ECDSA P-256 / SHA-256 (browser key, no biometric)", "payload": payload,
            "signature": assertion["signature"], "public_key": jwk, "key_id": p256.key_fingerprint(jwk)}


def compute_digest(draft: Draft) -> str:
    canon = json.dumps(draft.card_fields(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_challenge(session_id: str, draft: Draft, ttl: int | None = None) -> str:
    """The exact bytes the user's device signs: everything shown on the confirmation card + a one-time nonce."""
    card = draft.card_fields()
    return canonical({
        "domain": CHALLENGE_DOMAIN, "session_id": session_id, "draft_id": draft.draft_id, "digest": draft.digest,
        "kind": card["kind"], "payee": card["payee_name"], "amount_cents": card["amount_cents"],
        "currency": card["currency"], "asset_class": card["asset_class"], "from_account": card["from_account"],
        "you_said": card["you_said"],
        "nonce": secrets.token_hex(12), "expires_at": int(time.time()) + (ttl or settings.challenge_ttl),
    })


def build_settings_challenge(session_id: str, user_id: str, change: dict, ttl: int | None = None) -> str:
    return canonical({"domain": SETTINGS_DOMAIN, "session_id": session_id, "user_id": user_id, "change": change,
                      "nonce": secrets.token_hex(12), "expires_at": int(time.time()) + (ttl or settings.challenge_ttl)})


def verify_device_signature(public_key: dict, payload: str, signature_b64: str) -> bool:
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except Exception:  # noqa: BLE001
        return False
    return p256.verify(public_key, payload.encode(), sig)


class MockAuthenticator:
    """Mock on-device biometric check. Real implementation: browser navigator.credentials.get() + server-side verification."""
    ACCEPTED = {"demo-fingerprint", "demo-face", "demo-pin-123456"}

    def verify(self, assertion: str) -> bool:
        return assertion in self.ACCEPTED


class TokenService:
    def __init__(self, secret: bytes | None = None):
        self.secret = secret or settings.signing_secret
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def issue(self, draft_id: str, digest: str, ttl: int | None = None) -> str:
        payload = {"d": draft_id, "h": digest, "exp": int(time.time()) + (ttl or settings.auth_token_ttl),
                   "jti": secrets.token_hex(8)}
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        sig = hmac.new(self.secret, raw, hashlib.sha256).digest()
        return f"{_b64(raw)}.{_b64(sig)}"

    def verify_and_consume(self, token: str, draft_id: str, expected_digest: str) -> tuple[bool, str]:
        try:
            raw_b64, sig_b64 = token.split(".")
            raw = _unb64(raw_b64)
            if not hmac.compare_digest(hmac.new(self.secret, raw, hashlib.sha256).digest(), _unb64(sig_b64)):
                return False, "Invalid signature"
            payload = json.loads(raw)
        except Exception:
            return False, "Malformed token"
        if payload["d"] != draft_id:
            return False, "Token does not belong to this transaction"
        if not hmac.compare_digest(payload["h"], expected_digest):
            return False, "What was confirmed does not match what would be executed"
        if payload["exp"] < time.time():
            return False, "Authorization expired"
        with self._lock:
            if payload["jti"] in self._used:
                return False, "Authorization already used (replay protection)"
            self._used.add(payload["jti"])
        return True, "ok"
