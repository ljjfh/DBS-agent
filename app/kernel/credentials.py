"""Who is allowed to sign for a customer: the enrolled credentials.

Two kinds, strongest first:
  * passkey    - WebAuthn credential unlocked by the device's own fingerprint / face (Touch ID, Face ID, Windows Hello).
                 Enrolled per customer and per website (rp id), kept on disk across demo resets.
  * device_key - a non-extractable WebCrypto P-256 key, for browsers/computers without a biometric sensor.
                 Registered per session. No biometric check: shown to the user as "signed with this browser's key".

No downgrade: once a customer has a passkey for this site, only passkey signatures are accepted for them.

Both the kernel (authorize) and the execution gateway (before posting to the ledger) read from this registry and
verify signatures themselves; the gateway never takes the kernel's word for it.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path


class CredentialRegistry:
    def __init__(self, path: Path | None = None):
        self.path = path
        self._lock = threading.Lock()
        self._passkeys: dict[str, list[dict]] = {}
        self._device_keys: dict[str, dict] = {}
        if path and path.exists():
            try:
                self._passkeys = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                self._passkeys = {}

    # ---------------- passkeys (per customer, per rp id)
    def passkeys(self, user_id: str, rp_id: str) -> list[dict]:
        return [c for c in self._passkeys.get(user_id, []) if c["rp_id"] == rp_id]

    def has_passkey(self, user_id: str) -> bool:
        return bool(self._passkeys.get(user_id))

    def passkey(self, user_id: str, rp_id: str, credential_id: str) -> dict | None:
        return next((c for c in self.passkeys(user_id, rp_id) if c["credential_id"] == credential_id), None)

    def add_passkey(self, user_id: str, cred: dict) -> None:
        with self._lock:
            lst = self._passkeys.setdefault(user_id, [])
            lst[:] = [c for c in lst if c["credential_id"] != cred["credential_id"]]
            lst.append({**cred, "created_at": int(time.time())})
            self._save()

    def bump_count(self, user_id: str, rp_id: str, credential_id: str, count: int) -> None:
        with self._lock:
            c = self.passkey(user_id, rp_id, credential_id)
            if c and count:
                c["sign_count"] = count
                self._save()

    def remove_passkeys(self, user_id: str, rp_id: str) -> int:
        with self._lock:
            before = len(self._passkeys.get(user_id, []))
            self._passkeys[user_id] = [c for c in self._passkeys.get(user_id, []) if c["rp_id"] != rp_id]
            self._save()
            return before - len(self._passkeys[user_id])

    def _save(self):
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._passkeys, indent=1), encoding="utf-8")

    # ---------------- browser keys (per session)
    def device_key(self, session_id: str) -> dict | None:
        return self._device_keys.get(session_id)

    def set_device_key(self, session_id: str, jwk: dict) -> None:
        self._device_keys[session_id] = jwk
