"""WebAuthn / passkeys: the payment is signed by the device's own biometric check (Touch ID, Face ID, Windows Hello).

Browser side (web/app.js):
  enrol  : navigator.credentials.create({authenticatorAttachment: "platform", userVerification: "required",
                                         algorithms ES256 (P-256) or RS256 (RSA, used by some Windows Hello set-ups)})
  sign   : navigator.credentials.get({challenge: SHA-256(exact payment payload), userVerification: "required"})
           -> the OS shows its native fingerprint / face prompt; the private key never leaves the secure hardware.

Server side (here), with no third-party library:
  * clientDataJSON: right type, the challenge is SHA-256 of the exact payload we issued, origin is this site
  * authenticatorData: rpIdHash = SHA-256(rp id), flags UP (user present) AND UV (user verified = biometric/PIN)
  * signature: ECDSA P-256 (ES256) or RSA PKCS#1 v1.5 (RS256) over authenticatorData || SHA-256(clientDataJSON),
    with the enrolled public key
  * signCount must increase (cloned-authenticator detection) when the authenticator keeps one

Attestation is "none": we don't check which brand of device made the key. Enrolment is trust-on-first-use for
this demo customer; a real bank would bind it to a verified identity (see docs/SECURITY.md).
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct

from app.kernel import p256

FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40


class WebAuthnError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    if not isinstance(s, str):
        raise WebAuthnError("Malformed passkey response.", "MALFORMED")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception as e:  # noqa: BLE001
        raise WebAuthnError("Malformed passkey response.", "MALFORMED") from e


# ---------------------------------------------------------------- minimal CBOR (enough for attestation objects)
def _cbor(data: bytes, i: int = 0):
    ib = data[i]
    major, info = ib >> 5, ib & 0x1F
    i += 1
    if info < 24:
        val = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        val = int.from_bytes(data[i:i + n], "big")
        i += n
    else:
        raise WebAuthnError("Unsupported CBOR encoding.", "MALFORMED")
    if major == 0:
        return val, i
    if major == 1:
        return -1 - val, i
    if major in (2, 3):
        chunk = data[i:i + val]
        return (chunk if major == 2 else chunk.decode()), i + val
    if major == 4:
        out = []
        for _ in range(val):
            item, i = _cbor(data, i)
            out.append(item)
        return out, i
    if major == 5:
        out = {}
        for _ in range(val):
            k, i = _cbor(data, i)
            v, i = _cbor(data, i)
            out[k] = v
        return out, i
    if major == 7:
        return {20: False, 21: True, 22: None}.get(info), i
    raise WebAuthnError("Unsupported CBOR type.", "MALFORMED")


def cbor_decode(data: bytes):
    try:
        return _cbor(data, 0)
    except (IndexError, UnicodeDecodeError) as e:
        raise WebAuthnError("Malformed passkey response.", "MALFORMED") from e


def _cbor_enc(obj) -> bytes:       # used only by the test/lab authenticator below
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)
    if isinstance(obj, bool):
        return bytes([0xF5 if obj else 0xF4])
    if isinstance(obj, int):
        return head(0, obj) if obj >= 0 else head(1, -1 - obj)
    if isinstance(obj, bytes):
        return head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode()
        return head(3, len(b)) + b
    if isinstance(obj, list):
        return head(4, len(obj)) + b"".join(_cbor_enc(x) for x in obj)
    if isinstance(obj, dict):
        return head(5, len(obj)) + b"".join(_cbor_enc(k) + _cbor_enc(v) for k, v in obj.items())
    raise TypeError(type(obj))


# ---------------------------------------------------------------- parsing
def parse_auth_data(ad: bytes) -> dict:
    if len(ad) < 37:
        raise WebAuthnError("Authenticator data too short.", "MALFORMED")
    out = {"rp_id_hash": ad[:32], "flags": ad[32], "sign_count": struct.unpack(">I", ad[33:37])[0]}
    if out["flags"] & FLAG_AT:
        cred_len = struct.unpack(">H", ad[53:55])[0]
        out["credential_id"] = ad[55:55 + cred_len]
        out["cose_key"], _ = cbor_decode(ad[55 + cred_len:])
    return out


_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_verify(jwk: dict, message: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 with SHA-256 (RS256), as used by some Windows Hello authenticators."""
    try:
        n, e = int.from_bytes(unb64u(jwk["n"]), "big"), int.from_bytes(unb64u(jwk["e"]), "big")
    except (KeyError, WebAuthnError):
        return False
    k = (n.bit_length() + 7) // 8
    if n.bit_length() < 2048 or len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_DIGESTINFO + hashlib.sha256(message).digest()
    return em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def key_id(jwk: dict) -> str:
    """Short, stable id of a public key (EC or RSA), shown on receipts."""
    if jwk.get("kty") == "RSA":
        return hashlib.sha256((jwk["n"] + "." + jwk["e"]).encode()).hexdigest()[:16]
    return p256.key_fingerprint(jwk)


def verify_signature(jwk: dict, message: bytes, sig: bytes) -> bool:
    if jwk.get("kty") == "RSA":
        return rsa_verify(jwk, message, sig)
    return p256.verify(jwk, message, der_to_raw(sig))


def cose_to_jwk(cose: dict) -> dict:
    """COSE key -> public JWK. EC2 (kty 2, alg -7 ES256, crv 1 P-256) or RSA (kty 3, alg -257 RS256)."""
    if isinstance(cose, dict) and cose.get(1) == 3 and cose.get(3) == -257:
        n, e = cose.get(-1), cose.get(-2)
        if not isinstance(n, bytes) or not isinstance(e, bytes) or len(n) < 256:
            raise WebAuthnError("RSA passkeys must be at least 2048 bits.", "UNSUPPORTED_KEY")
        return {"kty": "RSA", "alg": "RS256", "n": b64u(n), "e": b64u(e)}
    if not isinstance(cose, dict) or cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
        raise WebAuthnError("Only ES256 (P-256) and RS256 (RSA) passkeys are supported.", "UNSUPPORTED_KEY")
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(cose[-2]), "y": b64u(cose[-3])}
    try:
        p256.public_point(jwk)
    except p256.InvalidKey as e:
        raise WebAuthnError(str(e), "UNSUPPORTED_KEY") from e
    return jwk


def der_to_raw(sig: bytes) -> bytes:
    """ASN.1 DER ECDSA signature -> 64-byte r||s."""
    try:
        if sig[0] != 0x30:
            raise ValueError
        i = 2 if sig[1] < 0x80 else 2 + (sig[1] & 0x7F)
        parts = []
        for _ in range(2):
            if sig[i] != 0x02:
                raise ValueError
            n = sig[i + 1]
            parts.append(int.from_bytes(sig[i + 2:i + 2 + n], "big"))
            i += 2 + n
        return parts[0].to_bytes(32, "big") + parts[1].to_bytes(32, "big")
    except (IndexError, ValueError, OverflowError) as e:
        raise WebAuthnError("Malformed signature.", "MALFORMED") from e


def _client_data(b64: str, kind: str, challenge: bytes, origins: set[str]) -> bytes:
    raw = unb64u(b64)
    try:
        cd = json.loads(raw)
    except ValueError as e:
        raise WebAuthnError("Malformed client data.", "MALFORMED") from e
    if cd.get("type") != kind:
        raise WebAuthnError("Wrong kind of passkey response.", "WRONG_TYPE")
    if cd.get("challenge") != b64u(challenge):
        raise WebAuthnError("The passkey signed something other than this exact payment.", "CHALLENGE_MISMATCH")
    if cd.get("origin") not in origins:
        raise WebAuthnError("This passkey response came from a different website.", "ORIGIN_MISMATCH")
    return raw


def _check_flags(ad: dict, rp_id: str):
    if ad["rp_id_hash"] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("This passkey belongs to a different website.", "RP_MISMATCH")
    if not ad["flags"] & FLAG_UP:
        raise WebAuthnError("The device did not confirm you were present.", "UP_REQUIRED")
    if not ad["flags"] & FLAG_UV:
        raise WebAuthnError("Your fingerprint / face was not checked on the device.", "UV_REQUIRED")


# ---------------------------------------------------------------- ceremonies
def verify_registration(*, credential_id: str, client_data_json: str, attestation_object: str,
                        challenge: bytes, rp_id: str, origins: set[str]) -> dict:
    _client_data(client_data_json, "webauthn.create", challenge, origins)
    att, _ = cbor_decode(unb64u(attestation_object))
    if not isinstance(att, dict) or "authData" not in att:
        raise WebAuthnError("Malformed attestation.", "MALFORMED")
    ad = parse_auth_data(att["authData"])
    _check_flags(ad, rp_id)
    if "cose_key" not in ad:
        raise WebAuthnError("No credential in the attestation.", "MALFORMED")
    if b64u(ad["credential_id"]) != credential_id:
        raise WebAuthnError("Credential id mismatch.", "MALFORMED")
    return {"credential_id": credential_id, "public_key": cose_to_jwk(ad["cose_key"]), "sign_count": ad["sign_count"],
            "rp_id": rp_id}


def verify_assertion(*, public_key: dict, payload: str, authenticator_data: str, client_data_json: str,
                     signature: str, rp_id: str, origins: set[str], prev_sign_count: int = 0) -> int:
    """Returns the new signCount. The challenge MUST be SHA-256 of the exact payload the server issued."""
    cd_raw = _client_data(client_data_json, "webauthn.get", hashlib.sha256(payload.encode()).digest(), origins)
    ad_raw = unb64u(authenticator_data)
    ad = parse_auth_data(ad_raw)
    _check_flags(ad, rp_id)
    if not verify_signature(public_key, ad_raw + hashlib.sha256(cd_raw).digest(), unb64u(signature)):
        raise WebAuthnError("The passkey signature is not valid.", "INVALID_SIGNATURE")
    if ad["sign_count"] and ad["sign_count"] <= prev_sign_count:
        raise WebAuthnError("This passkey's counter went backwards (possible cloned device).", "COUNTER_REPLAY")
    return ad["sign_count"]


# ---------------------------------------------------------------- a software authenticator (tests and lab only)
def _rsa_keypair(bits: int = 2048):
    """Test-only RSA key (Miller-Rabin primes). Never used to verify anything in production code paths."""
    import secrets as _s

    def prime(nbits):
        while True:
            c = _s.randbits(nbits) | (1 << (nbits - 1)) | 1
            if all(c % p for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)) and all(
                    pow(a, (c - 1) >> (r := ((c - 1) & -(c - 1)).bit_length() - 1), c) in (1, c - 1) or any(
                        pow(a, ((c - 1) >> r) << j, c) == c - 1 for j in range(1, r))
                    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)):
                return c
    e = 65537
    while True:
        p, q = prime(bits // 2), prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e and (p * q).bit_length() == bits:
            return p * q, e, pow(e, -1, phi)


class SoftAuthenticator:
    """Plays a phone's / laptop's secure element in tests: makes real WebAuthn registration and assertion messages.
    alg "ES256" (Touch ID, Face ID, most authenticators) or "RS256" (some Windows Hello set-ups)."""
    def __init__(self, rp_id: str = "localhost", origin: str = "http://localhost:8000", alg: str = "ES256"):
        self.rp_id, self.origin, self.alg = rp_id, origin, alg
        if alg == "RS256":
            self.n, self.e, self.rsa_d = _rsa_keypair()
            nb = self.n.to_bytes(256, "big")
            self.jwk = {"kty": "RSA", "alg": "RS256", "n": b64u(nb), "e": b64u(self.e.to_bytes(3, "big"))}
            self.d = None
        else:
            self.d, self.jwk = p256.generate_keypair()
        self.cred_id = hashlib.sha256(self.jwk.get("x", self.jwk.get("n", "")).encode()).digest()[:16]
        self.count = 0

    def _ad(self, flags: int, extra: bytes = b"", rp_id: str | None = None) -> bytes:
        self.count += 1
        return hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + \
            struct.pack(">I", self.count) + extra

    def register(self, challenge: bytes) -> dict:
        if self.alg == "RS256":
            cose = _cbor_enc({1: 3, 3: -257, -1: unb64u(self.jwk["n"]), -2: unb64u(self.jwk["e"])})
        else:
            x, y = unb64u(self.jwk["x"]), unb64u(self.jwk["y"])
            cose = _cbor_enc({1: 2, 3: -7, -1: 1, -2: x, -3: y})
        att_data = bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + cose
        ad = self._ad(FLAG_UP | FLAG_UV | FLAG_AT, att_data)
        cd = json.dumps({"type": "webauthn.create", "challenge": b64u(challenge), "origin": self.origin}).encode()
        return {"credential_id": b64u(self.cred_id), "client_data_json": b64u(cd),
                "attestation_object": b64u(_cbor_enc({"fmt": "none", "attStmt": {}, "authData": ad}))}

    def sign(self, payload: str, uv: bool = True, rp_id: str | None = None, origin: str | None = None,
             key: int | None = None) -> dict:
        ad = self._ad(FLAG_UP | (FLAG_UV if uv else 0), rp_id=rp_id)
        cd = json.dumps({"type": "webauthn.get", "challenge": b64u(hashlib.sha256(payload.encode()).digest()),
                         "origin": origin or self.origin}).encode()
        msg = ad + hashlib.sha256(cd).digest()
        if self.alg == "RS256":
            t = _SHA256_DIGESTINFO + hashlib.sha256(msg).digest()
            em = b"\x00\x01" + b"\xff" * (256 - len(t) - 3) + b"\x00" + t
            sig = pow(int.from_bytes(em, "big"), self.rsa_d, self.n).to_bytes(256, "big")
            return {"type": "webauthn", "payload": payload, "credential_id": b64u(self.cred_id),
                    "authenticator_data": b64u(ad), "client_data_json": b64u(cd), "signature": b64u(sig)}
        raw = p256.sign(key or self.d, msg)
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")

        def der_int(v):
            b = v.to_bytes(33, "big").lstrip(b"\0")
            b = b"\0" + b if b[0] & 0x80 else b
            return b"\x02" + bytes([len(b)]) + b
        body = der_int(r) + der_int(s)
        return {"type": "webauthn", "payload": payload, "credential_id": b64u(self.cred_id),
                "authenticator_data": b64u(ad), "client_data_json": b64u(cd),
                "signature": b64u(b"\x30" + bytes([len(body)]) + body)}
