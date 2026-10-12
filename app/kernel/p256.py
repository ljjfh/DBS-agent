"""ECDSA P-256 (secp256r1) with SHA-256 - just enough to verify browser Web Crypto signatures.

Why it exists: the browser keeps a NON-EXTRACTABLE private key (Web Crypto, IndexedDB) and signs the exact
authorization payload; the server only ever sees the public key. That is the same shape as a Passkey.

* verify() is what the server uses. If the `cryptography` package is installed it is used instead; otherwise
  this small pure-Python implementation is used, so the project needs no extra dependency.
* sign() / generate_keypair() exist only for tests and the security lab (they play the "user's device").
  Not constant-time: never use them to protect real secrets.

Signatures are IEEE P1363 (r || s, 64 bytes) - the format Web Crypto produces. Public keys are JWK.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

# Curve parameters (FIPS 186-4, P-256)
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


class InvalidKey(ValueError):
    pass


# ---------------------------------------------------------------- point arithmetic (Jacobian coordinates)
def _to_jac(pt):
    return (pt[0], pt[1], 1)


def _from_jac(pt):
    x, y, z = pt
    if z == 0:
        return None
    zi = pow(z, -1, P)
    zi2 = zi * zi % P
    return (x * zi2 % P, y * zi2 * zi % P)


def _double(pt):
    x, y, z = pt
    if z == 0 or y == 0:
        return (0, 1, 0)
    ysq = y * y % P
    s = 4 * x * ysq % P
    m = (3 * x * x + A * pow(z, 4, P)) % P
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * ysq * ysq) % P
    nz = 2 * y * z % P
    return (nx, ny, nz)


def _add(p1, p2):
    if p1[2] == 0:
        return p2
    if p2[2] == 0:
        return p1
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    z1s, z2s = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2s % P, x2 * z1s % P
    s1, s2 = y1 * z2s * z2 % P, y2 * z1s * z1 % P
    if u1 == u2:
        return _double(p1) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % P, (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    u1h2 = u1 * h2 % P
    nx = (r * r - h3 - 2 * u1h2) % P
    ny = (r * (u1h2 - nx) - s1 * h3) % P
    nz = h * z1 * z2 % P
    return (nx, ny, nz)


def _mul(k, pt):
    result, addend = (0, 1, 0), _to_jac(pt)
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _double(addend)
        k >>= 1
    return result


def _on_curve(pt) -> bool:
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


# ---------------------------------------------------------------- encoding helpers
def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def public_point(jwk: dict) -> tuple[int, int]:
    """Validate a public JWK and return the curve point. Rejects private keys, wrong curves and off-curve points."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise InvalidKey("A public P-256 key (JWK) is required.")
    try:
        x = int.from_bytes(_b64u_dec(jwk["x"]), "big")
        y = int.from_bytes(_b64u_dec(jwk["y"]), "big")
    except Exception as e:  # noqa: BLE001
        raise InvalidKey("Malformed public key.") from e
    if not _on_curve((x, y)):
        raise InvalidKey("Public key is not on the P-256 curve.")
    return (x, y)


def key_fingerprint(jwk: dict) -> str:
    """Short, stable id of a public key (shown on receipts)."""
    x, y = public_point(jwk)
    return hashlib.sha256(x.to_bytes(32, "big") + y.to_bytes(32, "big")).hexdigest()[:16]


# ---------------------------------------------------------------- verify
def verify(jwk: dict, message: bytes, signature: bytes) -> bool:
    """True only if `signature` (64-byte r||s) over `message` was made by the private half of `jwk`."""
    try:
        q = public_point(jwk)
    except InvalidKey:
        return False
    if len(signature) != 64:
        return False
    try:   # use the audited library when it is available
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        pub = ec.EllipticCurvePublicNumbers(q[0], q[1], ec.SECP256R1()).public_key()
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        try:
            pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    except ImportError:
        pass
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, N)
    pt = _from_jac(_add(_mul(e * w % N, G), _mul(r * w % N, q)))
    return pt is not None and pt[0] % N == r


# ---------------------------------------------------------------- test / lab helpers (the "user's device")
def generate_keypair() -> tuple[int, dict]:
    d = secrets.randbelow(N - 1) + 1
    x, y = _from_jac(_mul(d, G))
    return d, {"kty": "EC", "crv": "P-256", "x": _b64u_enc(x.to_bytes(32, "big")),
               "y": _b64u_enc(y.to_bytes(32, "big")), "ext": True}


def sign(d: int, message: bytes) -> bytes:
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        # deterministic-but-unique nonce (RFC 6979 style simplification) - fine for tests, not for production
        k = int.from_bytes(hmac.new(d.to_bytes(32, "big"), message + secrets.token_bytes(16),
                                    hashlib.sha256).digest(), "big") % N
        if not k:
            continue
        r = _from_jac(_mul(k, G))[0] % N
        if not r:
            continue
        s = pow(k, -1, N) * (e + r * d) % N
        if s:
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
