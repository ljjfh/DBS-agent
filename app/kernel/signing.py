"""所见即所签（What You See Is What You Sign）。

1. 草稿生成时，对确认卡上的全部字段计算 digest。
2. 用户在设备上完成生物识别后，认证器对“用户看到的 digest”签发一次性授权令牌。
3. 执行器只在 令牌有效 + 未被用过 + 令牌里的 digest == 服务端重新计算的 digest 时才动钱。

Demo 中生物识别用模拟认证器代替；生产环境换成 WebAuthn / Passkey：
设备私钥对 digest 签名，服务端用注册时的公钥验签，接口形状不变。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time

from app.config import settings
from app.models import Draft


def compute_digest(draft: Draft) -> str:
    canon = json.dumps(draft.card_fields(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class MockAuthenticator:
    """模拟设备上的生物识别。真实实现：浏览器 navigator.credentials.get() + 服务端验签。"""
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
                return False, "签名无效"
            payload = json.loads(raw)
        except Exception:
            return False, "令牌格式错误"
        if payload["d"] != draft_id:
            return False, "令牌不属于这笔交易"
        if not hmac.compare_digest(payload["h"], expected_digest):
            return False, "确认内容与执行内容不一致"
        if payload["exp"] < time.time():
            return False, "授权已过期"
        with self._lock:
            if payload["jti"] in self._used:
                return False, "授权已被使用（防重放）"
            self._used.add(payload["jti"])
        return True, "ok"
