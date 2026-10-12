"""HTTP hardening for the local demo server (adapted from a teammate's prototype, Aegis).

* Host allowlist      - only answer to localhost (or ALLOWED_HOSTS): blocks DNS-rebinding attacks
* Same-origin POSTs   - a browser POST with a foreign Origin header is refused: blocks cross-site requests
* JSON only           - POST bodies must be application/json: a plain HTML form can't trigger an API call
* Size limits         - 32 KB for API calls, 3 MB for the speech endpoint
* Security headers    - strict CSP (no inline script, no third-party code), no framing, no sniffing,
                        microphone allowed only for this page

This is a local, single-process demo server. Do not expose it to the internet as-is (see docs/SECURITY.md).
"""
from __future__ import annotations

import json

from app.config import settings

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
       "media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), geolocation=(), microphone=(self)"),
    (b"cache-control", b"no-store"),
]
API_LIMIT, ASR_LIMIT = 32 * 1024, 3 * 1024 * 1024   # 50 s of 16 kHz WAV is ~2.2 MB as base64


class SecurityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        host = headers.get("host", "")
        hostname = host.rsplit(":", 1)[0].lower() if not host.startswith("[") else host.split("]")[0] + "]"
        path, method = scope["path"], scope["method"]

        if hostname not in settings.allowed_hosts:
            return await self._deny(send, 403, "INVALID_HOST",
                                    "Open the app via localhost (or add this host to ALLOWED_HOSTS).")
        if method == "POST":
            origin = headers.get("origin")
            if origin and origin not in (f"http://{host}", f"https://{host}"):
                return await self._deny(send, 403, "ORIGIN", "Cross-site requests are not allowed.")
            if not headers.get("content-type", "").startswith("application/json"):
                return await self._deny(send, 415, "CONTENT_TYPE", "JSON is required.")
            limit = ASR_LIMIT if path == "/api/asr" else API_LIMIT
            try:
                length = int(headers.get("content-length", "0"))
            except ValueError:
                length = limit + 1
            if length > limit:
                return await self._deny(send, 413, "TOO_LARGE", "Request is too large.")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [(k, v) for k, v in HEADERS if k not in existing]
            await send(message)

        await self.app(scope, receive, send_with_headers)

    @staticmethod
    async def _deny(send, status: int, code: str, msg: str):
        body = json.dumps({"error": msg, "code": code}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                *HEADERS]})
        await send({"type": "http.response.body", "body": body})
