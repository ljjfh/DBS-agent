"""HTTP tests: start the real server on a free local port (offline model, temp audit log) and probe it with requests.

Covers the hardening middleware (host allowlist, same-origin POST, JSON-only, size limits, security headers),
the static-file allowlist (source code and .env can never be fetched) and the dashboard API.
Run: python -m unittest discover tests
"""
import os
import socket
import tempfile
import threading
import time
import unittest

_TMP = tempfile.TemporaryDirectory()
os.environ["LLM_PROVIDER"] = "offline"          # never call a real model or ASR from tests
os.environ["TENCENTCLOUD_SECRET_ID"] = ""
os.environ["TENCENTCLOUD_SECRET_KEY"] = ""
os.environ["AUDIT_PATH"] = os.path.join(_TMP.name, "audit.jsonl")
os.environ["PASSKEY_PATH"] = os.path.join(_TMP.name, "passkeys.json")
os.environ.setdefault("RULE_FIXED_HOUR", "14")

import requests  # noqa: E402
import uvicorn  # noqa: E402

from app.server import app  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="warning"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            try:
                requests.get(cls.base + "/api/health", timeout=0.5)
                break
            except requests.ConnectionError:
                time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=5)

    def post(self, path, body=None, **kw):
        return requests.post(self.base + path, json=body if body is not None else {}, timeout=10, **kw)

    def test_reset_after_a_server_restart_starts_a_new_session(self):
        """A browser still holding a session the server forgot (redeploy) gets a fresh one, not an error."""
        r = self.post("/api/reset", {"session_id": "f" * 32, "world": True, "visitor": "0123456789abcdef"})
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["session_id"]
        self.assertNotEqual(sid, "f" * 32)
        self.assertEqual(self.post("/api/chat", {"session_id": sid, "text": "Send 50 to my daughter"}).status_code, 200)

    # ---- static files ----
    def test_page_and_assets(self):
        r = requests.get(self.base + "/", headers={"Host": f"localhost:{self.port}"})
        self.assertEqual(r.status_code, 200)
        self.assertIn('src="/app.js"', r.text)
        for path, mime in [("/app.js", "text/javascript"), ("/styles.css", "text/css"),
                           ("/dbs-logo.svg", "image/svg+xml"), ("/favicon.svg", "image/svg+xml")]:
            r = requests.get(self.base + path)
            self.assertEqual(r.status_code, 200, path)
            self.assertTrue(r.headers["content-type"].startswith(mime), path)

    def test_loopback_ip_redirects_to_localhost(self):
        """Passkeys can't use an IP address, so http://127.0.0.1:PORT/ sends the browser to http://localhost:PORT/."""
        r = requests.get(self.base + "/", allow_redirects=False)
        self.assertEqual(r.status_code, 307)
        self.assertEqual(r.headers["location"], f"http://localhost:{self.port}/")

    def test_source_and_secrets_never_served(self):
        for path in ["/.env", "/app/config.py", "/web/app.js", "/data/audit.jsonl", "/../.env", "/index.html.bak"]:
            self.assertEqual(requests.get(self.base + path).status_code, 404, path)

    # ---- hardening ----
    def test_security_headers(self):
        h = requests.get(self.base + "/", allow_redirects=False).headers
        self.assertIn("script-src 'self'", h["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", h["content-security-policy"])
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertEqual(h["x-frame-options"], "DENY")
        self.assertEqual(h["cache-control"], "no-store")

    def test_unknown_host_refused(self):
        r = requests.get(self.base + "/api/health", headers={"Host": "evil.example"})
        self.assertEqual((r.status_code, r.json()["code"]), (403, "INVALID_HOST"))

    def test_cross_site_post_refused(self):
        r = self.post("/api/reset", headers={"Origin": "https://evil.example"})
        self.assertEqual((r.status_code, r.json()["code"]), (403, "ORIGIN"))
        ok = self.post("/api/reset", headers={"Origin": self.base})
        self.assertEqual(ok.status_code, 200)

    def test_form_post_refused(self):
        r = requests.post(self.base + "/api/chat", data={"text": "pay 10 to my daughter"})
        self.assertEqual((r.status_code, r.json()["code"]), (415, "CONTENT_TYPE"))

    def test_oversized_post_refused(self):
        r = self.post("/api/chat", {"text": "x" * 40_000})
        self.assertEqual((r.status_code, r.json()["code"]), (413, "TOO_LARGE"))

    # ---- API ----
    def test_state_and_chat(self):
        sid = self.post("/api/reset", {"world": True}).json()["session_id"]
        st = requests.get(self.base + "/api/state", params={"session_id": sid}).json()
        self.assertEqual(st["phase"], "IDLE")
        self.assertGreaterEqual(len(st["accounts"]), 2)
        self.assertTrue(st["total_balance"].startswith("S$"))
        self.assertFalse(st["device_key"])
        self.assertTrue(all("masked_account" in p for p in st["payees"]))

        r = self.post("/api/chat", {"session_id": sid, "text": "Send 50 to my daughter"}).json()
        self.assertEqual(r["ui"]["type"], "confirm")
        self.assertEqual(r["ui"]["card"]["amount"], "S$50.00")
        # nothing moved: the agent can only draft
        after = requests.get(self.base + "/api/state", params={"session_id": sid}).json()
        self.assertEqual(after["total_balance"], st["total_balance"])

    def test_confirm_without_signature_rejected(self):
        sid = self.post("/api/reset", {"world": True}).json()["session_id"]
        card = self.post("/api/chat", {"session_id": sid, "text": "Send 50 to my daughter"}).json()["ui"]["card"]
        r = self.post("/api/confirm", {"session_id": sid, "draft_id": card["draft_id"], "digest": card["digest"],
                                       "assertion": "demo-fingerprint"})
        self.assertEqual(r.status_code, 400)
        # a missing field or malformed JSON is a clean 400, never a server error
        self.assertEqual(self.post("/api/confirm", {"session_id": sid}).status_code, 400)
        bad = requests.post(self.base + "/api/confirm", data="{not json", timeout=5,
                            headers={"Content-Type": "application/json"})
        self.assertEqual((bad.status_code, bad.json()["code"]), (400, "BAD_REQUEST"))
        st = requests.get(self.base + "/api/state", params={"session_id": sid}).json()
        self.assertEqual(st["receipts"], [])

    def test_passkey_enrolment_and_payment_over_http(self):
        from app.kernel import webauthn
        sid = self.post("/api/reset", {"world": True}).json()["session_id"]
        auth = webauthn.SoftAuthenticator(rp_id="127.0.0.1", origin=self.base)
        opts = self.post("/api/passkey/options", {"session_id": sid}).json()
        self.assertEqual(opts["rp_id"], "127.0.0.1")
        reg = self.post("/api/passkey/register", {"session_id": sid, **auth.register(webauthn.unb64u(opts["challenge"]))})
        self.assertEqual(reg.status_code, 200, reg.text)
        card = self.post("/api/chat", {"session_id": sid, "text": "Send 50 to my daughter"}).json()["ui"]["card"]
        ch = self.post("/api/challenge", {"session_id": sid, "draft_id": card["draft_id"], "digest": card["digest"]}).json()
        self.assertTrue(ch["passkey"]["enrolled"])
        r = self.post("/api/confirm", {"session_id": sid, "draft_id": card["draft_id"], "digest": card["digest"],
                                       "assertion": auth.sign(ch["payload"])})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["receipt"]["verifiable"]["authorization"]["method"], "passkey")
        self.post("/api/passkey/remove", {"session_id": sid})

    def test_model_mistake_demo_is_frozen(self):
        sid = self.post("/api/reset", {"world": True}).json()["session_id"]
        r = self.post("/api/demo/model-mistake", {"session_id": sid}).json()
        self.assertEqual(r["ui"]["type"], "frozen")
        self.assertEqual(r["ui"]["card"]["verification"]["status"], "mismatch")

    def test_protection_lowering_needs_signature(self):
        sid = self.post("/api/reset", {"world": True}).json()["session_id"]
        r = self.post("/api/protection", {"session_id": sid, "to": "standard"})
        self.assertEqual(r.status_code, 400)
        st = requests.get(self.base + "/api/state", params={"session_id": sid}).json()
        self.assertEqual(st["protection"]["level"], "enhanced")

    def test_cancel_offers_the_queued_request(self):
        sid = self.post("/api/reset", {"world": True}).json()["session_id"]
        card = self.post("/api/chat", {"session_id": sid, "text": "Send 50 to my daughter"}).json()["ui"]["card"]
        again = self.post("/api/chat", {"session_id": sid, "text": "Send 500 to my son"}).json()
        self.assertEqual(again["ui"]["card"]["draft_id"], card["draft_id"])
        r = self.post("/api/cancel", {"session_id": sid, "draft_id": card["draft_id"]}).json()
        self.assertEqual(r["next_task"], "Send 500 to my son")

    def test_history_never_has_two_assistant_turns_in_a_row(self):
        from app import runtime
        sid = self.post("/api/reset", {"world": True}).json()["session_id"]
        card = self.post("/api/chat", {"session_id": sid, "text": "Send 50 to my daughter"}).json()["ui"]["card"]
        self.post("/api/cancel", {"session_id": sid, "draft_id": card["draft_id"]})
        roles = [m["role"] for m in runtime.sessions.get(sid).messages]
        self.assertFalse(any(a == b == "assistant" for a, b in zip(roles, roles[1:])), roles)

    def test_visitors_are_isolated(self):
        """Online demo: two browsers (visitors) are two separate demo customers. One's payment, reset or passkey
        never shows up for the other."""
        from app import runtime
        from app.kernel import webauthn
        a = self.post("/api/reset", {"visitor": "aaaaaaaaaaaaaaaa"}).json()["session_id"]
        b = self.post("/api/reset", {"visitor": "bbbbbbbbbbbbbbbb"}).json()["session_id"]
        self.assertNotEqual(a, b)
        self.assertNotIn("aaaaaaaaaaaaaaaa", a)  # server-generated, opaque session capability
        ua, ub = runtime.sessions.get(a).user_id, runtime.sessions.get(b).user_id
        self.assertNotEqual(ua, ub)
        runtime.bank.account(ua, "SAV-001")["balance_cents"] = 1_00          # A's world changes...
        self.assertEqual(runtime.bank.account(ub, "SAV-001")["balance_cents"], 325000)   # ...B's doesn't
        # A enrols a passkey: B is unaffected and can still enrol their own
        auth = webauthn.SoftAuthenticator(rp_id="127.0.0.1", origin=self.base)
        opts = self.post("/api/passkey/options", {"session_id": a}).json()
        self.assertEqual(self.post("/api/passkey/register", {"session_id": a, **auth.register(
            webauthn.unb64u(opts["challenge"]))}).status_code, 200)
        st_b = requests.get(self.base + "/api/state", params={"session_id": b}).json()
        self.assertFalse(st_b["passkey"]["enrolled"])
        # A resets their world: only A's balance comes back, B's session and world are untouched
        runtime.bank.account(ub, "SAV-001")["balance_cents"] = 2_00
        a2 = self.post("/api/reset", {"visitor": "aaaaaaaaaaaaaaaa", "session_id": a, "world": True}).json()["session_id"]
        self.assertEqual(runtime.bank.account(runtime.sessions.get(a2).user_id, "SAV-001")["balance_cents"], 325000)
        self.assertEqual(runtime.bank.account(ub, "SAV-001")["balance_cents"], 2_00)
        # Identity comes from the server-owned binding, never a client-controlled prefix
        runtime.sessions._s.pop(b)
        self.assertEqual(runtime.sessions.get(b).user_id, ub)
        # junk visitor ids are ignored
        junk = self.post("/api/reset", {"visitor": "../../etc"}).json()["session_id"]
        self.assertEqual(runtime.sessions.get(junk).user_id, "u_chen")

    def test_platform_hostnames_are_allowed(self):
        from unittest import mock
        from app import config
        with mock.patch.dict(os.environ, {"RENDER_EXTERNAL_HOSTNAME": "star.onrender.com",
                                          "PUBLIC_HOST": "https://demo.example.com/", "FLY_APP_NAME": "star"}):
            hosts = config._hosts()
        for h in ["localhost", "star.onrender.com", "demo.example.com", "star.fly.dev"]:
            self.assertIn(h, hosts)

    def test_audit_endpoints(self):
        sid = self.post("/api/reset", {}).json()["session_id"]
        self.post("/api/chat", {"session_id": sid, "text": "What's my balance?"})
        v = requests.get(self.base + "/api/audit/verify").json()
        self.assertTrue(v["ok"])
        s = requests.get(self.base + f"/api/audit/session/{sid}").json()
        self.assertTrue(s["integrity"]["ok"])
        self.assertTrue(s["entries"])


if __name__ == "__main__":
    unittest.main()
