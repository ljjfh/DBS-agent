"""HTTP API (Starlette). Run: uvicorn app.server:app --reload --port 8000

Money only moves through /api/confirm, which needs a signature made by the user's own device key over the exact
challenge issued for the card they saw (/api/key -> /api/challenge -> sign in the browser -> /api/confirm).
The Agent (model) has no way to call any of these.
"""
from __future__ import annotations

import base64
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.middleware import Middleware
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from app import lab, runtime
from app.agent import presenter
from app.bank.mock_bank import DEMO_USER
from app.config import ROOT, settings
from app.kernel import protection as prot
from app.kernel.executor import KernelError
from app.kernel.signing import Site
from app.kernel.state import valid_visitor
from app.models import fmt_money
from app.security import SecurityMiddleware
from app.voice import asr


def _err(msg: str, code: str = "BAD_REQUEST", status: int = 400) -> JSONResponse:
    return JSONResponse({"error": msg, "code": code}, status_code=status)


class BadInput(Exception):
    pass


async def _json(request: Request, *required: str) -> dict:
    """Parse a JSON object body; missing fields or malformed JSON become a clean 400, never a 500."""
    try:
        body = await request.json()
    except ValueError:
        raise BadInput("Body must be valid JSON.")
    if not isinstance(body, dict):
        raise BadInput("Body must be a JSON object.")
    missing = [k for k in required if not isinstance(body.get(k), str) or not body.get(k)]
    if missing:
        raise BadInput(f"Missing field(s): {', '.join(missing)}")
    return body


async def _bad_input(_: Request, exc: BadInput):
    return _err(str(exc), "BAD_REQUEST", 400)


def _say(s, text: str) -> None:
    """Add a system message (receipt, cancel) to the history without creating two assistant turns in a row, which
    some model servers handle badly: merge it into the previous assistant message."""
    if s.messages and s.messages[-1]["role"] == "assistant":
        s.messages[-1] = {**s.messages[-1], "content": s.messages[-1]["content"] + "\n" + text}
    else:
        s.messages.append({"role": "assistant", "content": text})


def _site(request: Request) -> Site:
    """The passkey's website = the host the browser used (the middleware already restricts it to ALLOWED_HOSTS)."""
    host = request.headers.get("host", "localhost")
    rp_id = host.split("]")[0].lstrip("[") if host.startswith("[") else host.rsplit(":", 1)[0]
    return Site(rp_id.lower(), frozenset({f"http://{host}", f"https://{host}"}))


async def index(request: Request):
    # Passkeys (fingerprint / face) only work on a domain name, never an IP address. uvicorn prints
    # http://127.0.0.1:8000, so send loopback-IP visitors to the same server under "localhost".
    host = request.headers.get("host", "")
    name, _, port = host.rpartition(":") if not host.endswith("]") else (host, "", "")
    if (name or host) in ("127.0.0.1", "[::1]") and "localhost" in settings.allowed_hosts:
        return RedirectResponse(f"http://localhost{':' + port if port else ''}/", status_code=307)
    return FileResponse(ROOT / "web" / "index.html")


# Only these files are ever served: source code and .env can never be fetched.
STATIC = {"/styles.css": ("styles.css", "text/css"), "/app.js": ("app.js", "text/javascript"),
          "/dbs-logo.svg": ("dbs-logo.svg", "image/svg+xml"), "/favicon.svg": ("favicon.svg", "image/svg+xml")}


async def static(request: Request):
    name, mime = STATIC[request.url.path]
    return Response((ROOT / "web" / name).read_bytes(), media_type=mime + ("; charset=utf-8" if "svg" not in mime else ""))


async def state(request: Request):
    """Everything the dashboard shows: accounts, payees, bills, history, this session's receipts and status."""
    s = runtime.sessions.get(request.query_params.get("session_id"))
    bank, uid = runtime.bank, s.user_id
    user = bank.user(uid)
    return JSONResponse({
        "session_id": s.session_id, "phase": s.phase.value, "user": user["name"],
        "accounts": [{**a, "balance": fmt_money(a["balance_cents"])} for a in bank.accounts(uid)],
        "total_balance": fmt_money(sum(a["balance_cents"] for a in bank.accounts(uid))),
        "payees": [{k: p[k] for k in ("payee_id", "name", "relation", "type", "masked_account")}
                   for p in bank.payees(uid)],
        "bills": [{**b, "amount": fmt_money(b["amount_cents"])} for b in bank.bills(uid, only_unpaid=False)],
        "transactions": [{**t, "amount": ("+" if t["amount_cents"] > 0 else "−") + fmt_money(abs(t["amount_cents"]))}
                         for t in bank.transactions(uid, limit=30)],
        "receipts": s.receipts,
        "device_key": bool(s.public_key),
        "passkey": runtime.kernel.passkey_status(s.user_id, _site(request)),
        "protection": prot.status(bank, uid),
        "risk_profile": bank.risk_profile(uid)["label"],
        "holdings": [{"name": r["name"], "asset_class": r["asset_class"], "units": round(r["units"], 2),
                      "value": fmt_money(r["value_cents"]), "gain_cents": r["gain_cents"],
                      "gain": ("+" if r["gain_cents"] >= 0 else "−") + fmt_money(abs(r["gain_cents"]))}
                     for r in bank.portfolio(uid)],
        "cards": [{k: c[k] for k in ("card_id", "name", "masked", "status")} for c in bank.cards(uid)],
        "limits": {"daily": fmt_money(bank.limits(uid)["daily_transfer_cents"]),
                   "used_today": fmt_money(bank.transferred_today(uid)),
                   "pending": (fmt_money(bank.limits(uid)["pending"]["to_cents"]) if bank.limits(uid).get("pending") else None)},
        "standing_instructions": [{"si_id": x["si_id"], "to": (bank.payee(uid, x["payee_id"]) or {}).get("name", ""),
                                   "amount": fmt_money(x["amount_cents"]), "frequency": x["frequency"], "day": x["day"],
                                   "next": x["next_date"]}
                                  for x in bank.standing_instructions(uid) if x["status"] == "active"],
        "giro": [{"giro_id": g["giro_id"], "biller": g["biller"], "status": g["status"],
                  "max": fmt_money(g["limit_cents"]) if g.get("limit_cents") else "Each bill"}
                 for g in bank.giro(uid) if g["status"] != "cancelled"],
        "pending_change": (s.pending_change or {}).get("card"),
        "scam_level": s.scam_level.value,
    })


async def audit_export(request: Request):
    s = runtime.sessions.get(request.path_params["session_id"])
    return JSONResponse({"session_id": s.session_id, "integrity": runtime.audit.verify(),
                         "entries": runtime.audit.for_session(s.session_id)})


async def health(_: Request):
    return JSONResponse({"llm": getattr(runtime.llm, "name", "?"), "model": settings.llm_model if settings.llm_enabled
                         else "offline-rules", "asr": "tencent" if settings.asr_enabled else "browser-fallback",
                         "verifier": runtime.verifier.name, "public_demo": settings.public_demo,
                         "browser_key": settings.allow_browser_key})


async def world(request: Request):
    s = runtime.sessions.get(request.query_params.get("session_id"))
    a = runtime.bank.accounts(s.user_id)[0]
    return JSONResponse({"user": runtime.bank.user(s.user_id)["name"], "account": a["name"],
                         "balance": fmt_money(a["balance_cents"]), "phase": s.phase.value})


async def chat(request: Request):
    body = await _json(request)
    text = (body.get("text") or "").strip()
    if not text:
        return _err("text must not be empty")
    s = runtime.sessions.get(body.get("session_id"))
    result = runtime.agent.run_turn(s, text[:500])
    return JSONResponse({"session_id": s.session_id, "phase": s.phase.value, **result.to_dict()})


async def speech_to_text(request: Request):
    body = await _json(request)
    if not settings.asr_enabled:
        return _err("Tencent Cloud ASR is not configured on the server; the frontend will use browser speech recognition.", "ASR_DISABLED", 501)
    try:
        wav = base64.b64decode(body["audio_b64"])
    except Exception:  # noqa: BLE001
        return _err("audio_b64 is not valid base64")
    s = runtime.sessions.get(body.get("session_id"))
    hot = asr.build_hotwords(runtime.bank.payees(s.user_id))
    try:
        res = asr.recognize(wav, engine=body.get("engine"), hotwords=hot)
    except asr.ASRError as e:
        return _err(str(e), "ASR_ERROR", 502)
    s.add_trace("asr", f"Speech recognition ({res['engine']}, {res['latency_ms']}ms): {res['text']}")
    return JSONResponse(res)


async def register_key(request: Request):
    body = await _json(request)
    s = runtime.sessions.get(body.get("session_id"))
    try:
        key_id = runtime.kernel.register_key(s, body.get("public_key"))
    except KernelError as e:
        return _err(str(e), e.code)
    return JSONResponse({"key_id": key_id})


async def challenge(request: Request):
    body = await _json(request, "draft_id", "digest")
    s = runtime.sessions.get(body.get("session_id"))
    try:
        payload = runtime.kernel.issue_challenge(s, body["draft_id"], body["digest"],
                                                 verify_answer=body.get("verify_answer"))
    except KernelError as e:
        return JSONResponse({"error": str(e), "code": e.code}, status_code=400)
    return JSONResponse({"payload": payload, "passkey": runtime.kernel.passkey_status(s.user_id, _site(request))})


async def passkey_options(request: Request):
    body = await _json(request)
    s = runtime.sessions.get(body.get("session_id"))
    return JSONResponse(runtime.kernel.passkey_options(s, _site(request)))


async def passkey_register(request: Request):
    body = await _json(request, "credential_id", "client_data_json", "attestation_object")
    s = runtime.sessions.get(body.get("session_id"))
    try:
        key_id = runtime.kernel.passkey_register(s, _site(request), body["credential_id"], body["client_data_json"],
                                                 body["attestation_object"])
    except KernelError as e:
        return _err(str(e), e.code)
    return JSONResponse({"key_id": key_id, **runtime.kernel.passkey_status(s.user_id, _site(request))})


async def passkey_remove(request: Request):
    body = await _json(request)
    s = runtime.sessions.get(body.get("session_id"))
    return JSONResponse({"removed": runtime.kernel.passkey_remove(s, _site(request))})


async def protection_challenge(request: Request):
    body = await _json(request, "to")
    s = runtime.sessions.get(body.get("session_id"))
    try:
        payload = runtime.kernel.protection_challenge(s, body["to"])
    except KernelError as e:
        return _err(str(e), e.code)
    return JSONResponse({"payload": payload, "passkey": runtime.kernel.passkey_status(s.user_id, _site(request))})


async def protection_change(request: Request):
    body = await _json(request, "to")
    s = runtime.sessions.get(body.get("session_id"))
    try:
        st = runtime.kernel.change_protection(s, body["to"], body.get("assertion"), _site(request))
    except KernelError as e:
        return _err(str(e), e.code)
    return JSONResponse(st)


# ---- Account changes (add payee, raise limit, set up GIRO): signed on the device like a payment
async def change_challenge(request: Request):
    body = await _json(request, "change_id")
    s = runtime.sessions.get(body.get("session_id"))
    try:
        payload = runtime.kernel.change_challenge(s, body["change_id"])
    except KernelError as e:
        return _err(str(e), e.code)
    return JSONResponse({"payload": payload, "passkey": runtime.kernel.passkey_status(s.user_id, _site(request))})


async def change_confirm(request: Request):
    body = await _json(request, "change_id")
    s = runtime.sessions.get(body.get("session_id"))
    start = len(s.trace)
    try:
        out = runtime.kernel.apply_change(s, body["change_id"], body.get("assertion"), _site(request))
    except KernelError as e:
        return JSONResponse({"error": str(e), "code": e.code, "trace": s.trace[start:]}, status_code=400)
    _say(s, out["reply"])
    next_task = s.plan.pop(0) if s.plan else None
    return JSONResponse({"reply": out["reply"], "speak": out["reply"], "method": out["method"], "next_task": next_task,
                         "trace": s.trace[start:]})


async def change_cancel(request: Request):
    body = await _json(request, "change_id")
    s = runtime.sessions.get(body.get("session_id"))
    try:
        runtime.kernel.cancel_change(s, body["change_id"])
    except KernelError as e:
        return _err(str(e), e.code)
    msg = "OK, cancelled. Nothing was changed."
    _say(s, msg)
    return JSONResponse({"reply": msg, "speak": msg})


async def demo_model_mistake(request: Request):
    """Live demo: one turn with a model that writes the wrong amount, through the REAL verifier, kernel and gateway."""
    from app.agent.loop import Agent
    body = await _json(request)
    s = runtime.sessions.get(body.get("session_id"))
    text = (body.get("text") or "Send 50 to my daughter").strip()[:200]
    result = Agent(runtime.bank, runtime.gateway, runtime.audit, lab.MistakenLLM()).run_turn(s, text)
    return JSONResponse({"session_id": s.session_id, "phase": s.phase.value, **result.to_dict()})


async def run_security_lab(_: Request):
    return JSONResponse({"results": lab.run_lab()})


async def confirm(request: Request):
    body = await _json(request, "draft_id", "digest")
    s = runtime.sessions.get(body.get("session_id"))
    start = len(s.trace)
    try:
        token = runtime.kernel.authorize(s, body["draft_id"], body["digest"], body.get("assertion", ""),
                                         verify_answer=body.get("verify_answer"), site=_site(request))
        receipt = runtime.kernel.commit(s, body["draft_id"], token)
    except KernelError as e:
        return JSONResponse({"error": str(e), "code": e.code, "trace": s.trace[start:]}, status_code=400)
    draft = s.drafts[body["draft_id"]]
    if receipt.get("verifiable"):
        s.receipts.insert(0, receipt["verifiable"])
    text = presenter.receipt_text(draft, receipt)
    _say(s, text)
    s.settle()
    next_task = s.plan.pop(0) if s.plan else None
    return JSONResponse({"receipt": receipt, "reply": text, "speak": text, "next_task": next_task,
                         "trace": s.trace[start:], "phase": s.phase.value})


async def cancel(request: Request):
    body = await _json(request, "draft_id")
    s = runtime.sessions.get(body.get("session_id"))
    try:
        runtime.kernel.cancel(s, body["draft_id"], reason=body.get("reason", "user"))
    except KernelError as e:
        return _err(str(e), e.code)
    s.settle()
    msg = "OK, it's cancelled. No money was sent."
    _say(s, msg)
    next_task = s.plan.pop(0) if s.plan else None      # offered as a button, never run automatically
    return JSONResponse({"reply": msg, "speak": msg, "phase": s.phase.value, "next_task": next_task})


async def current_card(request: Request):
    s = runtime.sessions.get(request.path_params["session_id"])
    d = s.current_draft
    if not d:
        return JSONResponse({"card": None, "phase": s.phase.value})
    # once the cooling-off period ends, move to awaiting authorization
    runtime.kernel._refresh_cooling(s, d)  # noqa: SLF001
    return JSONResponse({"card": presenter.build_card(d, runtime.bank, s.phase), "phase": s.phase.value})


async def trace(request: Request):
    s = runtime.sessions.get(request.path_params["session_id"])
    return JSONResponse({"trace": s.trace, "audit": runtime.audit.for_session(s.session_id)[-50:]})


async def audit_verify(_: Request):
    return JSONResponse(runtime.audit.verify())


async def reset(request: Request):
    body = await _json(request)
    sid = body.get("session_id")
    visitor = valid_visitor(body.get("visitor"))
    if visitor:
        # Online demo: this browser's own demo customer. "Reset demo" resets only their world, never anyone else's;
        # their passkey stays enrolled.
        s = runtime.sessions.new_for_visitor(visitor)
        if body.get("world"):
            runtime.bank.reset_user(s.user_id)
    else:
        if body.get("world"):
            if settings.public_demo:
                runtime.bank.reset_user(DEMO_USER)     # a shared server never wipes every visitor at once
            else:
                runtime.bank.reset()
        s = runtime.sessions.reset(sid) if sid else runtime.sessions.get(None)
    return JSONResponse({"session_id": s.session_id, "ts": time.time()})


routes = [
    Route("/", index),
    *[Route(path, static) for path in STATIC],
    Route("/api/state", state),
    Route("/api/audit/session/{session_id}", audit_export),
    Route("/api/health", health),
    Route("/api/world", world),
    Route("/api/chat", chat, methods=["POST"]),
    Route("/api/asr", speech_to_text, methods=["POST"]),
    Route("/api/key", register_key, methods=["POST"]),
    Route("/api/challenge", challenge, methods=["POST"]),
    Route("/api/confirm", confirm, methods=["POST"]),
    Route("/api/passkey/options", passkey_options, methods=["POST"]),
    Route("/api/passkey/register", passkey_register, methods=["POST"]),
    Route("/api/passkey/remove", passkey_remove, methods=["POST"]),
    Route("/api/protection/challenge", protection_challenge, methods=["POST"]),
    Route("/api/change/challenge", change_challenge, methods=["POST"]),
    Route("/api/change/confirm", change_confirm, methods=["POST"]),
    Route("/api/change/cancel", change_cancel, methods=["POST"]),
    Route("/api/protection", protection_change, methods=["POST"]),
    Route("/api/lab", run_security_lab, methods=["POST"]),
    Route("/api/demo/model-mistake", demo_model_mistake, methods=["POST"]),
    Route("/api/cancel", cancel, methods=["POST"]),
    Route("/api/card/{session_id}", current_card),
    Route("/api/trace/{session_id}", trace),
    Route("/api/audit/verify", audit_verify),
    Route("/api/reset", reset, methods=["POST"]),
]

app = Starlette(routes=routes, middleware=[Middleware(SecurityMiddleware)],
                exception_handlers={BadInput: _bad_input})
