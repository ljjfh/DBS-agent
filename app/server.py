"""HTTP 接口（Starlette）。启动：uvicorn app.server:app --reload --port 8000

前端只能通过 /api/confirm 触发执行，而这个接口要求：用户看到的 digest + 生物识别断言。
Agent（模型）没有任何途径调用它。
"""
from __future__ import annotations

import base64
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from app import runtime
from app.agent import presenter
from app.config import ROOT, settings
from app.kernel.executor import KernelError
from app.models import fmt_money
from app.voice import asr


def _err(msg: str, code: str = "BAD_REQUEST", status: int = 400) -> JSONResponse:
    return JSONResponse({"error": msg, "code": code}, status_code=status)


async def index(_: Request):
    return FileResponse(ROOT / "web" / "index.html")


async def health(_: Request):
    return JSONResponse({"llm": getattr(runtime.llm, "name", "?"), "model": settings.llm_model if settings.llm_enabled
                         else "offline-rules", "asr": "tencent" if settings.asr_enabled else "browser-fallback"})


async def world(request: Request):
    s = runtime.sessions.get(request.query_params.get("session_id"))
    a = runtime.bank.accounts(s.user_id)[0]
    return JSONResponse({"user": runtime.bank.user(s.user_id)["name"], "account": a["name"],
                         "balance": fmt_money(a["balance_cents"]), "phase": s.phase.value})


async def chat(request: Request):
    body = await request.json()
    text = (body.get("text") or "").strip()
    if not text:
        return _err("text 不能为空")
    s = runtime.sessions.get(body.get("session_id"))
    result = runtime.agent.run_turn(s, text[:500])
    return JSONResponse({"session_id": s.session_id, "phase": s.phase.value, **result.to_dict()})


async def speech_to_text(request: Request):
    body = await request.json()
    if not settings.asr_enabled:
        return _err("服务器未配置腾讯云 ASR，前端将改用浏览器语音识别。", "ASR_DISABLED", 501)
    try:
        wav = base64.b64decode(body["audio_b64"])
    except Exception:  # noqa: BLE001
        return _err("audio_b64 不是合法的 base64")
    s = runtime.sessions.get(body.get("session_id"))
    hot = asr.build_hotwords(runtime.bank.payees(s.user_id))
    try:
        res = asr.recognize(wav, engine=body.get("engine"), hotwords=hot)
    except asr.ASRError as e:
        return _err(str(e), "ASR_ERROR", 502)
    s.add_trace("asr", f"语音识别（{res['engine']}，{res['latency_ms']}ms）：{res['text']}")
    return JSONResponse(res)


async def confirm(request: Request):
    body = await request.json()
    s = runtime.sessions.get(body.get("session_id"))
    start = len(s.trace)
    try:
        token = runtime.kernel.authorize(s, body["draft_id"], body["digest"], body.get("assertion", ""),
                                         verify_answer=body.get("verify_answer"))
        receipt = runtime.kernel.commit(s, body["draft_id"], token)
    except KernelError as e:
        return JSONResponse({"error": str(e), "code": e.code, "trace": s.trace[start:]}, status_code=400)
    draft = s.drafts[body["draft_id"]]
    text = presenter.receipt_text(draft, receipt)
    s.messages.append({"role": "assistant", "content": text})
    s.settle()
    next_task = s.plan.pop(0) if s.plan else None
    return JSONResponse({"receipt": receipt, "reply": text, "speak": text, "next_task": next_task,
                         "trace": s.trace[start:], "phase": s.phase.value})


async def cancel(request: Request):
    body = await request.json()
    s = runtime.sessions.get(body.get("session_id"))
    try:
        runtime.kernel.cancel(s, body["draft_id"], reason=body.get("reason", "user"))
    except KernelError as e:
        return _err(str(e), e.code)
    s.settle()
    s.plan.clear()
    msg = "好的，已经取消了，钱没有转出。"
    s.messages.append({"role": "assistant", "content": msg})
    return JSONResponse({"reply": msg, "speak": msg, "phase": s.phase.value})


async def current_card(request: Request):
    s = runtime.sessions.get(request.path_params["session_id"])
    d = s.current_draft
    if not d:
        return JSONResponse({"card": None, "phase": s.phase.value})
    # 冷静期到点后自动进入待授权
    runtime.kernel._refresh_cooling(s, d)  # noqa: SLF001
    return JSONResponse({"card": presenter.build_card(d, runtime.bank, s.phase), "phase": s.phase.value})


async def trace(request: Request):
    s = runtime.sessions.get(request.path_params["session_id"])
    return JSONResponse({"trace": s.trace, "audit": runtime.audit.for_session(s.session_id)[-50:]})


async def audit_verify(_: Request):
    return JSONResponse(runtime.audit.verify())


async def reset(request: Request):
    body = await request.json()
    sid = body.get("session_id")
    if body.get("world"):
        runtime.bank.reset()
    s = runtime.sessions.reset(sid) if sid else runtime.sessions.get(None)
    return JSONResponse({"session_id": s.session_id, "ts": time.time()})


routes = [
    Route("/", index),
    Route("/api/health", health),
    Route("/api/world", world),
    Route("/api/chat", chat, methods=["POST"]),
    Route("/api/asr", speech_to_text, methods=["POST"]),
    Route("/api/confirm", confirm, methods=["POST"]),
    Route("/api/cancel", cancel, methods=["POST"]),
    Route("/api/card/{session_id}", current_card),
    Route("/api/trace/{session_id}", trace),
    Route("/api/audit/verify", audit_verify),
    Route("/api/reset", reset, methods=["POST"]),
]

app = Starlette(routes=routes)
