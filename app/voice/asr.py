"""腾讯云一句话识别（SentenceRecognition，60 秒内短音频）。

直接实现 TC3-HMAC-SHA256 签名，避免国内版/国际版 SDK 的差异。
我们改不了 ASR 的识别能力，但能调的有：
  * 引擎 EngSerViceType：16k_zh_large（普通话+方言+英语）、16k_zh-PY（中英粤）、16k_en、16k_ms 等
  * 临时热词表 HotwordList：收款人称呼、产品名，权重 1-11（11 为超级热词）
  * 识别后处理：低置信度字段一律回读确认（在 Agent 侧完成）
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

import requests

from app.config import settings

SERVICE, VERSION, ACTION = "asr", "2019-06-14", "SentenceRecognition"


class ASRError(Exception):
    pass


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def tc3_headers(payload: str, host: str, secret_id: str, secret_key: str, region: str | None,
                action: str = ACTION, version: str = VERSION, service: str = SERVICE) -> dict:
    ts = int(time.time())
    date = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
    ct = "application/json; charset=utf-8"
    canonical = "\n".join(["POST", "/", "", f"content-type:{ct}\nhost:{host}\n", "content-type;host",
                           hashlib.sha256(payload.encode()).hexdigest()])
    scope = f"{date}/{service}/tc3_request"
    to_sign = "\n".join(["TC3-HMAC-SHA256", str(ts), scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _sign(_sign(_sign(("TC3" + secret_key).encode(), date), service), "tc3_request")
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Authorization": f"TC3-HMAC-SHA256 Credential={secret_id}/{scope}, SignedHeaders=content-type;host, "
                         f"Signature={signature}",
        "Content-Type": ct, "Host": host, "X-TC-Action": action, "X-TC-Timestamp": str(ts),
        "X-TC-Version": version,
    }
    if region:
        headers["X-TC-Region"] = region
    return headers


def build_hotwords(payees: list[dict]) -> str:
    """把收款人称呼和常用词做成临时热词表，例如 '阿囡|10,PayNow|10'。

    权重 11 是“超级热词”，官方建议只给极少数必须生效的词，设太多会降低整体字准率，所以这里不用。
    """
    words: list[tuple[str, int]] = [("PayNow", 10), ("养老金", 10), ("水电费", 10), ("杂费", 8), ("CPF", 10)]
    for p in payees:
        for a in [p["name"], *p.get("aliases", [])]:
            if 1 <= len(a) <= 10:
                words.append((a, 10 if p["type"] == "person" else 8))
    seen, out = set(), []
    for w, wt in words:
        if w.lower() not in seen:
            seen.add(w.lower())
            out.append(f"{w}|{wt}")
    return ",".join(out[:128])


def recognize(wav_bytes: bytes, engine: str | None = None, hotwords: str = "") -> dict:
    if not settings.asr_enabled:
        raise ASRError("未配置 TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY")
    body = {"EngSerViceType": engine or settings.asr_engine, "SourceType": 1, "VoiceFormat": "wav",
            "Data": base64.b64encode(wav_bytes).decode(), "DataLen": len(wav_bytes),
            "WordInfo": 0, "FilterModal": 1, "ConvertNumMode": 1}
    if hotwords:
        body["HotwordList"] = hotwords
    payload = json.dumps(body)
    host = settings.asr_endpoint
    headers = tc3_headers(payload, host, settings.tc_secret_id, settings.tc_secret_key, settings.asr_region)
    t0 = time.time()
    try:
        r = requests.post(f"https://{host}", data=payload.encode(), headers=headers, timeout=20)
    except requests.RequestException as e:
        raise ASRError(f"网络错误：{e}") from e
    resp = r.json().get("Response", {})
    if "Error" in resp:
        raise ASRError(f"{resp['Error'].get('Code')}: {resp['Error'].get('Message')}")
    return {"text": resp.get("Result", ""), "audio_ms": resp.get("AudioDuration"),
            "latency_ms": int((time.time() - t0) * 1000), "engine": body["EngSerViceType"]}
