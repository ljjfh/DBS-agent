"""追加式哈希链审计日志：每条记录带上前一条的哈希，任何一条被改动都能被检测出来。

同一份日志同时服务：调试 / 评测、合规取证、路演回放。
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _canon(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def append(self, event: str, session_id: str, data: dict) -> dict:
        with self._lock:
            body = {"ts": round(time.time(), 3), "event": event, "session_id": session_id,
                    "data": data, "prev_hash": self._last_hash}
            body["hash"] = hashlib.sha256(_canon(body).encode()).hexdigest()
            with self.path.open("a", encoding="utf-8") as f:
                f.write(_canon(body) + "\n")
            self._last_hash = body["hash"]
            return body

    def verify(self) -> dict:
        """重新计算整条链。返回是否完整、条数，以及第一处断裂的位置。"""
        prev = GENESIS
        n = 0
        if not self.path.exists():
            return {"ok": True, "records": 0}
        with self.path.open(encoding="utf-8") as f:
            for i, line in enumerate(f):
                if not line.strip():
                    continue
                rec = json.loads(line)
                claimed = rec.pop("hash")
                if rec["prev_hash"] != prev or hashlib.sha256(_canon(rec).encode()).hexdigest() != claimed:
                    return {"ok": False, "records": n, "broken_at_line": i + 1}
                prev = claimed
                n += 1
        return {"ok": True, "records": n, "head": prev}

    def for_session(self, session_id: str) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [r for r in (json.loads(l) for l in f if l.strip()) if r["session_id"] == session_id]
