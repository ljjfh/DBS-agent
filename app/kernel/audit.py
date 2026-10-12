"""Append-only hash-chained audit log: each record carries the previous record's hash, so any edit is detectable.

The same log serves debugging / evaluation, compliance evidence, and demo replay.
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
        """Recompute the whole chain. Returns whether it is intact, the record count, and where it first breaks."""
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
