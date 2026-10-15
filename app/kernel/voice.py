"""Voice recordings for the audit trail.

The DBS brief asks that every step be traceable: the raw audio, the transcript, the drafts, the checks and the
signature. Each recording sent to speech recognition is kept here under its SHA-256, and the audit log stores that
hash with the transcript. A confirmation card carries the hashes of the recordings it was built from, so the
customer's fingerprint signature covers "this recording -> this card".

Demo storage is the server's disk (wiped on a redeploy). A bank would use encrypted object storage with a retention
policy. The oldest files are removed once the folder passes MAX_FILES / MAX_BYTES.
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
from pathlib import Path

MAX_FILES = 400
MAX_BYTES = 300 * 1024 * 1024
_SHA = re.compile(r"^[a-f0-9]{64}$")


class VoiceStore:
    def __init__(self, folder: Path):
        self.folder = Path(folder)
        self._lock = threading.Lock()

    def save(self, wav: bytes) -> str:
        sha = hashlib.sha256(wav).hexdigest()
        with self._lock:
            self.folder.mkdir(parents=True, exist_ok=True)
            path = self.folder / f"{sha}.wav"
            if not path.exists():
                path.write_bytes(wav)
            self._prune()
        return sha

    def path(self, sha: str) -> Path | None:
        if not isinstance(sha, str) or not _SHA.match(sha):
            return None
        p = self.folder / f"{sha}.wav"
        return p if p.exists() else None

    def _prune(self) -> None:
        files = sorted(self.folder.glob("*.wav"), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in files)
        while files and (len(files) > MAX_FILES or total > MAX_BYTES):
            old = files.pop(0)
            total -= old.stat().st_size
            old.unlink(missing_ok=True)


def wav_seconds(wav: bytes) -> float:
    """Length of a PCM WAV (16-bit mono from the app); 0 when the header can't be read."""
    try:
        rate = int.from_bytes(wav[24:28], "little")
        bits = int.from_bytes(wav[34:36], "little") or 16
        chans = int.from_bytes(wav[22:24], "little") or 1
        return round((len(wav) - 44) / (rate * chans * bits / 8), 2) if rate else 0.0
    except Exception:  # noqa: BLE001
        return 0.0


def record_clip(s, store: VoiceStore, audit, wav: bytes, result: dict) -> str:
    """Keep the recording, remember it for this session and write it to the audit chain. Returns its SHA-256."""
    sha = store.save(wav)
    meta = {"audio_sha256": sha, "bytes": len(wav), "seconds": wav_seconds(wav), "engine": result.get("engine", ""),
            "transcript": result.get("text", ""), "latency_ms": result.get("latency_ms"), "at": int(time.time())}
    s.voice_clips[sha] = meta
    audit.append("voice.recorded", s.session_id, meta)
    return sha


def bind_utterance(s, text: str, sha: str | None) -> str | None:
    """Link what the user sent to the recording it came from: only a recording of THIS session whose transcript is
    exactly these words (so a card never claims a recording that said something else)."""
    norm = lambda t: " ".join(str(t or "").split()).lower()
    if sha and sha in s.voice_clips and norm(s.voice_clips[sha].get("transcript")) == norm(text):
        s.utterance_audio[text] = sha
        return sha
    return None


def task_audio(s) -> list[str]:
    """Recordings behind the current task's own words: these hashes go on the card and are signed with it."""
    out = []
    for m in s.messages[s.task_start:]:
        if m.get("role") != "user":
            continue
        for key in (m.get("raw_content"), m.get("ground_text"), m.get("content")):
            sha = s.utterance_audio.get(key or "")
            if sha and sha not in out:
                out.append(sha)
    return out
