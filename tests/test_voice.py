"""Voice recordings in the audit trail (kernel/voice.py).

The brief: every step traceable, from the raw audio to the signature. A recording is kept under its SHA-256, the
audit log has the hash and the transcript, and the card carries the hashes, so the signature covers them.
"""
import os
import struct
import tempfile
from pathlib import Path

os.environ.setdefault("RULE_FIXED_HOUR", "14")

from tests.test_dbs_apis import ApiBase  # noqa: E402
from app.kernel import voice  # noqa: E402
from app.kernel.signing import compute_digest  # noqa: E402


def wav(seconds=1.0, rate=16000, tone=1):
    n = int(seconds * rate)
    data = struct.pack(f"<{n}h", *([tone * 100] * n))
    return (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16)
            + b"data" + struct.pack("<I", len(data)) + data)


class VoiceBase(ApiBase):
    def setUp(self):
        super().setUp()
        self.vtmp = tempfile.TemporaryDirectory()
        self.store = voice.VoiceStore(Path(self.vtmp.name))

    def tearDown(self):
        self.vtmp.cleanup()
        super().tearDown()

    def say(self, text, audio=None):
        """What the server does for a spoken message: record the clip, link the words, run the turn."""
        audio = audio or wav()
        sha = voice.record_clip(self.s, self.store, self.audit, audio, {"text": text, "engine": "16k_en", "latency_ms": 300})
        self.s.turn_audio = voice.bind_utterance(self.s, text, sha)
        try:
            return sha, self.turn(text)
        finally:
            self.s.turn_audio = None


class TestRecordingIsKept(VoiceBase):
    def test_clip_saved_and_audited(self):
        audio = wav(1.5)
        sha, _ = self.say("What's my balance?", audio)
        self.assertEqual(self.store.path(sha).read_bytes(), audio)
        rec = [e for e in self.audit.for_session(self.s.session_id) if e["event"] == "voice.recorded"][-1]["data"]
        self.assertEqual((rec["audio_sha256"], rec["transcript"], rec["seconds"]), (sha, "What's my balance?", 1.5))
        said = [e for e in self.audit.for_session(self.s.session_id) if e["event"] == "user.utterance"][-1]["data"]
        self.assertEqual(said["audio_sha256"], sha)

    def test_typed_message_has_no_recording(self):
        self.turn("Send 50 to my daughter")
        self.assertEqual(self.s.current_draft.you_said_audio, [])

    def test_a_hash_from_elsewhere_is_ignored(self):
        self.assertIsNone(voice.bind_utterance(self.s, "Send 50 to my daughter", "a" * 64))

    def test_a_recording_of_other_words_is_not_linked(self):
        sha = voice.record_clip(self.s, self.store, self.audit, wav(), {"text": "What's my balance?"})
        self.assertIsNone(voice.bind_utterance(self.s, "Send 5000 to my daughter", sha))


class TestCardCarriesTheRecording(VoiceBase):
    def test_signed_card_and_receipt_hold_the_hash(self):
        sha, _ = self.say("Send 50 to my daughter")
        d = self.s.current_draft
        self.assertEqual(d.you_said_audio, [sha])
        self.assertEqual(d.card_fields()["you_said_audio"], [sha])
        tampered = d.model_copy(update={"you_said_audio": ["b" * 64]})
        self.assertNotEqual(compute_digest(tampered), d.digest)           # the signature covers the recording
        rec = self.pay()
        self.assertEqual(rec["verifiable"]["card"]["you_said_audio"], [sha])

    def test_two_clips_for_one_task(self):
        sha1, _ = self.say("Send money to my daughter")
        sha2, _ = self.say("50 dollars", wav(tone=2))
        self.assertEqual(self.s.current_draft.you_said_audio, [sha1, sha2])


class TestStore(VoiceBase):
    def test_bad_names_and_pruning(self):
        self.assertIsNone(self.store.path("../../etc/passwd"))
        self.assertIsNone(self.store.path("a" * 64))
        old = voice.MAX_FILES
        voice.MAX_FILES = 2
        try:
            shas = [self.store.save(wav(0.1, tone=t)) for t in (1, 2, 3)]
        finally:
            voice.MAX_FILES = old
        self.assertEqual(len(list(Path(self.vtmp.name).glob("*.wav"))), 2)
        self.assertIsNotNone(self.store.path(shas[-1]))
