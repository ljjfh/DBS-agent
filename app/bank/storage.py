"""Single-process demo ledger persistence, with atomic snapshots and audit outbox."""
import copy
import functools
import json
import sqlite3
from contextlib import closing
from pathlib import Path


def atomic_write(fn):
    @functools.wraps(fn)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            before = copy.deepcopy(self._snapshot())
            try:
                result = fn(self, *args, **kwargs)
                self._save()
                return result
            except Exception:
                self._restore(before)
                raise
    return wrapped


class LedgerStorage:
    def _snapshot(self):
        return {k: getattr(self, k) for k in ('world', 'executed', 'recent_exec_times', 'outbox')}

    def _restore(self, data):
        for k, v in data.items():
            setattr(self, k, v)

    def _load(self):
        if not self.path:
            return
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY, data TEXT NOT NULL)')
            row = db.execute('SELECT data FROM ledger WHERE id=1').fetchone()
        if row:
            self._restore(json.loads(row[0]))

    def _save(self):
        if self.path:
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute('INSERT OR REPLACE INTO ledger VALUES (1, ?)',
                           (json.dumps(self._snapshot(), ensure_ascii=False),))

    def transaction(self, user_id, draft_id):
        with self._lock:
            r = self.executed.get(draft_id)
            return copy.deepcopy(r) if r and r.get('user_id') == user_id else None

    def flush_audit(self, audit):
        # Posting remains successful if the audit sink is unavailable. Events stay durable for retry.
        with self._lock:
            for event in list(self.outbox):
                try:
                    audit.append(event['event'], event['session_id'], event['data'])
                except (OSError, sqlite3.Error):
                    break
                self.outbox.remove(event)
            try:
                self._save()
            except (OSError, sqlite3.Error):
                pass  # ledger already committed; a later retry may duplicate an audit event, never a payment
