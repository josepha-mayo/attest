from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path


class WebhookInbox:
    def __init__(self, path: Path):
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=0.25)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS deliveries (
                id TEXT PRIMARY KEY, raw_body BLOB NOT NULL, signature TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                retry_at REAL NOT NULL DEFAULT 0, lease TEXT, lease_until REAL,
                error_code TEXT, received_at REAL NOT NULL
            )
        """)

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def enqueue(self, request_id: str, raw_body: bytes, signature: str) -> bool:
        with self._transaction():
            existing = self._db.execute(
                "SELECT raw_body, signature FROM deliveries WHERE id=?", (request_id,)
            ).fetchone()
            if existing:
                if existing["raw_body"] != raw_body or existing["signature"] != signature:
                    raise ValueError("request id reused with different content")
                return False
            queued = self._db.execute(
                "SELECT COUNT(*) FROM deliveries WHERE status IN ('pending', 'processing')"
            ).fetchone()[0]
            if queued >= 10000:
                raise OverflowError("webhook queue at capacity")
            self._db.execute(
                "INSERT INTO deliveries (id, raw_body, signature, received_at) VALUES (?, ?, ?, ?)",
                (request_id, raw_body, signature, time.time()),
            )
            return True

    def claim(self, *, now: float | None = None) -> dict | None:
        now = time.time() if now is None else now
        with self._transaction():
            self._db.execute(
                "UPDATE deliveries SET status='failed', error_code='LeaseExpired' "
                "WHERE status='processing' AND lease_until<=? AND attempts>=5",
                (now,),
            )
            row = self._db.execute(
                "SELECT * FROM deliveries WHERE (status='pending' AND retry_at<=?) "
                "OR (status='processing' AND lease_until<=?) ORDER BY received_at, id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            lease = secrets.token_hex(16)
            self._db.execute(
                "UPDATE deliveries SET status='processing', lease=?, lease_until=?, attempts=attempts+1 "
                "WHERE id=?",
                (lease, now + 300, row["id"]),
            )
            return {**dict(row), "lease": lease, "attempts": row["attempts"] + 1}

    def complete(self, job: dict, status: str) -> None:
        if status not in ("done", "rejected"):
            raise ValueError("invalid delivery outcome")
        with self._transaction():
            self._db.execute(
                "UPDATE deliveries SET status=?, lease=NULL, lease_until=NULL, error_code=NULL "
                "WHERE id=? AND lease=?",
                (status, job["id"], job["lease"]),
            )

    def fail(self, job: dict, error_code: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        status = "failed" if job["attempts"] >= 5 else "pending"
        retry_at = now + min(60, 2 ** min(job["attempts"], 6))
        with self._transaction():
            self._db.execute(
                "UPDATE deliveries SET status=?, retry_at=?, error_code=?, lease=NULL, lease_until=NULL "
                "WHERE id=? AND lease=?",
                (status, retry_at, error_code[:100], job["id"], job["lease"]),
            )

    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._db.execute("SELECT status, COUNT(*) FROM deliveries GROUP BY status"))

    def entries(self, *, limit: int = 1000) -> list[dict]:
        """Delivery metadata for lifecycle reporting. Bodies are never returned."""
        with self._lock:
            return [
                {k: r[k] for k in ("id", "status", "attempts", "error_code", "received_at")}
                for r in self._db.execute(
                    "SELECT id, status, attempts, error_code, received_at "
                    "FROM deliveries ORDER BY received_at LIMIT ?",
                    (limit,),
                )
            ]

    def close(self) -> None:
        self._db.close()
