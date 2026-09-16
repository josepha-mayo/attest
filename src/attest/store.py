"""SQLite persistence. One table per entity, rows stored as JSON with a few indexed columns."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from .models import (
    CheckinGrant,
    Evidence,
    PollObservation,
    Receipt,
    ReviewEntry,
    ReviewGrant,
    Schedule,
    Site,
    Visit,
    VisitState,
    Worker,
)

T = TypeVar("T", bound=BaseModel)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sites     (id TEXT PRIMARY KEY, ring_account_id TEXT, door_camera_id TEXT,
                                      door_sensor_id TEXT, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workers   (id TEXT PRIMARY KEY, checkin_token TEXT UNIQUE, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, site_id TEXT, worker_id TEXT,
                                      window_start TEXT, window_end TEXT, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS visits    (id TEXT PRIMARY KEY, site_id TEXT, schedule_id TEXT, state TEXT,
                                      arrived_at TEXT, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence  (id TEXT PRIMARY KEY, visit_id TEXT, at TEXT, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS receipts  (id TEXT PRIMARY KEY, visit_id TEXT UNIQUE, sequence INTEGER UNIQUE,
                                      body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS seen_requests (request_id TEXT PRIMARY KEY, seen_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkin_grants (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ingestion_sources (site_id TEXT PRIMARY KEY, source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS late_events (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS journal (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL, table_name TEXT NOT NULL, row_id TEXT NOT NULL,
    op TEXT NOT NULL, body_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS poll_observations (id TEXT PRIMARY KEY, site_id TEXT NOT NULL,
                                               device_id TEXT, polled_at TEXT NOT NULL,
                                               body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_poll_obs_device ON poll_observations(device_id, polled_at);
CREATE TABLE IF NOT EXISTS reviews (id TEXT PRIMARY KEY, visit_id TEXT NOT NULL, revision INTEGER NOT NULL,
                                    body TEXT NOT NULL, UNIQUE(visit_id, revision));
CREATE TABLE IF NOT EXISTS review_grants (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE, body TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_visits_site_state ON visits(site_id, state);
CREATE INDEX IF NOT EXISTS ix_evidence_visit ON evidence(visit_id, at);
CREATE INDEX IF NOT EXISTS ix_schedules_site ON schedules(site_id, window_start);
"""


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("timezone-aware timestamp required")
    return dt.astimezone(UTC).isoformat()


def _sha(s: str) -> str:
    import hashlib

    return hashlib.sha256(s.encode()).hexdigest()


# Tables covered by the mutation journal, with the column that identifies a row.
_JOURNALED_KEYS = {
    "sites": "id",
    "workers": "id",
    "schedules": "id",
    "visits": "id",
    "evidence": "id",
    "receipts": "id",
    "reviews": "id",
    "review_grants": "id",
    "checkin_grants": "id",
    "late_events": "id",
    "poll_observations": "id",
    "settings": "name",
    "seen_requests": "request_id",
    "ingestion_sources": "site_id",
}

# Rows without a JSON `body` column get hashed over their content columns.
_JOURNALED_CONTENT = {
    "seen_requests": ("request_id", "seen_at"),
    "ingestion_sources": ("site_id", "source"),
}


def atomic(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self.store.transaction():
            return method(self, *args, **kwargs)

    return wrapped


class Store:
    def __init__(self, path: Path | str = ":memory:"):
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL") if path != ":memory:" else None
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)

    @contextmanager
    def transaction(self):
        with self._lock:
            if self._conn.in_transaction:
                yield
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    def setting(self, name: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT body FROM settings WHERE name=?", (name,)).fetchone()
            return json.loads(row[0]) if row else None

    def put_setting(self, name: str, value: dict) -> None:
        with self._lock:
            body = json.dumps(value)
            self._conn.execute(
                "INSERT INTO settings (name, body) VALUES (?, ?) "
                "ON CONFLICT(name) DO UPDATE SET body=excluded.body",
                (name, body),
            )
            self._journal("settings", name, "put", _sha(body))

    def close(self) -> None:
        self._conn.close()

    # ----------------------------------------------------------------- journal

    def _journal(self, table: str, row_id: str, op: str, body_hash: str) -> None:
        """Append a hash-chained mutation record. Callers must hold ``_lock``; the
        entry lands in the caller's transaction so a rollback undoes both writes."""
        with self._lock:
            prev = self._conn.execute("SELECT hash FROM journal ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = prev[0] if prev else "0" * 64
            at = _iso(datetime.now(tz=UTC))
            digest = _sha(
                json.dumps(
                    {
                        "at": at,
                        "table": table,
                        "row_id": row_id,
                        "op": op,
                        "body_hash": body_hash,
                        "prev_hash": prev_hash,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            self._conn.execute(
                "INSERT INTO journal (at, table_name, row_id, op, body_hash, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (at, table, row_id, op, body_hash, prev_hash, digest),
            )

    def _row_hash(self, table: str, row_id: str) -> str | None:
        """Hash of a row's current content, or None if the row is gone."""
        key = _JOURNALED_KEYS[table]
        with self._lock:
            if table in _JOURNALED_CONTENT:
                cols = ",".join(_JOURNALED_CONTENT[table])
                r = self._conn.execute(f"SELECT {cols} FROM {table} WHERE {key}=?", (row_id,)).fetchone()
                if r is None:
                    return None
                return _sha(json.dumps(dict(zip(_JOURNALED_CONTENT[table], r, strict=True)), sort_keys=True))
            r = self._conn.execute(f"SELECT body FROM {table} WHERE {key}=?", (row_id,)).fetchone()
            return _sha(r[0]) if r else None

    def verify_journal(self) -> dict:
        """Replay the mutation journal: link integrity, then state-vs-log agreement.

        A row that was journaled 'put' must still exist with the same content; a
        journaled 'delete' must be gone. Rows never journaled (pre-journal data or
        out-of-band writes) are reported as untracked — visible, not silently trusted.
        """
        with self._lock:
            entries = self._conn.execute(
                "SELECT seq, at, table_name, row_id, op, body_hash, prev_hash, hash FROM journal ORDER BY seq"
            ).fetchall()
            prev_hash, mismatches, last_op = "0" * 64, [], {}
            expected_seq = 1
            for seq, at, table, row_id, op, body_hash, prev, h in entries:
                if seq != expected_seq:
                    mismatches.append(f"journal gap at seq {seq}")
                    expected_seq = seq
                expected_seq += 1
                if prev != prev_hash:
                    mismatches.append(f"journal link broken at seq {seq}")
                recomputed = _sha(
                    json.dumps(
                        {
                            "at": at,
                            "table": table,
                            "row_id": row_id,
                            "op": op,
                            "body_hash": body_hash,
                            "prev_hash": prev,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                if recomputed != h:
                    mismatches.append(f"journal entry {seq} altered")
                prev_hash = h
                last_op[(table, row_id)] = (op, body_hash, seq)

            tracked = set()
            for (table, row_id), (op, body_hash, seq) in last_op.items():
                tracked.add((table, row_id))
                current = self._row_hash(table, row_id)
                if op == "delete":
                    if current is not None:
                        mismatches.append(f"{table}:{row_id} deleted in journal but still present")
                elif current is None:
                    mismatches.append(f"{table}:{row_id} journaled '{op}' but row vanished")
                elif current != body_hash:
                    mismatches.append(f"{table}:{row_id} content changed after seq {seq}")

            untracked = 0
            for table, key in _JOURNALED_KEYS.items():
                ids = [r[0] for r in self._conn.execute(f"SELECT {key} FROM {table}")]
                untracked += sum(1 for rid in ids if (table, rid) not in tracked)

            return {
                "entries": len(entries),
                "intact": not mismatches,
                "mismatches": mismatches[:50],
                "untracked_rows": untracked,
            }

    def journal_baseline(self) -> int:
        """Stamp every existing row as 'baseline' — explicit operator action for a
        store created before journaling. Never automatic: it admits current state."""
        stamped = 0
        with self.transaction():
            for table, key in _JOURNALED_KEYS.items():
                if table in _JOURNALED_CONTENT:
                    cols = _JOURNALED_CONTENT[table]
                    rows = self._conn.execute(f"SELECT {key}, {','.join(cols)} FROM {table}").fetchall()
                    content = {
                        r[0]: _sha(json.dumps(dict(zip(cols, r[1:], strict=True)), sort_keys=True))
                        for r in rows
                    }
                else:
                    rows = self._conn.execute(f"SELECT {key}, body FROM {table}").fetchall()
                    content = {r[0]: _sha(r[1]) for r in rows}
                for row_id, h in content.items():
                    self._journal(table, row_id, "baseline", h)
                    stamped += 1
        return stamped

    # ----------------------------------------------------------------- generic

    def _put(self, table: str, obj: BaseModel, **cols: object) -> None:
        cols = {"id": obj.id, **cols, "body": obj.model_dump_json()}  # type: ignore[attr-defined]
        names = ",".join(cols)
        marks = ",".join("?" * len(cols))
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO {table} ({names}) VALUES ({marks})", tuple(cols.values())
            )
            self._journal(table, obj.id, "put", _sha(cols["body"]))  # type: ignore[attr-defined]

    def _rows(self, model: type[T], sql: str, params: Iterable[object] = ()) -> list[T]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return [model.model_validate_json(r[0]) for r in cur.fetchall()]

    def _one(self, model: type[T], sql: str, params: Iterable[object] = ()) -> T | None:
        rows = self._rows(model, sql + " LIMIT 1", params)
        return rows[0] if rows else None

    # ----------------------------------------------------------------- sites

    def put_site(self, s: Site) -> Site:
        self._put(
            "sites",
            s,
            ring_account_id=s.ring_account_id,
            door_camera_id=s.door_camera_id,
            door_sensor_id=s.door_sensor_id,
        )
        return s

    def site(self, site_id: str) -> Site | None:
        return self._one(Site, "SELECT body FROM sites WHERE id=?", (site_id,))

    def sites(self) -> list[Site]:
        return self._rows(Site, "SELECT body FROM sites ORDER BY id")

    def site_for_device(self, device_id: str) -> Site | None:
        return self._one(
            Site,
            "SELECT body FROM sites WHERE door_camera_id=? OR door_sensor_id=?",
            (device_id, device_id),
        )

    # ----------------------------------------------------------------- workers

    def put_worker(self, w: Worker) -> Worker:
        self._put("workers", w, checkin_token=w.checkin_token)
        return w

    def worker(self, worker_id: str) -> Worker | None:
        return self._one(Worker, "SELECT body FROM workers WHERE id=?", (worker_id,))

    def worker_by_token(self, token: str) -> Worker | None:
        return self._one(Worker, "SELECT body FROM workers WHERE checkin_token=?", (token,))

    def workers(self) -> list[Worker]:
        return self._rows(Worker, "SELECT body FROM workers ORDER BY id")

    def put_checkin_grant(self, grant: CheckinGrant) -> None:
        self._put("checkin_grants", grant, token_hash=grant.token_hash)

    def checkin_grant(self, token_hash: str) -> CheckinGrant | None:
        return self._one(CheckinGrant, "SELECT body FROM checkin_grants WHERE token_hash=?", (token_hash,))

    def checkin_grants(self) -> list[CheckinGrant]:
        return self._rows(CheckinGrant, "SELECT body FROM checkin_grants ORDER BY id")

    # ----------------------------------------------------------------- schedules

    def put_schedule(self, s: Schedule) -> Schedule:
        self._put(
            "schedules",
            s,
            site_id=s.site_id,
            worker_id=s.worker_id,
            window_start=_iso(s.window_start),
            window_end=_iso(s.window_end),
        )
        return s

    def schedule(self, schedule_id: str) -> Schedule | None:
        return self._one(Schedule, "SELECT body FROM schedules WHERE id=?", (schedule_id,))

    def schedules_for_site(self, site_id: str) -> list[Schedule]:
        return self._rows(
            Schedule, "SELECT body FROM schedules WHERE site_id=? ORDER BY window_start", (site_id,)
        )

    def schedules(self) -> list[Schedule]:
        return self._rows(Schedule, "SELECT body FROM schedules ORDER BY window_start DESC")

    # ----------------------------------------------------------------- visits

    def put_visit(self, v: Visit) -> Visit:
        self._put(
            "visits",
            v,
            site_id=v.site_id,
            schedule_id=v.schedule_id,
            state=v.state,
            arrived_at=_iso(v.arrived_at),
        )
        return v

    def visit(self, visit_id: str) -> Visit | None:
        return self._one(Visit, "SELECT body FROM visits WHERE id=?", (visit_id,))

    def visits(
        self,
        *,
        site_id: str | None = None,
        states: Iterable[VisitState] | None = None,
        limit: int = 200,
    ) -> list[Visit]:
        sql, params = "SELECT body FROM visits WHERE 1=1", []
        if site_id:
            sql += " AND site_id=?"
            params.append(site_id)
        if states:
            states = list(states)
            sql += f" AND state IN ({','.join('?' * len(states))})"
            params.extend(states)
        sql += " ORDER BY arrived_at DESC LIMIT ?"
        params.append(limit)
        return self._rows(Visit, sql, params)

    def active_visit(self, site_id: str) -> Visit | None:
        return self._one(
            Visit,
            "SELECT body FROM visits WHERE site_id=? AND state IN (?,?,?) ORDER BY arrived_at DESC",
            (site_id, VisitState.OPEN, VisitState.IN_PROGRESS, VisitState.UNMATCHED),
        )

    def visit_for_schedule(self, schedule_id: str) -> Visit | None:
        return self._one(
            Visit,
            "SELECT body FROM visits WHERE schedule_id=? ORDER BY arrived_at DESC",
            (schedule_id,),
        )

    # ----------------------------------------------------------------- evidence

    def put_evidence(self, e: Evidence) -> Evidence:
        self._put("evidence", e, visit_id=e.visit_id, at=_iso(e.at))
        return e

    def evidence_for(self, visit_id: str) -> list[Evidence]:
        return self._rows(Evidence, "SELECT body FROM evidence WHERE visit_id=? ORDER BY at", (visit_id,))

    # ----------------------------------------------------------------- receipts

    def put_receipt(self, r: Receipt) -> Receipt:
        with self._lock:
            body = r.model_dump_json()
            self._conn.execute(
                "INSERT INTO receipts (id, visit_id, sequence, body) VALUES (?, ?, ?, ?)",
                (r.id, r.visit_id, r.sequence, body),
            )
            self._journal("receipts", r.id, "put", _sha(body))
        return r

    def receipt(self, receipt_id: str) -> Receipt | None:
        return self._one(Receipt, "SELECT body FROM receipts WHERE id=?", (receipt_id,))

    def receipt_for_visit(self, visit_id: str) -> Receipt | None:
        return self._one(Receipt, "SELECT body FROM receipts WHERE visit_id=?", (visit_id,))

    def latest_receipt(self) -> Receipt | None:
        return self._one(Receipt, "SELECT body FROM receipts ORDER BY sequence DESC")

    def receipts(self) -> list[Receipt]:
        return self._rows(Receipt, "SELECT body FROM receipts ORDER BY sequence")

    def reviews_for(self, visit_id: str) -> list[ReviewEntry]:
        return self._rows(
            ReviewEntry, "SELECT body FROM reviews WHERE visit_id=? ORDER BY revision", (visit_id,)
        )

    def put_review(self, review: ReviewEntry) -> None:
        with self._lock:
            body = review.model_dump_json()
            self._conn.execute(
                "INSERT INTO reviews (id, visit_id, revision, body) VALUES (?, ?, ?, ?)",
                (review.id, review.visit_id, review.revision, body),
            )
            self._journal("reviews", review.id, "put", _sha(body))

    def put_review_grant(self, grant: ReviewGrant) -> None:
        self._put("review_grants", grant, token_hash=grant.token_hash)

    def review_grant(self, token_hash: str) -> ReviewGrant | None:
        return self._one(ReviewGrant, "SELECT body FROM review_grants WHERE token_hash=?", (token_hash,))

    def review_grants(self) -> list[ReviewGrant]:
        return self._rows(ReviewGrant, "SELECT body FROM review_grants ORDER BY id")

    # ------------------------------------------------------------- poll coverage

    def put_poll_observation(self, obs: PollObservation) -> None:
        self._put(
            "poll_observations",
            obs,
            site_id=obs.site_id,
            device_id=obs.device_id,
            polled_at=_iso(obs.polled_at),
        )

    def poll_observations(self, device_id: str, start: datetime, until: datetime) -> list[PollObservation]:
        """Polls that could have seen events at or after ``start``, made before ``until``.

        The upper bound is the report cutoff, not the window end — history is
        retrospective, so a poll after the window can still cover it."""
        return self._rows(
            PollObservation,
            "SELECT body FROM poll_observations WHERE device_id=? AND polled_at>=? "
            "AND polled_at<=? ORDER BY polled_at",
            (device_id, _iso(start), _iso(until)),
        )

    # ----------------------------------------------------------------- idempotency

    def bind_source(self, site_id: str, source: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO ingestion_sources (site_id, source) VALUES (?, ?)", (site_id, source)
            )
            if cur.rowcount:
                self._journal(
                    "ingestion_sources",
                    site_id,
                    "put",
                    _sha(json.dumps({"site_id": site_id, "source": source}, sort_keys=True)),
                )
            return (
                self._conn.execute(
                    "SELECT source FROM ingestion_sources WHERE site_id=?", (site_id,)
                ).fetchone()[0]
                == source
            )

    def record_late_event(self, event_id: str, site_id: str, body: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO late_events (id, site_id, body) VALUES (?, ?, ?)", (event_id, site_id, body)
            )
            self._journal("late_events", event_id, "put", _sha(body))

    def late_events(self) -> list[dict]:
        with self._lock:
            return [json.loads(r[0]) for r in self._conn.execute("SELECT body FROM late_events ORDER BY id")]

    def late_event_rows(self) -> list[dict]:
        with self._lock:
            return [
                {"id": r[0], "site_id": r[1], "body": json.loads(r[2])}
                for r in self._conn.execute("SELECT id, site_id, body FROM late_events ORDER BY id")
            ]

    def mark_seen(self, request_id: str, at: datetime) -> bool:
        """Return True if new, False if this webhook request_id was already processed."""
        with self._lock:
            try:
                seen_at = _iso(at)
                self._conn.execute(
                    "INSERT INTO seen_requests (request_id, seen_at) VALUES (?, ?)",
                    (request_id, seen_at),
                )
                self._journal(
                    "seen_requests",
                    request_id,
                    "put",
                    _sha(json.dumps({"request_id": request_id, "seen_at": seen_at}, sort_keys=True)),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def stale_seen(self, before: datetime, *, limit: int = 200) -> tuple[int, list[str]]:
        """Count dedupe keys older than ``before`` and return up to ``limit`` ids."""
        iso = _iso(before)
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM seen_requests WHERE seen_at<?", (iso,)
            ).fetchone()[0]
            ids = [
                r[0]
                for r in self._conn.execute(
                    "SELECT request_id FROM seen_requests WHERE seen_at<? ORDER BY seen_at LIMIT ?",
                    (iso, limit),
                )
            ]
            return total, ids

    # ----------------------------------------------------------------- retention

    def _delete_ids(self, table: str, column: str, ids: Iterable[str]) -> int:
        ids = list(ids)
        if not ids:
            return 0
        journaled = column == _JOURNALED_KEYS.get(table)
        removed = 0
        with self.transaction():
            for rid in ids:
                h = self._row_hash(table, rid) if journaled else None
                removed += self._conn.execute(f"DELETE FROM {table} WHERE {column}=?", (rid,)).rowcount
                if h is not None:
                    self._journal(table, rid, "delete", h)
            return removed

    def delete_seen(self, ids: Iterable[str]) -> int:
        return self._delete_ids("seen_requests", "request_id", ids)

    def delete_late_events(self, ids: Iterable[str]) -> int:
        return self._delete_ids("late_events", "id", ids)

    def delete_checkin_grants(self, ids: Iterable[str]) -> int:
        return self._delete_ids("checkin_grants", "id", ids)

    def delete_review_grants(self, ids: Iterable[str]) -> int:
        return self._delete_ids("review_grants", "id", ids)

    def delete_poll_observations(self, ids: Iterable[str]) -> int:
        return self._delete_ids("poll_observations", "id", ids)

    def poll_observation_rows(self) -> list[PollObservation]:
        return self._rows(PollObservation, "SELECT body FROM poll_observations ORDER BY polled_at")

    # ----------------------------------------------------------------- misc

    def stats(self) -> dict:
        """Table counts and oldest timestamps for lifecycle reporting. No bodies."""
        with self._lock:

            def row(sql: str):
                return self._conn.execute(sql).fetchone()

            visits = row("SELECT COUNT(*), MIN(arrived_at) FROM visits")
            by_state = dict(
                self._conn.execute("SELECT state, COUNT(*) FROM visits GROUP BY state").fetchall()
            )
            evidence = row("SELECT COUNT(*), MIN(at) FROM evidence")
            receipts = row("SELECT COUNT(*), MAX(sequence) FROM receipts")
            seen = row("SELECT COUNT(*), MIN(seen_at) FROM seen_requests")
            return {
                "sites": row("SELECT COUNT(*) FROM sites")[0],
                "workers": row("SELECT COUNT(*) FROM workers")[0],
                "schedules": row("SELECT COUNT(*) FROM schedules")[0],
                "reviews": row("SELECT COUNT(*) FROM reviews")[0],
                "late_events": row("SELECT COUNT(*) FROM late_events")[0],
                "poll_observations": row("SELECT COUNT(*) FROM poll_observations")[0],
                "checkin_grants": row("SELECT COUNT(*) FROM checkin_grants")[0],
                "review_grants": row("SELECT COUNT(*) FROM review_grants")[0],
                "visits": {"total": visits[0], "oldest_arrival": visits[1], "by_state": by_state},
                "evidence": {"total": evidence[0], "oldest": evidence[1]},
                "receipts": {"total": receipts[0], "latest_sequence": receipts[1]},
                "seen_requests": {"total": seen[0], "oldest": seen[1]},
            }

    def dump(self) -> dict:
        return {
            "sites": [json.loads(s.model_dump_json()) for s in self.sites()],
            "workers": [json.loads(w.model_dump_json(exclude={"checkin_token"})) for w in self.workers()],
            "late_events": self.late_events(),
            "schedules": [json.loads(s.model_dump_json()) for s in self.schedules()],
            "visits": [json.loads(v.model_dump_json()) for v in self.visits()],
        }
