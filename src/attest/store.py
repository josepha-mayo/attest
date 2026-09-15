"""SQLite persistence. One table per entity, rows stored as JSON with a few indexed columns."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from .models import Evidence, Receipt, Schedule, Site, Visit, VisitState, Worker

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
CREATE INDEX IF NOT EXISTS ix_visits_site_state ON visits(site_id, state);
CREATE INDEX IF NOT EXISTS ix_evidence_visit ON evidence(visit_id, at);
CREATE INDEX IF NOT EXISTS ix_schedules_site ON schedules(site_id, window_start);
"""


def _iso(dt: datetime) -> str:
    return dt.isoformat()


class Store:
    def __init__(self, path: Path | str = ":memory:"):
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL") if path != ":memory:" else None
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ----------------------------------------------------------------- generic

    def _put(self, table: str, obj: BaseModel, **cols: object) -> None:
        cols = {"id": obj.id, **cols, "body": obj.model_dump_json()}  # type: ignore[attr-defined]
        names = ",".join(cols)
        marks = ",".join("?" * len(cols))
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO {table} ({names}) VALUES ({marks})", tuple(cols.values())
            )

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
        self._put("receipts", r, visit_id=r.visit_id, sequence=r.sequence)
        return r

    def receipt(self, receipt_id: str) -> Receipt | None:
        return self._one(Receipt, "SELECT body FROM receipts WHERE id=?", (receipt_id,))

    def receipt_for_visit(self, visit_id: str) -> Receipt | None:
        return self._one(Receipt, "SELECT body FROM receipts WHERE visit_id=?", (visit_id,))

    def latest_receipt(self) -> Receipt | None:
        return self._one(Receipt, "SELECT body FROM receipts ORDER BY sequence DESC")

    def receipts(self) -> list[Receipt]:
        return self._rows(Receipt, "SELECT body FROM receipts ORDER BY sequence")

    # ----------------------------------------------------------------- idempotency

    def mark_seen(self, request_id: str, at: datetime) -> bool:
        """Return True if new, False if this webhook request_id was already processed."""
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO seen_requests (request_id, seen_at) VALUES (?, ?)",
                    (request_id, _iso(at)),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    # ----------------------------------------------------------------- misc

    def dump(self) -> dict:
        return {
            "sites": [json.loads(s.model_dump_json()) for s in self.sites()],
            "workers": [json.loads(w.model_dump_json()) for w in self.workers()],
            "schedules": [json.loads(s.model_dump_json()) for s in self.schedules()],
            "visits": [json.loads(v.model_dump_json()) for v in self.visits()],
        }
