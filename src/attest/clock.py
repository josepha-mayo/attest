from __future__ import annotations

import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

from .models import utcnow
from .store import Store


class ExecutionClock:
    def __init__(self, store: Store, *, replay: bool, ring_base_url: str):
        self.store = store
        self.replay = replay
        url = urlsplit(ring_base_url)
        if replay and (url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost", "::1")):
            raise ValueError("replay requires a loopback HTTP emulator, never the real Ring API")
        mode = "replay" if replay else "wall"
        with store.transaction():
            existing = store.setting("execution_mode")
            if existing and existing["mode"] != mode:
                raise ValueError("runtime clock mode cannot change; choose a separate data directory")
            if not existing:
                if replay and (store.sites() or store.workers() or store.visits() or store.schedules()):
                    raise ValueError("replay requires a fresh private runtime directory")
                store.put_setting("execution_mode", {"mode": mode})

    def snapshot(self) -> dict:
        state = self.store.setting("replay_clock") if self.replay else None
        return {
            "mode": "replay" if self.replay else "wall",
            "ready": not self.replay or state is not None,
            "replay_id": state["id"] if state else None,
            "now": state["at"] if state else (None if self.replay else utcnow().isoformat()),
        }

    def now(self) -> datetime:
        if not self.replay:
            return utcnow()
        state = self.store.setting("replay_clock")
        if state is None:
            raise ValueError("start the replay clock before creating schedules or events")
        return datetime.fromisoformat(state["at"])

    def _validate(self, at: datetime) -> datetime:
        if not self.replay:
            raise ValueError("replay controls are disabled")
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("replay time must include a UTC offset")
        if at > utcnow():
            raise ValueError("replay time cannot be in the future")
        return at.astimezone(UTC)

    def start(self, at: datetime) -> dict:
        at = self._validate(at)
        with self.store.transaction():
            if self.store.setting("replay_clock"):
                raise ValueError("replay already started; resume it or use a fresh runtime directory")
            self.store.put_setting("replay_clock", {"id": uuid.uuid4().hex, "at": at.isoformat()})
        return self.snapshot()

    def advance(self, at: datetime) -> dict:
        at = self._validate(at)
        with self.store.transaction():
            if at < self.now():
                raise ValueError("replay clock cannot rewind")
            state = self.store.setting("replay_clock")
            self.store.put_setting("replay_clock", {**state, "at": at.isoformat()})
        return self.snapshot()
