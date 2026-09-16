"""Event History poller: an ingest path for accounts that cannot receive webhooks.

Playground tokens (and any partner before webhook URLs are configured) get no webhook
deliveries, but ``GET /v1/history/devices/{id}/events`` still returns motion, doorbell,
and on-demand media events. The poller turns new history events into the same v1.1
``WebhookEvent`` shape the engine consumes, using the history event id as ``request_id``
so idempotency holds across restarts and across a later switch to real webhooks.

Verified against the live Playground: the server IGNORES the ``event_types`` filter, so
the returned ``attributes.event_type`` must be trusted and mapped client-side — and
Playground motion/doorbell triggers surface as ``on_demand`` entries, which we keep as
honest "media was requested" evidence rather than mislabeling them as doorbell presses.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from ring_sandbox import RingAPIError, RingClient, WebhookEvent, webhooks
from ring_sandbox.models import HistoryEvent

from .engine import VisitEngine
from .models import PollObservation
from .store import Store

log = logging.getLogger("attest.poller")

# real history event_type -> (webhook event type, sub_type). Unknown types are skipped:
# the record must carry what Ring actually reported, not a guess.
_MAP = {
    "ding": ("button_press", None),
    "motion": ("motion_detected", None),
    "on_demand": ("on_demand", None),
}


class HistoryPoller:
    def __init__(
        self, engine: VisitEngine, store: Store, ring: RingClient, *, lookback: timedelta | None = None
    ):
        self.engine, self.store, self.ring = engine, store, ring
        self.lookback = lookback or timedelta(minutes=30)
        self._started = datetime.now(tz=UTC)

    def poll_once(self) -> int:
        """Fetch recent history events for every bound camera; ingest new ones.

        Requests are unfiltered: the live API ignores ``event_types``, so the
        response's own ``attributes.event_type`` decides the mapping.
        """
        ingested = 0
        since = max(self._started - self.lookback, datetime.now(tz=UTC) - timedelta(hours=24))
        for site in self.store.sites():
            pending = {}
            seen = 0
            try:
                for ev in self.ring.events(site.door_camera_id, since=since):
                    if ev.device_id != site.door_camera_id:
                        continue
                    seen += 1
                    mapped = _MAP.get(ev.attributes.event_type)
                    if mapped is None:
                        log.info(
                            "history event %s has unhandled type %r; skipped",
                            ev.id,
                            ev.attributes.event_type,
                        )
                        continue
                    etype, sub = mapped
                    pending[ev.id] = _to_webhook(ev, site.ring_account_id, etype, sub)
            except RingAPIError as exc:
                log.warning("history poll failed for %s: HTTP %s", site.name, exc.status_code)
                self.store.put_poll_observation(
                    PollObservation(
                        site_id=site.id,
                        device_id=site.door_camera_id,
                        polled_at=datetime.now(tz=UTC),
                        since=since,
                        ok=False,
                        error=f"HTTP {exc.status_code}",
                    )
                )
                continue
            self.store.put_poll_observation(
                PollObservation(
                    site_id=site.id,
                    device_id=site.door_camera_id,
                    polled_at=datetime.now(tz=UTC),
                    since=since,
                    ok=True,
                    events_returned=seen,
                )
            )
            for ev in sorted(pending.values(), key=lambda e: (e.occurred_at, e.request_id)):  # oldest first
                outcome = self.engine.ingest(ev, source="history")
                if outcome.ignored_reason is None:
                    ingested += 1
        return ingested


def _to_webhook(ev: HistoryEvent, account_id: str, etype: str, sub: str | None) -> WebhookEvent:
    payload = webhooks.build_event(
        event_type=etype,
        device_id=ev.device_id or "",
        account_id=account_id,
        occurred_at=ev.attributes.started_at,
        sub_type=sub,
        request_id=f"history:{ev.id}",
    )
    return WebhookEvent.model_validate(payload)
