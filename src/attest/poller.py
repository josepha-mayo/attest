"""Event History poller: an ingest path for accounts that cannot receive webhooks.

Playground tokens (and any partner before webhook URLs are configured) get no webhook
deliveries, but ``GET /v1/history/devices/{id}/events`` still returns motion and doorbell
events. The poller turns new history events into the same v1.1 ``WebhookEvent`` shape the
engine consumes, using the history event id as ``request_id`` so idempotency holds across
restarts and across a later switch to real webhooks.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from ring_sandbox import RingAPIError, RingClient, WebhookEvent, webhooks
from ring_sandbox.models import HistoryEvent

from .engine import VisitEngine
from .store import Store

log = logging.getLogger("attest.poller")

# history filter -> (webhook type, sub_type)
_MAP = {
    "motion.human": ("motion_detected", "human"),
    "ding": ("button_press", None),
}


class HistoryPoller:
    def __init__(
        self, engine: VisitEngine, store: Store, ring: RingClient, *, lookback: timedelta | None = None
    ):
        self.engine, self.store, self.ring = engine, store, ring
        self.lookback = lookback or timedelta(minutes=30)
        self._started = datetime.now(tz=UTC)

    def poll_once(self) -> int:
        """Fetch recent human-motion and doorbell events for every bound camera; ingest new ones."""
        ingested = 0
        since = max(self._started - self.lookback, datetime.now(tz=UTC) - timedelta(hours=24))
        for site in self.store.sites():
            for filt, (etype, sub) in _MAP.items():
                try:
                    events = list(self.ring.events(site.door_camera_id, event_types=[filt], since=since))
                except RingAPIError as exc:
                    log.warning("history poll failed for %s (%s): %s", site.name, filt, exc)
                    continue
                for ev in sorted(events, key=lambda e: e.attributes.start):  # oldest first
                    if self.engine.ingest(
                        _to_webhook(ev, site.ring_account_id, etype, sub)
                    ).ignored_reason != ("duplicate request_id"):
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
