"""Visit engine: Ring events in, visit state transitions + evidence + receipts out.

State machine (per site, at most one active visit):

    (no visit) --arrival cue in a schedule window--> OPEN
    (no visit) --arrival cue, no schedule---------> UNMATCHED
    OPEN --worker check-in------------------------> IN_PROGRESS
    OPEN | IN_PROGRESS --departure cue------------> CLOSED (receipt issued)
    OPEN | IN_PROGRESS --idle timeout-------------> CLOSED (receipt issued, flagged)
    schedule window elapsed, no visit-------------> NO_OBSERVATION (receipt issued)

Arrival cues:  motion_detected(human) on the door camera, button_press, door opened (contact sensor).
Departure cue: door open->close, then motion_detected(human) within 2 min, once the visit is at
               least ``min_visit_minutes`` old. Or door closed with no camera activity for
               ``idle_close_minutes``.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import sqlite3
import statistics
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
from ring_sandbox import RingAPIError, RingClient, WebhookEvent

from .clock import ExecutionClock
from .config import Settings
from .errors import DomainError
from .ledger import Signer
from .media import MediaStore
from .models import (
    CheckinGrant,
    CoverageEvent,
    CoverageEventKind,
    Evidence,
    EvidenceKind,
    FamilyGrant,
    Flag,
    LiveViewSession,
    Receipt,
    Schedule,
    Site,
    Visit,
    VisitState,
    utcnow,
)
from .store import Store, atomic
from .summarize import Summarizer

log = logging.getLogger("attest.engine")

_ARRIVAL_MOTION = {"human"}
# Device-scoped lifecycle events recorded as coverage events — they explain why
# observation stopped or resumed, they are never visit cues.
_COVERAGE_DEVICE_EVENTS = {
    "device_offline",
    "device_online",
    "device_added",
    "device_removed",
    "subscription_activated",
    "subscription_deactivated",
}
_COVERAGE_ACCOUNT_EVENTS = {
    CoverageEventKind.APP_INTEGRATION_ADDED,
    CoverageEventKind.APP_INTEGRATION_REMOVED,
}
_DEPART_AFTER_DOOR_CLOSE = timedelta(minutes=2)
_MIN_VISIT = timedelta(minutes=3)


class NotYetAdmissible(ValueError):
    """Event timestamp lands past the ingestion tolerance — it becomes legal
    at ``admissible_at``. The inbox should reschedule to that instant rather
    than burn its retry budget on early arrivals (sender skew, batch flush)."""

    def __init__(self, admissible_at: datetime):
        super().__init__("event timestamp is in the future")
        self.admissible_at = admissible_at


@dataclass
class Outcome:
    visit: Visit | None = None
    transitions: list[str] = field(default_factory=list)
    ignored_reason: str | None = None


@dataclass
class _SnapshotFetch:
    """Bytes fetched from Ring OUTSIDE the write txn. ``ok=False`` (and no
    prefetch at all) degrades to the same media_unavailable flag a failed
    fetch produces — the ledger never waits on the network."""

    ok: bool
    content: bytes = b""
    content_type: str = "image/jpeg"
    actual_at: datetime | None = None


@dataclass
class _ClosePrefetch:
    """Everything `_close`/`_issue_receipt` needs from the network, fetched
    against committed state BEFORE the write txn. The apply path re-checks
    the token fields and degrades to the inline template summary / no
    history if the record moved since — identical outcomes to a failed
    fetch, so a hung Ring or Bedrock can never stall the write lock."""

    summary: tuple[str, str | None, str | None, str | None] | None = None
    history: list[dict] | None = None
    last_activity_at: datetime | None = None
    evidence_count: int = 0
    pending_evidence: int = 0
    receipt_absent: bool = True

    def matches(self, visit: Visit, n_evidence: int) -> bool:
        return (
            self.summary is not None
            and self.last_activity_at == visit.last_activity_at
            and self.evidence_count + self.pending_evidence == n_evidence
            and self.receipt_absent == (visit.receipt_id is None)
        )


@dataclass
class _NetBundle:
    snapshots: dict[str, _SnapshotFetch] = field(default_factory=dict)
    close: _ClosePrefetch | None = None


class VisitEngine:
    def __init__(
        self,
        store: Store,
        ring: RingClient,
        signer: Signer,
        media: MediaStore,
        summarizer: Summarizer,
        settings: Settings,
    ):
        self.store, self.ring, self.signer, self.media = store, ring, signer, media
        self.summarizer, self.settings = summarizer, settings
        self.clock = ExecutionClock(store, replay=settings.replay_mode, ring_base_url=ring.base_url)

    # ------------------------------------------------------------------ webhooks

    def ingest(self, ev: WebhookEvent, *, source: str = "webhook") -> Outcome:
        # Fetch any media/history/summary this event will need BEFORE the
        # write txn — a hung Ring or Bedrock must never hold the store lock.
        # The prefetch reads are advisory: `_ingest` re-derives the decision
        # under the lock and simply ignores prefetched data that no longer
        # applies (same outcome as a failed fetch).
        if source not in ("webhook", "history"):
            raise ValueError("invalid ingestion source")
        ev = ev.model_copy(update={"meta": ev.meta.model_copy(update={"ingest_source": source})})
        net = self._prefetch_event(ev, source)
        return self._ingest(ev, source, net)

    def _prefetch_event(self, ev: WebhookEvent, source: str) -> _NetBundle:
        bundle = _NetBundle()
        if source not in ("webhook", "history"):
            return bundle
        if ev.data.attributes.source_type == "accounts":
            return bundle
        site = self.store.site_for_device(ev.device_id)
        if site is None or ev.meta.account_id != site.ring_account_id or site.disconnected_at is not None:
            return bundle
        at = ev.occurred_at
        if (self.clock.replay and at > self.clock.now()) or at > utcnow() + timedelta(seconds=30):
            return bundle
        visit = self.store.active_visit(site.id)
        et, sub = ev.event_type, ev.sub_type
        is_camera = ev.device_id == site.door_camera_id
        human_motion = et == "motion_detected" and is_camera and sub in _ARRIVAL_MOTION
        opens = visit is None and (
            human_motion
            or (et == "button_press" and is_camera)
            or (et == "contact_sensor_faulted" and ev.device_id == site.door_sensor_id)
        )
        departs = (
            visit is not None
            and human_motion
            and at >= visit.last_activity_at
            and at - visit.arrived_at >= _MIN_VISIT
            and self._door_closed_recently(visit, at)
        )
        if opens:
            bundle.snapshots["first_observation"] = self._fetch_snapshot(site, at)
        if departs:
            snap = self._fetch_snapshot(site, at)
            bundle.snapshots["departure_cue"] = snap
            pending = [self._pending_evidence(visit, EvidenceKind.DEPARTURE_MOTION, at, ev)]
            if snap.ok:
                pending.append(self._pending_snapshot_evidence(visit, site, snap, "near departure cue"))
            bundle.close = self._prefetch_close(visit, site, at, "departure", pending)
        return bundle

    @atomic
    def _ingest(self, ev: WebhookEvent, source: str, net: _NetBundle) -> Outcome:
        # Account-scoped lifecycle events name the account, not a device, as
        # their source — they route to every site bound to that Ring account.
        if ev.data.attributes.source_type == "accounts":
            return self._on_account_event(ev, source)
        site = self.store.site_for_device(ev.device_id)
        if site is None:
            return Outcome(ignored_reason=f"device {ev.device_id} not bound to a site")
        if ev.meta.account_id != site.ring_account_id:
            return Outcome(ignored_reason="account mismatch")
        if site.disconnected_at is not None:
            return Outcome(
                ignored_reason=f"site's Ring source disconnected at {site.disconnected_at.isoformat()}"
            )
        if not self.store.bind_source(site.id, source):
            return Outcome(ignored_reason="ingestion source changed; reconciliation required")
        if not self.store.mark_seen(f"{site.ring_account_id}:{ev.request_id}", utcnow()):
            return Outcome(ignored_reason="duplicate request_id")
        at = ev.occurred_at
        if self.clock.replay and at > self.clock.now():
            raise ValueError("advance the replay clock before submitting this event")
        if at > utcnow() + timedelta(seconds=30):
            # Not poison - just early (sender clock skew, batch flush). The
            # inbox must retry once the event is admissible, not burn its
            # five-attempt budget on ~62s of exponential backoff.
            raise NotYetAdmissible(at - timedelta(seconds=30))
        is_camera = ev.device_id == site.door_camera_id
        et, sub = ev.event_type, ev.sub_type
        if et in _COVERAGE_DEVICE_EVENTS:
            # A lifecycle fact, not a visit cue: record it as coverage evidence
            # (explains observation gaps) regardless of visit state.
            detail: dict[str, str] = {}
            if ev.data.attributes.plan_id:
                detail["plan_id"] = ev.data.attributes.plan_id
            if ev.data.attributes.expires_at:
                detail["expires_at"] = ev.data.attributes.expires_at.isoformat()
            self.store.put_coverage_event(
                CoverageEvent(
                    site_id=site.id,
                    device_id=ev.device_id,
                    at=at,
                    kind=CoverageEventKind(et),
                    ring_request_id=ev.request_id if source == "webhook" else None,
                    detail=detail,
                )
            )
            return Outcome(ignored_reason=None)
        recent = self.store.visits(site_id=site.id, limit=1)
        if recent and (
            at < recent[0].last_activity_at
            or (
                recent[0].state in (VisitState.CLOSED, VisitState.NO_OBSERVATION)
                and at == recent[0].last_activity_at
            )
        ):
            self.store.record_late_event(
                f"{site.ring_account_id}:{ev.request_id}", site.id, ev.model_dump_json()
            )
            return Outcome(ignored_reason="late event retained for review")

        if et == "motion_detected" and is_camera:
            return self._on_motion(site, at, ev, human=sub in _ARRIVAL_MOTION, net=net)
        if et == "button_press" and is_camera:
            return self._on_arrival_cue(site, at, ev, EvidenceKind.DOORBELL, net)
        if et == "contact_sensor_faulted" and ev.device_id == site.door_sensor_id:
            return self._on_door(site, at, ev, opened=True, net=net)
        if et == "contact_sensor_cleared" and ev.device_id == site.door_sensor_id:
            return self._on_door(site, at, ev, opened=False, net=net)
        if et == "on_demand" and is_camera:
            # Media was requested from the camera (Ring history event_type=on_demand).
            # Attest's own close-time snapshot requests surface here too — if this
            # opened visits it would loop. Attach to an active visit only.
            visit = self.store.active_visit(site.id)
            if visit is None:
                return Outcome(ignored_reason="on-demand media request with no active visit")
            self._evidence(visit, EvidenceKind.ON_DEMAND, at, ev)
            self._touch(visit, at)
            return Outcome(visit, ["activity"])
        return Outcome(ignored_reason=f"{et}/{sub} not used by the visit engine")

    def _on_account_event(self, ev: WebhookEvent, source: str) -> Outcome:
        """Record an account-scoped lifecycle event (``app_integration_added`` /
        ``app_integration_removed``) as a coverage event on every still-bound site
        of that Ring account. An unlink does not disconnect sites — that stays an
        explicit operator action — it records why observation stopped."""
        et = ev.event_type
        if et not in _COVERAGE_ACCOUNT_EVENTS:
            return Outcome(ignored_reason=f"account-scoped {et} not used by the visit engine")
        sites = self.store.sites_for_account(ev.meta.account_id or "")
        if not sites:
            return Outcome(ignored_reason=f"account {ev.meta.account_id} has no sites")
        at = ev.occurred_at
        if self.clock.replay and at > self.clock.now():
            raise ValueError("advance the replay clock before submitting this event")
        if at > utcnow() + timedelta(seconds=30):
            # Not poison - just early (sender clock skew, batch flush). The
            # inbox must retry once the event is admissible, not burn its
            # five-attempt budget on ~62s of exponential backoff.
            raise NotYetAdmissible(at - timedelta(seconds=30))
        recorded = 0
        for site in sites:
            if site.disconnected_at is not None:
                continue
            if not self.store.bind_source(site.id, source):
                continue
            # Per-site dedupe: one account event lands on each bound site once.
            if not self.store.mark_seen(f"{site.ring_account_id}:{site.id}:{ev.request_id}", utcnow()):
                continue
            self.store.put_coverage_event(
                CoverageEvent(
                    site_id=site.id,
                    at=at,
                    kind=CoverageEventKind(et),
                    ring_request_id=ev.request_id if source == "webhook" else None,
                )
            )
            recorded += 1
        if not recorded:
            return Outcome(ignored_reason="duplicate request_id or no bound sites")
        return Outcome(ignored_reason=None)

    # ------------------------------------------------------------------ cues

    def _on_motion(
        self, site: Site, at: datetime, ev: WebhookEvent, *, human: bool, net: _NetBundle
    ) -> Outcome:
        visit = self.store.active_visit(site.id)
        if visit is None:
            if not human:
                return Outcome(ignored_reason="non-human motion with no active visit")
            return self._on_arrival_cue(site, at, ev, EvidenceKind.ARRIVAL_MOTION, net)
        # Departure: door closed recently, then a person walks away past the camera.
        if human and self._door_closed_recently(visit, at) and at - visit.arrived_at >= _MIN_VISIT:
            self._evidence(visit, EvidenceKind.DEPARTURE_MOTION, at, ev)
            self._snapshot(
                visit,
                site,
                at,
                "departure_cue",
                "near departure cue",
                net.snapshots.get("departure_cue"),
            )
            return self._close(visit, site, at, reason="departure", net=net.close)
        self._evidence(visit, EvidenceKind.ACTIVITY, at, ev)
        self._touch(visit, at)
        return Outcome(visit, ["activity"])

    def _on_door(
        self, site: Site, at: datetime, ev: WebhookEvent, *, opened: bool, net: _NetBundle
    ) -> Outcome:
        visit = self.store.active_visit(site.id)
        kind = EvidenceKind.DOOR_OPENED if opened else EvidenceKind.DOOR_CLOSED
        if visit is None:
            if opened:
                return self._on_arrival_cue(site, at, ev, kind, net)
            return Outcome(ignored_reason="door closed with no active visit")
        self._evidence(visit, kind, at, ev)
        self._touch(visit, at)
        return Outcome(visit, [kind.value])

    def _on_arrival_cue(
        self, site: Site, at: datetime, ev: WebhookEvent, kind: EvidenceKind, net: _NetBundle
    ) -> Outcome:
        visit = self.store.active_visit(site.id)
        if visit is not None:
            self._evidence(visit, kind, at, ev)
            self._touch(visit, at)
            return Outcome(visit, ["activity"])
        schedule = self._matching_schedule(site, at)
        visit = Visit(
            site_id=site.id,
            schedule_id=schedule.id if schedule else None,
            worker_id=None,
            state=VisitState.OPEN if schedule else VisitState.UNMATCHED,
            arrived_at=at,
            last_activity_at=at,
            clock_mode=self.clock.snapshot()["mode"],
            replay_id=self.clock.snapshot()["replay_id"],
        )
        if schedule and at < schedule.window_start:
            visit.flags.append(
                Flag(
                    code="early",
                    severity="info",
                    message=(
                        f"first device observation {_mins(schedule.window_start - at)} "
                        "min before the scheduled window"
                    ),
                )
            )
        if schedule and at > schedule.window_end:
            visit.flags.append(
                Flag(
                    code="late",
                    severity="warn",
                    message=(
                        f"first device observation {_mins(at - schedule.window_end)} "
                        "min after the window closed"
                    ),
                )
            )
        if not schedule:
            visit.flags.append(
                Flag(
                    code="unscheduled",
                    severity="warn",
                    message="device activity with no scheduled visit in window",
                )
            )
        self.store.put_visit(visit)
        self._evidence(visit, kind, at, ev)
        self._snapshot(
            visit,
            site,
            at,
            "first_observation",
            "first-observation window",
            net.snapshots.get("first_observation"),
        )
        log.info("visit %s opened at %s (%s)", visit.id, at.isoformat(), visit.state)
        return Outcome(visit, ["opened"])

    # ------------------------------------------------------------------ check-in

    @atomic
    def issue_checkin(self, visit_id: str) -> str:
        visit = self.store.visit(visit_id)
        if not visit or visit.state not in (VisitState.OPEN, VisitState.UNMATCHED):
            raise ValueError("visit is not awaiting check-in")
        schedule = self._schedule(visit)
        if not schedule or not self.store.worker(schedule.worker_id):
            raise ValueError("a scheduled worker is required")
        token = secrets.token_urlsafe(32)
        self.store.put_checkin_grant(
            CheckinGrant(
                id=visit.id,
                worker_id=schedule.worker_id,
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=utcnow() + timedelta(minutes=15),
            )
        )
        return token

    def issue_family_link(self, visit_id: str) -> str:
        visit = self.store.visit(visit_id)
        if visit is None:
            raise ValueError("unknown visit")
        token = secrets.token_urlsafe(32)
        self.store.put_family_grant(
            FamilyGrant(
                id=visit.id,
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=utcnow() + timedelta(days=7),
            )
        )
        return token

    def family_target(self, token: str) -> Visit | None:
        grant = self.store.family_grant(hashlib.sha256(token.encode()).hexdigest())
        if grant is None or grant.expires_at <= utcnow():
            return None
        return self.store.visit(grant.id)

    def revoke_family_link(self, visit_id: str) -> bool:
        """Delete the visit's family grant — the journaled delete makes the
        revocation part of the mutation log, not a silent row removal."""
        return bool(self.store.delete_family_grants([visit_id]))

    def checkin_target(self, token: str):
        grant = self.store.checkin_grant(hashlib.sha256(token.encode()).hexdigest())
        if grant is None or grant.used_at or grant.expires_at <= utcnow():
            return None
        visit = self.store.visit(grant.id)
        if not visit or visit.checked_in_at or visit.state not in (VisitState.OPEN, VisitState.UNMATCHED):
            return None
        schedule = self._schedule(visit)
        worker = self.store.worker(grant.worker_id)
        if not schedule or schedule.worker_id != grant.worker_id or worker is None:
            return None
        return grant, visit, worker

    @atomic
    def check_in(self, token: str, at: datetime | None = None) -> Visit | None:
        at = at or self.clock.now()
        target = self.checkin_target(token)
        if target is None:
            return None
        grant, visit, worker = target
        if at < visit.arrived_at:
            raise DomainError(
                "checkin_precedes_observation",
                "check-in cannot precede first observation",
            )
        grant.used_at = utcnow()
        self.store.put_checkin_grant(grant)
        if visit is not None:
            visit.worker_id = worker.id
            visit.checked_in_at = at
            visit.checkin_received_at = utcnow()
            # An UNMATCHED visit becomes a real one once a known worker claims it; the
            # "unscheduled" flag stays on the record.
            visit.state = VisitState.IN_PROGRESS
            visit.last_seen_at = utcnow()
            self.store.put_visit(visit)
            self.store.put_evidence(
                Evidence(
                    visit_id=visit.id,
                    kind=EvidenceKind.CHECKIN,
                    at=at,
                    note=f"Worker check-in self-reported using the link issued to {worker.name}; "
                    "not identity-verified",
                )
            )
            return visit
        return None

    # ------------------------------------------------------------------ sweeper

    def sweep(self, now: datetime | None = None) -> list[Visit]:
        """Close idle visits and lapse elapsed schedules to no_observation. Call periodically.

        Idleness is *webhook silence* (wall clock since the last cue we ingested), not the
        event timestamp: Ring retries can deliver late, and replayed scenarios are back-dated.
        """
        now = now or self.clock.now()
        nets = self._prefetch_sweep(now)
        return self._sweep(now, nets)

    def _prefetch_sweep(self, now: datetime) -> dict[str, _NetBundle]:
        """Fetch snapshots/summaries/history for visits that look idle-closeable
        BEFORE the write txn (advisory reads; the apply path re-validates)."""
        if self.clock.replay:
            return {}
        idle = timedelta(minutes=self.settings.idle_close_minutes)
        nets: dict[str, _NetBundle] = {}
        for site in self.store.sites():
            visit = self.store.active_visit(site.id)
            if not visit or now - visit.last_seen_at < idle:
                continue
            bundle = _NetBundle()
            snap = self._fetch_snapshot(site, visit.last_activity_at)
            bundle.snapshots["last_observation"] = snap
            pending = (
                [self._pending_snapshot_evidence(visit, site, snap, "last-observation window")]
                if snap.ok
                else []
            )
            bundle.close = self._prefetch_close(visit, site, visit.last_activity_at, "idle", pending)
            nets[visit.id] = bundle
        return nets

    @atomic
    def _sweep(self, now: datetime, nets: dict[str, _NetBundle]) -> list[Visit]:
        changed: list[Visit] = []
        idle = timedelta(minutes=self.settings.idle_close_minutes)
        for site in self.store.sites():
            visit = self.store.active_visit(site.id)
            if visit and not self.clock.replay and now - visit.last_seen_at >= idle:
                net = nets.get(visit.id) or _NetBundle()
                if site.door_sensor_id is None:
                    # Camera-only site: the last person seen at the door is the best departure evidence.
                    flag = Flag(
                        code="observation_gap",
                        severity="warn",
                        message="No recent camera observations; departure and continued presence are unknown "
                        f"({self.settings.idle_close_minutes} min without a new observation)",
                    )
                else:
                    flag = Flag(
                        code="idle_close",
                        severity="info",
                        message=f"closed after {self.settings.idle_close_minutes} min without activity",
                    )
                visit.flags.append(flag)
                self._snapshot(
                    visit,
                    site,
                    visit.last_activity_at,
                    "last_observation",
                    "last-observation window",
                    net.snapshots.get("last_observation"),
                )
                changed.append(
                    self._close(visit, site, visit.last_activity_at, reason="idle", net=net.close).visit
                )
            grace = timedelta(minutes=self.settings.arrival_grace_minutes)
            for sch in self.store.schedules_for_site(site.id):
                if (
                    sch.status == "scheduled"
                    and sch.window_end + grace < now
                    and self.store.visit_for_schedule(sch.id) is None
                ):
                    ns = Visit(
                        site_id=site.id,
                        schedule_id=sch.id,
                        worker_id=None,
                        state=VisitState.NO_OBSERVATION,
                        arrived_at=sch.window_start,
                        last_activity_at=sch.window_end,
                        closed_at=now,
                        close_reason="window_elapsed",
                        summary_source="template",
                        clock_mode=self.clock.snapshot()["mode"],
                        replay_id=self.clock.snapshot()["replay_id"],
                        flags=[
                            Flag(
                                code="no_observation",
                                severity="warn",
                                message="No matching observation was received; "
                                "attendance and coverage are unknown",
                            )
                        ],
                    )
                    ns.summary = "No matching observation was received. This does not establish a no-show."
                    self.store.put_visit(ns)
                    self._issue_receipt(ns, site)
                    changed.append(ns)
        return changed

    # ------------------------------------------------------------------ closing

    def close_for_review(self, visit_id: str) -> Visit:
        net = self._prefetch_close_for(visit_id)
        return self._close_for_review_apply(visit_id, net)

    def _prefetch_close_for(self, visit_id: str) -> _ClosePrefetch | None:
        """Fetch summary + history for a coordinator close BEFORE the write
        txn, against committed state. Returns None when nothing is closeable —
        the apply path raises the same validation errors as before."""
        visit = self.store.visit(visit_id)
        if visit is None or visit.receipt_id:
            return None
        site = self.store.site(visit.site_id)
        if site is None:
            return None
        return self._prefetch_close(visit, site, visit.last_activity_at, "coordinator_review", [])

    @atomic
    def _close_for_review_apply(self, visit_id: str, net: _ClosePrefetch | None) -> Visit:
        visit = self.store.visit(visit_id)
        if visit is None or visit.receipt_id:
            raise ValueError("record is missing or already signed")
        site = self.store.site(visit.site_id)
        if site is None:
            raise ValueError(
                "site record is gone — a receipt would name a source binding "
                "that no longer exists; cannot sign"
            )
        self._close(visit, site, visit.last_activity_at, reason="coordinator_review", net=net)
        return visit

    def _prefetch_close(
        self,
        visit: Visit,
        site: Site,
        at: datetime,
        reason: str,
        pending: list[Evidence],
    ) -> _ClosePrefetch:
        """Replicate `_close`'s mutations on a copy so the summary sees exactly
        the inputs it would inside the txn — but the Bedrock/Ring calls happen
        here, before the lock is taken."""
        vcopy = visit.model_copy(deep=True)
        self._close_mutations(vcopy, at, reason)
        evidence = self.store.evidence_for(visit.id)
        sch = self._schedule(visit)
        text = self.summarizer.summarize(
            vcopy, site, sch, self._worker_name(visit), [*evidence, *pending], self.media
        )
        return _ClosePrefetch(
            summary=(text, vcopy.summary_source, vcopy.summary_model, vcopy.summary_fallback_reason),
            history=self._fetch_history(visit, site),
            last_activity_at=max(visit.last_activity_at, at),
            evidence_count=len(evidence),
            pending_evidence=len(pending),
            receipt_absent=visit.receipt_id is None,
        )

    def _close(
        self, visit: Visit, site: Site, at: datetime, *, reason: str, net: _ClosePrefetch | None = None
    ) -> Outcome:
        self._close_mutations(visit, at, reason)
        evidence = self.store.evidence_for(visit.id)
        if net is not None and net.matches(visit, len(evidence)):
            (
                visit.summary,
                visit.summary_source,
                visit.summary_model,
                visit.summary_fallback_reason,
            ) = net.summary  # type: ignore[misc]
            history = net.history
        else:
            # State moved since prefetch (or nothing prefetched) — the write
            # txn never waits on the network; fall back to the deterministic
            # summary path and sign without a history cross-check.
            visit.summary = self._degraded_summarizer().summarize(
                visit, site, self._schedule(visit), self._worker_name(visit), evidence, self.media
            )
            history = None
        self.store.put_visit(visit)
        self._issue_receipt(visit, site, history=history)
        log.info(
            "record %s closed (%s); observed interval %.1f min",
            visit.id,
            reason,
            visit.observed_span_minutes or 0,
        )
        return Outcome(visit, ["closed"])

    def _degraded_summarizer(self) -> Summarizer:
        """A no-network summarizer for the degrade path — Bedrock's own
        template fallback, or the summarizer itself when it's already
        deterministic."""
        fb = getattr(self.summarizer, "fallback", None)
        return fb if fb is not None else self.summarizer

    def _close_mutations(self, visit: Visit, at: datetime, reason: str) -> None:
        """The state changes `_close` applies — shared verbatim with
        `_prefetch_close`, which runs them on a copy to build the summary's
        inputs before the write txn starts."""
        visit.departed_at = None
        visit.departure_candidate_at = at if reason == "departure" else None
        visit.last_activity_at = max(visit.last_activity_at, at)
        visit.closed_at = self.clock.now()
        visit.close_reason = reason
        visit.state = VisitState.CLOSED
        visit.flags.append(
            Flag(
                code="departure_unconfirmed",
                severity="warn",
                message="Record closed for review; "
                "direction, identity, and continuous presence are not established",
            )
        )
        if reason == "departure" and visit.checked_in_at and visit.checked_in_at > at:
            visit.flags.append(
                Flag(
                    code="clock_conflict",
                    severity="warn",
                    message="Check-in was received after the last observed event; "
                    "review replay or delayed delivery",
                )
            )
        self._apply_duration_flags(visit)
        if visit.checked_in_at is None and visit.schedule_id:
            visit.flags.append(
                Flag(
                    code="no_checkin",
                    severity="warn",
                    message="no worker self-report was received through the check-in link",
                )
            )

    def _apply_duration_flags(self, visit: Visit) -> None:
        sch = self._schedule(visit)
        if sch is None or visit.observed_span_minutes is None:
            return
        ratio = visit.observed_span_minutes / sch.expected_minutes if sch.expected_minutes else 1
        if ratio < 0.5:
            visit.flags.append(
                Flag(
                    code="observed_interval_short",
                    severity="warn",
                    message=f"Observations span {visit.observed_span_minutes:.0f} min; "
                    f"{sch.expected_minutes} min scheduled. Time worked is unknown",
                )
            )
        elif ratio < 0.8:
            visit.flags.append(
                Flag(
                    code="observed_interval_short",
                    severity="warn",
                    message=f"Observations span {visit.observed_span_minutes:.0f} min; "
                    f"{sch.expected_minutes} min scheduled. Time worked is unknown",
                )
            )

    def _issue_receipt(self, visit: Visit, site: Site, *, history: list[dict] | None = None) -> None:
        prev = self.store.latest_receipt()
        sch = self._schedule(visit)
        evidence = self.store.evidence_for(visit.id)
        scheduled_worker = self.store.worker(sch.worker_id) if sch else None
        facts = {
            "visit_id": visit.id,
            "state": visit.state.value,
            "clock": {
                "mode": visit.clock_mode,
                "replay_id": visit.replay_id,
                "checkin_received_at": visit.checkin_received_at.isoformat()
                if visit.checkin_received_at
                else None,
                "issuance_uses_wall_clock": True,
            },
            "data_origin": "ring_api"
            if self.ring.base_url == "https://api.amazonvision.com"
            else "local_or_test",
            "site": {
                "id": site.id,
                "name": site.name,
                "ring_account_id": site.ring_account_id,
                "door_camera_id": site.door_camera_id,
                "door_sensor_id": site.door_sensor_id,
            },
            "worker": self._worker_name(visit),
            "worker_id": visit.worker_id,
            "scheduled_worker": (
                {"id": scheduled_worker.id, "name": scheduled_worker.name} if scheduled_worker else None
            ),
            "schedule": (
                {
                    "id": sch.id,
                    "window_start": sch.window_start.isoformat(),
                    "window_end": sch.window_end.isoformat(),
                    "expected_minutes": sch.expected_minutes,
                    "service": sch.service,
                }
                if sch
                else None
            ),
            "first_observed_at": visit.arrived_at.isoformat() if visit.has_observations else None,
            "last_observed_at": visit.last_activity_at.isoformat() if visit.has_observations else None,
            "checked_in_at": visit.checked_in_at.isoformat() if visit.checked_in_at else None,
            "departure_candidate_at": (
                visit.departure_candidate_at.isoformat() if visit.departure_candidate_at else None
            ),
            "departed_at": None,
            "duration_minutes": None,
            "observed_span_minutes": visit.observed_span_minutes,
            # 42 USC 1396b(l)(5)(A) crosswalk — every statutorily-required EVV
            # element mapped to the basis this record can actually establish.
            # A crosswalk, not a submission: each basis is the honest qualifier.
            "cures_act_elements": {
                "status": "corroboration_map_only_not_an_evv_submission",
                "service_type": {
                    "value": sch.service if sch else None,
                    "basis": "scheduled_expectation_not_verified_performed",
                },
                "individual_receiving": {
                    "value": site.name,
                    "basis": "premises_not_a_verified_person",
                },
                "date": {
                    "value": sch.window_start.date().isoformat() if sch else None,
                    "basis": "scheduled_date_observation_timestamps_are_device_reported",
                },
                "location": {
                    "value": site.door_camera_id,
                    "basis": "device_anchored_at_premises_not_gps",
                },
                "individual_providing": {
                    "value": scheduled_worker.name if scheduled_worker else visit.worker_id,
                    "basis": "scheduled_worker_plus_self_report_identity_unverified",
                },
                "time_begins_ends": {
                    "value": [
                        visit.arrived_at.isoformat() if visit.has_observations else None,
                        visit.last_activity_at.isoformat() if visit.has_observations else None,
                    ],
                    "basis": "observed_interval_bounds_never_time_worked",
                },
            },
            "assessment": {
                "attendance": "self_reported" if visit.checked_in_at else "unknown",
                "identity_verified": False,
                "departure_verified": False,
                "time_worked_minutes": None,
                "requires_review": True,
                "signature_scope": "record_integrity_only",
            },
            "closed_at": visit.closed_at.isoformat() if visit.closed_at else None,
            "close_reason": visit.close_reason,
            "flags": [f.model_dump() for f in visit.flags],
            "summary": visit.summary,
            "summary_provenance": {
                "source": visit.summary_source,
                "model": visit.summary_model,
                "fallback_reason": visit.summary_fallback_reason,
                "is_attendance_evidence": False,
            },
            "evidence": [
                {
                    "kind": e.kind.value,
                    "at": e.at.isoformat(),
                    "device": e.source_device_id,
                    "ring_event": e.ring_event_type,
                    "ring_sub_type": e.ring_sub_type,
                    "ring_request_id": e.ring_request_id,
                    "ring_history_event_id": e.ring_history_event_id,
                    "ingestion_source": e.ingestion_source,
                    "media_sha256": e.media_sha256,
                }
                for e in evidence
            ],
            "history_poll_coverage": self._coverage(visit, site),
            "ring_history": history,
            "journal_head": self.store.journal_head(),
        }
        receipt = self.signer.issue(
            visit_id=visit.id,
            sequence=(prev.sequence + 1 if prev else 1),
            prev_hash=prev.payload_hash if prev else None,
            facts=facts,
        )
        self.store.put_receipt(receipt)
        visit.receipt_id = receipt.id
        self.store.put_visit(visit)

    # ------------------------------------------------------------------ helpers

    @atomic
    def issue_coverage_attestation(self, site: Site, start: datetime, end: datetime) -> Receipt:
        """Sign a coverage attestation for an arbitrary interval — chain-linked but
        visit-independent. "We polled K times and Ring returned M events" is a
        standalone signed answer to "was anyone watching?" — never to absence."""
        from .coverage import coverage_report

        device = site.door_camera_id or site.door_sensor_id
        report = coverage_report(self.store, device, start, end, now=self.clock.now(), site_id=site.id)
        if report.get("state") == "no_window":
            # An inverted or not-yet-arrived window has nothing to attest —
            # signing one would put the deployment's key on an empty claim.
            raise ValueError("coverage window is empty (end <= start after clamping to now)")
        pseudo_id = f"coverage:{site.id}:{start.isoformat()}:{end.isoformat()}"
        existing = self.store.receipt_for_visit(pseudo_id)
        if existing:
            return existing
        prev = self.store.latest_receipt()
        receipt = self.signer.issue(
            visit_id=pseudo_id,
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "coverage_attestation",
                "site": {"id": site.id, "name": site.name},
                "device_id": device,
                "coverage": report,
                "boundary": (
                    "Attests what the pipeline observed and when it was blind — "
                    "never identity, attendance, or absence."
                ),
                "journal_head": self.store.journal_head(),
            },
        )
        try:
            self.store.put_receipt(receipt)
        except sqlite3.IntegrityError:
            return self.store.receipt_for_visit(pseudo_id)
        return receipt

    @atomic
    def issue_period_digest(self, site: Site, start: datetime, end: datetime) -> Receipt:
        """Sign a digest of the *records* written for an interval — visit counts by
        outcome, review counts by stance, and exactly which receipts it summarizes.
        Counts of signed records, never claims about physical presence."""
        from .coverage import coverage_report

        if end <= start:
            raise ValueError("digest window is empty (end <= start) — nothing to summarize")
        pseudo_id = f"digest:{site.id}:{start.isoformat()}:{end.isoformat()}"
        existing = self.store.receipt_for_visit(pseudo_id)
        if existing:
            return existing
        visits = [
            v
            for v in self.store.visits(site_id=site.id, limit=10_000)
            if v.arrived_at is not None and start <= v.arrived_at <= end
        ]
        entries = [e for v in visits for e in self.store.reviews_for(v.id)]

        def _role(e) -> str:
            a = e.receipt.payload.get("actor")
            return a.get("role", "") if isinstance(a, dict) else ""

        worker_entries = [e for e in entries if _role(e) == "worker"]
        household_entries = [e for e in entries if _role(e) == "household"]
        resolution_entries = [
            e
            for e in entries
            if isinstance(e.receipt.payload.get("review"), dict)
            and e.receipt.payload["review"].get("kind") == "resolution"
        ]
        # The dispute loop closing is itself a ledger metric: how many records
        # carry a signed conclusion, and how long first-worker-statement ->
        # conclusion took. "Resolved" uses the same derivation every other
        # surface does — latest resolution post-dates latest worker statement —
        # so a re-opened record does not count as resolved. Ledger time only.
        resolved_records, resolution_lags = 0, []
        reason_histogram: dict[str, int] = {}
        for v in visits:
            v_entries = self.store.reviews_for(v.id)
            worker_ats = [
                e.receipt.payload.get("statement_received_at") for e in v_entries if _role(e) == "worker"
            ]
            res_entries = [
                e
                for e in v_entries
                if isinstance(e.receipt.payload.get("review"), dict)
                and e.receipt.payload["review"].get("kind") == "resolution"
            ]
            res_ats = [e.receipt.payload.get("statement_received_at") for e in res_entries]
            if not res_ats or res_ats[-1] is None:
                continue
            try:
                latest_res = datetime.fromisoformat(res_ats[-1])
                first_worker = datetime.fromisoformat(worker_ats[0]) if worker_ats and worker_ats[0] else None
            except (TypeError, ValueError):
                continue  # corrupt journal-adjacent data — omit rather than sign garbage
            # Re-opened uses the same derivation as countersign_status — chain
            # revision order, not wall-clock stamps that can tie or step back.
            worker_entries_v = [e for e in v_entries if _role(e) == "worker"]
            if worker_entries_v and worker_entries_v[-1].revision > res_entries[-1].revision:
                continue  # a later worker statement re-opened the record
            resolved_records += 1
            reason = res_entries[-1].receipt.payload["review"].get("reason_code")
            if reason:
                reason_histogram[reason] = reason_histogram.get(reason, 0) + 1
            if first_worker:
                lag = (latest_res - first_worker).total_seconds() / 60
                if lag >= 0:
                    resolution_lags.append(lag)
        receipts = {
            r.visit_id: r.payload_hash for r in self.store.receipts() if r.visit_id in {v.id for v in visits}
        }
        counts = {
            "visits_observed": sum(1 for v in visits if v.has_observations and v.schedule_id),
            "visits_no_observation": sum(1 for v in visits if v.state == VisitState.NO_OBSERVATION),
            "visits_unmatched": sum(1 for v in visits if not v.schedule_id),
            "worker_statements": len(worker_entries),
            "worker_disputes": sum(
                1
                for e in worker_entries
                if isinstance(e.receipt.payload.get("review"), dict)
                and e.receipt.payload["review"].get("decision") == "dispute"
            ),
            "household_statements": len(household_entries),
            "coordinator_statements": len(entries)
            - len(worker_entries)
            - len(household_entries)
            - len(resolution_entries),
            "coordinator_resolutions": len(resolution_entries),
            "records_resolved": resolved_records,
            # Which coded reasons stand behind currently-resolved records —
            # signed so the exception pattern itself is auditable.
            "resolution_reasons": dict(sorted(reason_histogram.items())),
            "median_resolution_minutes": (
                round(statistics.median(resolution_lags), 1) if resolution_lags else None
            ),
            # Streams brokered in the interval — a journaled-fact count, never
            # a claim about who watched or what was on screen.
            "liveview_sessions": sum(
                1
                for s in self.store.liveview_sessions(site.id, start, end, limit=None)
                if s.state != "failed"
            ),
        }
        device = site.door_camera_id or site.door_sensor_id
        prev = self.store.latest_receipt()
        receipt = self.signer.issue(
            visit_id=pseudo_id,
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "period_digest",
                "site": {"id": site.id, "name": site.name},
                "interval": {"start": start.isoformat(), "end": end.isoformat()},
                "counts": counts,
                "summarized_receipts": receipts,
                "coverage": coverage_report(
                    self.store, device, start, end, now=self.clock.now(), site_id=site.id
                ),
                "boundary": (
                    "Counts the signed records this deployment wrote in the interval — "
                    "a statement about the ledger, never about physical presence or absence."
                ),
                "journal_head": self.store.journal_head(),
            },
        )
        try:
            self.store.put_receipt(receipt)
        except sqlite3.IntegrityError:
            return self.store.receipt_for_visit(pseudo_id)
        return receipt

    def maybe_period_digest(self, site: Site, interval_s: int) -> Receipt | None:
        """Cadence-driven self-summarization: when the newest period digest's
        window ended more than ``interval_s`` ago, sign a new digest continuing
        from where it stopped; with no prior digest, cover the trailing
        interval. The ledger keeps summarizing itself without an operator."""
        if interval_s <= 0:
            return None
        now = self.clock.now()
        digests = [
            r
            for r in self.store.receipts()
            if r.visit_id.startswith(f"digest:{site.id}:") and r.payload.get("record_type") == "period_digest"
        ]
        ends = [
            datetime.fromisoformat(r.payload["interval"]["end"])
            for r in digests
            if r.payload.get("interval", {}).get("end")
        ]
        if ends:
            end = max(ends)
            if now - end < timedelta(seconds=interval_s):
                return None
            start = end
        else:
            start = now - timedelta(seconds=interval_s)
        return self.issue_period_digest(site, start, now)

    @atomic
    def issue_export_manifest(self, site: Site, manifest: dict) -> Receipt:
        """Sign a case-pack manifest: the export itself becomes a chain event
        naming exactly which receipt hashes it carries. A pack that drops or
        swaps a record then fails verification — not just a missing file.
        Idempotent per identical manifest content via an ``export:`` pseudo
        visit_id; never a statement about physical presence."""
        import hashlib
        import json as _json

        canonical = _json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        pseudo_id = f"export:{site.id}:{digest[:16]}"
        existing = self.store.receipt_for_visit(pseudo_id)
        if existing:
            return existing
        prev = self.store.latest_receipt()
        receipt = self.signer.issue(
            visit_id=pseudo_id,
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "case_export",
                "site": {"id": site.id, "name": site.name},
                "generated_at": manifest["generated_at"],
                "manifest_sha256": digest,
                "visit_count": len(manifest["visits"]),
                "receipt_hashes": {v["visit_id"]: v["payload_hash"] for v in manifest["visits"]},
                "media_redacted": manifest["media_redacted"],
                "boundary": (
                    "A signed statement that exactly these records existed at export "
                    "time — dropping or swapping one invalidates the pack."
                ),
                "journal_head": self.store.journal_head(),
            },
        )
        try:
            self.store.put_receipt(receipt)
        except sqlite3.IntegrityError:
            return self.store.receipt_for_visit(pseudo_id)
        return receipt

    @atomic
    def issue_verification_report(self, report: dict) -> Receipt:
        """Sign a verify-live sweep into the chain: 'this deployment ran the
        official-API checks at this time and these are the results.' An
        unsigned report file could be edited to upgrade a fail to a pass
        before a judge sees it; a chained receipt cannot. Idempotent per
        identical report content via a ``verify:`` pseudo visit_id."""
        import hashlib
        import json as _json

        canonical = _json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        pseudo_id = f"verify:{digest[:16]}"
        existing = self.store.receipt_for_visit(pseudo_id)
        if existing:
            return existing
        prev = self.store.latest_receipt()
        receipt = self.signer.issue(
            visit_id=pseudo_id,
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "verification_report",
                "generated_at": report["generated_at"],
                "base_url": report["base_url"],
                "checks": report["checks"],
                "summary": report["summary"],
                "boundary": (
                    "A signed statement that these checks ran at this time and "
                    "returned these results — a PASS attests the API call "
                    "succeeded, never the semantics beyond it."
                ),
                "journal_head": self.store.journal_head(),
            },
        )
        try:
            self.store.put_receipt(receipt)
        except sqlite3.IntegrityError:
            return self.store.receipt_for_visit(pseudo_id)
        return receipt

    @contextmanager
    def signing_barrier(self):
        """Hold the store write lock across a multi-step signing sequence.

        ``@atomic`` methods keep their own transactions (the lock is an
        RLock, so nested acquisitions re-enter and each step still commits
        independently) — but no other ``@atomic`` issuance can interleave
        between the steps. Key rotation needs exactly this: a receipt signed
        between the rotation commit and the signer swap would land under the
        retired key post-pivot and break the chain for good."""
        with self.store._lock:  # noqa: SLF001 — engine is the store's writer peer
            yield

    def resume_pending_adoptions(self) -> list[Receipt]:
        """Countersign any unconsented rotation endorsing THIS signer — the
        recovery path for a crash between successor persist and adoption.
        Each adoption is idempotent via its ``key:``:``adopted`` pseudo
        visit_id, so calling this on boot and before every rotate is safe:
        a fully consummated history returns []."""
        from .ledger import _adoption_consent

        new_key = self.signer.public_key_b64
        receipts = self.store.receipts()
        issued = []
        for r in receipts:
            p = r.payload
            if (
                p.get("record_type") == "key_rotation"
                and p.get("new_key") == new_key
                and not _adoption_consent(receipts, r, new_key)
            ):
                issued.append(self.issue_key_adoption(p["previous_key"], r))
        return issued

    @atomic
    def issue_key_rotation(self, new_public_key: str, reason: str = "") -> Receipt:
        """Sign, under the CURRENT issuer key, that it retires in favor of the
        named successor. The receipt is the chain's pivot: every receipt before
        it verifies under the retiring key, every receipt after under the new
        one — ``verify_chain`` reads it as a key transition, not a break.
        Idempotent per (old, new) pair via a ``key:`` pseudo visit_id. The
        successor holder should then countersign via ``issue_key_adoption`` —
        the pivot alone proves the retiring key asserted the change; the
        adoption proves the new key holder consented to it."""
        old_key = self.signer.public_key_b64
        if new_public_key == old_key:
            raise ValueError("rotation to the same key is a no-op")
        used = {r.public_key for r in self.store.receipts()}
        if new_public_key in used:
            raise ValueError(
                "successor key already signed receipts — re-adopting a retired "
                "key would make lineage non-monotonic; generate a fresh key"
            )
        pseudo_id = f"key:{old_key[:12]}:{new_public_key[:12]}"
        existing = self.store.receipt_for_visit(pseudo_id)
        if existing:
            return existing
        prev = self.store.latest_receipt()
        receipt = self.signer.issue(
            visit_id=pseudo_id,
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "key_rotation",
                "previous_key": old_key,
                "new_key": new_public_key,
                "reason": reason or None,
                "boundary": (
                    "A signed statement that the issuer retired the signing key "
                    "named here and adopted the successor — extends pinned-key "
                    "trust across the transition; never proves either key was "
                    "or stayed uncompromised."
                ),
                "journal_head": self.store.journal_head(),
            },
        )
        try:
            self.store.put_receipt(receipt)
        except sqlite3.IntegrityError:
            return self.store.receipt_for_visit(pseudo_id)
        return receipt

    @atomic
    def issue_key_adoption(self, previous_public_key: str, rotation: Receipt) -> Receipt:
        """Sign, under the NEW issuer key, that its holder executed the named
        rotation — a retiring key could claim any successor; only the new key's
        own signature proves the successor consented. Chained directly after
        the rotation receipt so the pair reads as one event."""
        new_key = self.signer.public_key_b64
        if previous_public_key == new_key:
            raise ValueError("adoption must be signed by the successor key, not the retiring one")
        if (
            rotation.payload.get("record_type") != "key_rotation"
            or rotation.payload.get("new_key") != new_key
            or rotation.payload.get("previous_key") != previous_public_key
            or rotation.public_key != previous_public_key
        ):
            raise ValueError("adoption must name a key_rotation receipt endorsing THIS key")
        pseudo_id = f"key:{previous_public_key[:12]}:{new_key[:12]}:adopted"
        existing = self.store.receipt_for_visit(pseudo_id)
        if existing:
            return existing
        prev = self.store.latest_receipt()
        receipt = self.signer.issue(
            visit_id=pseudo_id,
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "key_adoption",
                "previous_key": previous_public_key,
                "rotation_receipt": {"id": rotation.id, "hash": rotation.payload_hash},
                "boundary": (
                    "A signed statement that the holder of the new signing key "
                    "executed the named rotation — together with the retiring "
                    "key's endorsement it binds both sides of the transition."
                ),
                "journal_head": self.store.journal_head(),
            },
        )
        try:
            self.store.put_receipt(receipt)
        except sqlite3.IntegrityError:
            return self.store.receipt_for_visit(pseudo_id)
        return receipt

    def rotate_signing_key(
        self, new_public_key: str, adopt_signer, reason: str = ""
    ) -> tuple[Receipt, Receipt]:
        """The whole issuer rotation, ordered and serialized under the
        signing barrier — shared by `attest rotate-key` and the admin
        endpoint so both paths hold identical crash/race semantics.

        Steps (each commits independently, so every crash window has a
        recovery): first, any pending adoption owed to the CURRENT signer
        is countersigned (a prior rotate that died post-persist heals
        before a new pivot); the retiring key signs the ``key_rotation``
        receipt; ``adopt_signer`` persists the successor under the
        deployment's custody posture and returns the reloaded Signer;
        this engine's signer swaps to it; the successor countersigns
        ``key_adoption``. Because the barrier blocks all other ``@atomic``
        issuance for the duration, no receipt can be minted mid-pivot.
        If ``adopt_signer`` raises, the rotation is an unconsented orphan —
        ``verify_chain`` ignores it and the chain stays valid under the
        retiring key."""
        with self.signing_barrier():
            self.resume_pending_adoptions()
            rotation = self.issue_key_rotation(new_public_key, reason)
            self.signer = adopt_signer()  # persist + reload; raises → inert orphan
            adoption = self.issue_key_adoption(rotation.payload["previous_key"], rotation)
            return rotation, adoption

    @atomic
    def issue_key_revocation(self, revoked_key: str, suspect_after: datetime, reason: str = "") -> Receipt:
        """Sign, under the CURRENT issuer key, that ``revoked_key``'s
        signatures are suspect for anything timestamped after
        ``suspect_after`` — the incident-response counterpart to rotation.

        Revocation annotates trust, it never erases: revoked-key records
        still verify cryptographically, and verifiers report them as
        suspect-window signatures rather than failures. Only the current
        issuer can revoke — a retired key revoking its successor would let
        a compromised key smear the healthy one, and the current key
        revoking itself would strand the deployment (rotate away first,
        then revoke the hot key)."""
        current = self.signer.public_key_b64
        if revoked_key == current:
            raise ValueError(
                "the active key cannot revoke itself — rotate to a fresh "
                "key first, then revoke the compromised one"
            )
        history = {r.public_key for r in self.store.receipts()}
        if revoked_key not in history:
            raise ValueError(
                "cannot revoke a key that never signed this chain — "
                "revocation only has meaning inside this deployment's lineage"
            )
        if suspect_after.tzinfo is None:
            # Both callers normalize, but the signed instant leaves here — a
            # naive spelling would poison every suspect-window comparison
            # downstream, so the engine insists on an instant, not a spelling.
            suspect_after = suspect_after.replace(tzinfo=UTC)
        # Idempotent per revoked key: the full key makes the pseudo visit_id
        # collision-free (a 12-char prefix could alias a different key). The
        # legacy prefix id is honored for revocations written by earlier builds.
        pseudo_id = f"key:revoked:{revoked_key}"
        for candidate in (pseudo_id, f"key:revoked:{revoked_key[:12]}"):
            existing = self.store.receipt_for_visit(candidate)
            if existing and existing.payload.get("revoked_key") == revoked_key:
                return existing
        prev = self.store.latest_receipt()
        receipt = self.signer.issue(
            visit_id=pseudo_id,
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "key_revocation",
                "revoked_key": revoked_key,
                "suspect_after": suspect_after.isoformat(),
                "reason": reason or None,
                "boundary": (
                    "A signed statement that the issuer declares the named "
                    "key's signatures suspect for records timestamped after "
                    "the given instant — a trust annotation, never proof the "
                    "records are false, and it never erases them."
                ),
                "journal_head": self.store.journal_head(),
            },
        )
        try:
            self.store.put_receipt(receipt)
        except sqlite3.IntegrityError:
            return self.store.receipt_for_visit(pseudo_id)
        return receipt

    @atomic
    def disconnect_site(self, site: Site, reason: str = "") -> Receipt:
        """Revoke a site's Ring source binding: tombstone the site and sign a
        ``source_disconnected`` receipt naming exactly what was unbound. The
        binding stays recorded as historical fact; ingestion and polling stop.
        One-way — reconnecting is a new site, not a silent re-bind."""
        if site.disconnected_at is not None:
            raise ValueError(f"site {site.id} source already disconnected")
        at = utcnow()
        prev = self.store.latest_receipt()
        receipt = self.signer.issue(
            visit_id=f"source:{site.id}",
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "source_disconnected",
                "site": {"id": site.id, "name": site.name},
                "ring_account_id": site.ring_account_id,
                "devices": {
                    "door_camera_id": site.door_camera_id,
                    "door_sensor_id": site.door_sensor_id,
                },
                "disconnected_at": at.isoformat(),
                "reason": reason,
                "boundary": (
                    "Stops ingestion and Event History polling for this site. "
                    "Does not alter any signed record; deliveries arriving after "
                    "disconnect are acknowledged to the inbox but never bound."
                ),
                "journal_head": self.store.journal_head(),
            },
        )
        self.store.put_receipt(receipt)
        site.disconnected_at = at
        site.disconnected_reason = reason
        self.store.put_site(site)
        return receipt

    # ------------------------------------------------------------------ live view

    def open_liveview(self, site_id: str, sdp_offer: str) -> tuple[LiveViewSession, str]:
        """Broker a WHEP live-view session: forward the browser's SDP offer to
        Ring, journal the session Ring actually established, hand back the SDP
        answer for the browser's RTCPeerConnection.

        The journaled row is human-attention evidence with a hard boundary:
        it proves a stream was established at ``opened_at`` — never that anyone
        watched, who watched, or what was on screen. An attempt that reached
        Ring and failed journals a ``failed`` row — the attempt is the
        auditable fact; rejections before the call (unknown site, disconnected,
        malformed offer, no camera) journal nothing."""
        site = self.store.site(site_id)
        if site is None:
            raise ValueError("unknown site")
        if site.disconnected_at is not None:
            raise ValueError("site's Ring source is disconnected — live view ends with consent")
        if not site.door_camera_id:
            raise ValueError("site has no camera bound")
        try:
            session = self.ring.whep_session(device_id=site.door_camera_id, sdp_offer=sdp_offer)
        except (RingAPIError, httpx.HTTPError) as exc:
            self._liveview_failed(site, exc)
            raise
        return self._liveview_opened(site, session)

    @atomic
    def _liveview_opened(self, site: Site, session) -> tuple[LiveViewSession, str]:
        row = LiveViewSession(
            site_id=site.id,
            device_id=site.door_camera_id,
            session_url=session.session_url,
            opened_at=self.clock.now(),
        )
        self.store.put_liveview_session(row)
        return row, session.sdp_answer

    @atomic
    def _liveview_failed(self, site: Site, exc: Exception) -> None:
        reason = f"Ring API HTTP {exc.status_code}" if isinstance(exc, RingAPIError) else "Ring unreachable"
        self.store.put_liveview_session(
            LiveViewSession(
                site_id=site.id,
                device_id=site.door_camera_id,
                opened_at=self.clock.now(),
                state="failed",
                failure_reason=reason,
            )
        )

    def close_liveview(self, site_id: str, session_id: str) -> LiveViewSession:
        """End a brokered session — DELETE it at Ring, then mark the journaled
        row closed. Closing Ring-side first keeps 'still streaming' from ever
        being recorded when it isn't; a failed close leaves the row open. The
        network call runs between two short txns so a hung Ring API never
        holds the store lock."""
        row = self._liveview_to_close(site_id, session_id)
        if row.closed_at is not None:
            return row
        try:
            self.ring.whep_close(row.session_url)
        except RingAPIError as exc:
            if exc.status_code != 404:
                raise
            # 404 = upstream already ended it (Ring sessions expire after ~60 s).
            # The stream is verifiably gone — journal the close rather than
            # leaving a stale "open" row forever.
        return self._liveview_closed(row)

    @atomic
    def _liveview_to_close(self, site_id: str, session_id: str) -> LiveViewSession:
        row = self.store.liveview_session(session_id)
        if row is None or row.site_id != site_id:
            raise ValueError("unknown live-view session")
        return row

    @atomic
    def _liveview_closed(self, row: LiveViewSession) -> LiveViewSession:
        current = self.store.liveview_session(row.id)
        if current is None or current.closed_at is not None:
            # A concurrent close already journaled it — keep the recorded row.
            return current or row
        current.closed_at = self.clock.now()
        current.state = "closed"
        self.store.put_liveview_session(current)
        return current

    def _coverage(self, visit: Visit, site: Site) -> dict | None:
        """How much of this visit's window Event History polling actually watched.

        For a record with observations, this bounds what polling alone would have
        corroborated. For a no-observation record it is the honest answer to "did
        anyone come?": the pipeline can attest to checking, never to absence.
        """
        from .coverage import coverage_report

        start = visit.arrived_at
        end = visit.last_activity_at
        sch = self._schedule(visit)
        if sch is not None:
            if not visit.has_observations:
                start, end = sch.window_start, sch.window_end
            elif visit.departed_at is None:
                # Departure was never observed — the coverage question is "could
                # the pipeline have seen them leave?", so attest watching through
                # the scheduled window's end, not just the last observed event.
                end = max(end, sch.window_end)
        if end <= start:
            return None
        return coverage_report(self.store, site.door_camera_id, start, end, now=utcnow(), site_id=site.id)

    def _fetch_history(self, visit: Visit, site: Site) -> list[dict] | None:
        """Corroborate webhook evidence with Ring's own Event History for the visit window.

        Independent of webhook delivery: a receipt that cites history event ids can be
        re-checked against Ring later. Best-effort; ``None`` means history was unavailable.
        Network-only — callers fetch this BEFORE the write txn and pass the result
        into `_issue_receipt`.
        """
        if not visit.has_observations:
            return None
        pad = timedelta(minutes=2)
        lo = visit.arrived_at - pad
        hi = (visit.departed_at or visit.last_activity_at) + pad
        try:
            events = self.ring.events(site.door_camera_id, event_types=["motion", "ding"], since=lo)
            return [
                {
                    "id": e.id,
                    "event_type": e.attributes.event_type,
                    "start": e.attributes.started_at.isoformat(),
                    "end": e.attributes.ended_at.isoformat() if e.attributes.ended_at else None,
                }
                for e in events
                if e.attributes.started_at <= hi
            ]
        except Exception as exc:  # noqa: BLE001 - never block the receipt on a read
            log.warning("history reconciliation for %s failed: %s", visit.id, exc)
            return None

    def _touch(self, visit: Visit, at: datetime) -> None:
        visit.last_activity_at = max(visit.last_activity_at, at)
        visit.last_seen_at = utcnow()
        self.store.put_visit(visit)

    def _evidence(self, visit: Visit, kind: EvidenceKind, at: datetime, ev: WebhookEvent) -> Evidence:
        return self.store.put_evidence(
            Evidence(
                visit_id=visit.id,
                kind=kind,
                at=at,
                source_device_id=ev.device_id,
                ring_event_type=ev.event_type,
                ring_sub_type=ev.sub_type,
                ring_request_id=ev.request_id if ev.meta.ingest_source == "webhook" else None,
                ring_history_event_id=(
                    ev.request_id.removeprefix("history:") if ev.meta.ingest_source == "history" else None
                ),
                ingestion_source=ev.meta.ingest_source,
            )
        )

    def _fetch_snapshot(self, site: Site, at: datetime) -> _SnapshotFetch:
        """The network half of `_snapshot` — call BEFORE the write txn.
        Failures return ``ok=False``; the apply path records the same
        media_unavailable flag either way."""
        w = timedelta(seconds=self.settings.snapshot_window_seconds)
        end = min(at + w, self.clock.now())
        try:
            snap = self.ring.snapshot_latest(site.door_camera_id, at - w, end)
            if snap.timestamp is None or not snap.content:
                raise ValueError("snapshot content or actual timestamp missing")
            actual_at = datetime.fromtimestamp(snap.timestamp / 1000, tz=at.tzinfo)
            if not at - w <= actual_at <= end:
                raise ValueError("snapshot timestamp outside requested window")
        except Exception as exc:  # noqa: BLE001 - Ring media is best-effort evidence
            log.warning("snapshot fetch for %s failed: %s", site.door_camera_id, type(exc).__name__)
            return _SnapshotFetch(ok=False)
        return _SnapshotFetch(
            ok=True, content=snap.content, content_type=snap.content_type, actual_at=actual_at
        )

    def _pending_snapshot_evidence(
        self, visit: Visit, site: Site, fetched: _SnapshotFetch, note: str
    ) -> Evidence:
        """A synthesized SNAPSHOT evidence row for the prefetch-time summary
        input — the real row is written by `_snapshot` inside the txn. The
        media isn't saved yet, so media_path stays None (the Bedrock prompt
        skips it; the fallback summary only reads the row's shape)."""
        return Evidence(
            visit_id=visit.id,
            kind=EvidenceKind.SNAPSHOT,
            at=fetched.actual_at or self.clock.now(),
            source_device_id=site.door_camera_id,
            ingestion_source="ring_media_api"
            if self.ring.base_url == "https://api.amazonvision.com"
            else "local_or_test",
            note=note,
        )

    def _pending_evidence(self, visit: Visit, kind: EvidenceKind, at: datetime, ev: WebhookEvent) -> Evidence:
        """The row `_evidence` will write, synthesized for prefetch-time
        summary inputs (never persisted directly)."""
        return Evidence(
            visit_id=visit.id,
            kind=kind,
            at=at,
            source_device_id=ev.device_id,
            ring_event_type=ev.event_type,
            ring_sub_type=ev.sub_type,
            ring_request_id=ev.request_id if ev.meta.ingest_source == "webhook" else None,
            ring_history_event_id=(
                ev.request_id.removeprefix("history:") if ev.meta.ingest_source == "history" else None
            ),
            ingestion_source=ev.meta.ingest_source,
        )

    def _snapshot(
        self,
        visit: Visit,
        site: Site,
        at: datetime,
        media_label: str,
        note: str,
        fetched: _SnapshotFetch | None,
    ) -> None:
        """media_label must stay filename-safe ([a-zA-Z0-9_-]); note is the
        human caption — they differ so captions can say what the snapshot is.
        Consumes bytes fetched BEFORE the write txn; ``None``/failed fetches
        degrade to the same media_unavailable flag — this method never does
        network I/O under the store lock."""
        if fetched is None or not fetched.ok or fetched.actual_at is None:
            visit.flags.append(
                Flag(
                    code="media_unavailable",
                    severity="info",
                    message=(
                        f"No usable snapshot for the {note} was retrieved; "
                        "imagery does not support this record"
                    ),
                )
            )
            self.store.put_visit(visit)
            return
        sha, path = self.media.save(visit.id, media_label, fetched.content, fetched.content_type)
        self.store.put_evidence(
            Evidence(
                visit_id=visit.id,
                kind=EvidenceKind.SNAPSHOT,
                at=fetched.actual_at,
                source_device_id=site.door_camera_id,
                ingestion_source="ring_media_api"
                if self.ring.base_url == "https://api.amazonvision.com"
                else "local_or_test",
                media_sha256=sha,
                media_path=str(path),
                note=note,
            )
        )

    def _door_closed_recently(self, visit: Visit, at: datetime) -> bool:
        for e in reversed(self.store.evidence_for(visit.id)):
            if e.kind == EvidenceKind.DOOR_CLOSED:
                return timedelta(0) <= at - e.at <= _DEPART_AFTER_DOOR_CLOSE
            if e.kind == EvidenceKind.DOOR_OPENED:
                return False
        return False

    def _matching_schedule(self, site: Site, at: datetime) -> Schedule | None:
        grace = timedelta(minutes=self.settings.arrival_grace_minutes)
        candidates = [
            s
            for s in self.store.schedules_for_site(site.id)
            if s.status == "scheduled"
            and s.matches(at, grace)
            and self.store.visit_for_schedule(s.id) is None
        ]
        return (
            min(candidates, key=lambda s: abs((s.window_start - at).total_seconds())) if candidates else None
        )

    def _schedule(self, visit: Visit) -> Schedule | None:
        return self.store.schedule(visit.schedule_id) if visit.schedule_id else None

    def _worker_name(self, visit: Visit) -> str | None:
        w = self.store.worker(visit.worker_id) if visit.worker_id else None
        return w.name if w else None


def _mins(td: timedelta) -> int:
    return int(round(td.total_seconds() / 60))
