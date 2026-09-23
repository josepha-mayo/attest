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
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import httpx
from ring_sandbox import RingAPIError, RingClient, WebhookEvent

from .clock import ExecutionClock
from .config import Settings
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


@dataclass
class Outcome:
    visit: Visit | None = None
    transitions: list[str] = field(default_factory=list)
    ignored_reason: str | None = None


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

    @atomic
    def ingest(self, ev: WebhookEvent, *, source: str = "webhook") -> Outcome:
        if source not in ("webhook", "history"):
            raise ValueError("invalid ingestion source")
        ev = ev.model_copy(update={"meta": ev.meta.model_copy(update={"ingest_source": source})})
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
            raise ValueError("event timestamp is in the future")
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
            return self._on_motion(site, at, ev, human=sub in _ARRIVAL_MOTION)
        if et == "button_press" and is_camera:
            return self._on_arrival_cue(site, at, ev, EvidenceKind.DOORBELL)
        if et == "contact_sensor_faulted" and ev.device_id == site.door_sensor_id:
            return self._on_door(site, at, ev, opened=True)
        if et == "contact_sensor_cleared" and ev.device_id == site.door_sensor_id:
            return self._on_door(site, at, ev, opened=False)
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
            raise ValueError("event timestamp is in the future")
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

    def _on_motion(self, site: Site, at: datetime, ev: WebhookEvent, *, human: bool) -> Outcome:
        visit = self.store.active_visit(site.id)
        if visit is None:
            if not human:
                return Outcome(ignored_reason="non-human motion with no active visit")
            return self._on_arrival_cue(site, at, ev, EvidenceKind.ARRIVAL_MOTION)
        # Departure: door closed recently, then a person walks away past the camera.
        if human and self._door_closed_recently(visit, at) and at - visit.arrived_at >= _MIN_VISIT:
            self._evidence(visit, EvidenceKind.DEPARTURE_MOTION, at, ev)
            self._snapshot(visit, site, at, "departure")
            return self._close(visit, site, at, reason="departure")
        self._evidence(visit, EvidenceKind.ACTIVITY, at, ev)
        self._touch(visit, at)
        return Outcome(visit, ["activity"])

    def _on_door(self, site: Site, at: datetime, ev: WebhookEvent, *, opened: bool) -> Outcome:
        visit = self.store.active_visit(site.id)
        kind = EvidenceKind.DOOR_OPENED if opened else EvidenceKind.DOOR_CLOSED
        if visit is None:
            if opened:
                return self._on_arrival_cue(site, at, ev, kind)
            return Outcome(ignored_reason="door closed with no active visit")
        self._evidence(visit, kind, at, ev)
        self._touch(visit, at)
        return Outcome(visit, [kind.value])

    def _on_arrival_cue(self, site: Site, at: datetime, ev: WebhookEvent, kind: EvidenceKind) -> Outcome:
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
                    message=f"arrived {_mins(schedule.window_start - at)} min before window",
                )
            )
        if schedule and at > schedule.window_end:
            visit.flags.append(
                Flag(
                    code="late",
                    severity="warn",
                    message=f"arrived {_mins(at - schedule.window_end)} min after window closed",
                )
            )
        if not schedule:
            visit.flags.append(
                Flag(
                    code="unscheduled",
                    severity="warn",
                    message="arrival with no scheduled visit in window",
                )
            )
        self.store.put_visit(visit)
        self._evidence(visit, kind, at, ev)
        self._snapshot(visit, site, at, "arrival")
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
            raise ValueError("check-in cannot precede first observation")
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
                    note=f"Presence self-reported using the link issued to {worker.name}; "
                    "not identity-verified",
                )
            )
            return visit
        return None

    # ------------------------------------------------------------------ sweeper

    @atomic
    def sweep(self, now: datetime | None = None) -> list[Visit]:
        """Close idle visits and mark elapsed schedules as no-shows. Call periodically.

        Idleness is *webhook silence* (wall clock since the last cue we ingested), not the
        event timestamp: Ring retries can deliver late, and replayed scenarios are back-dated.
        """
        now = now or self.clock.now()
        changed: list[Visit] = []
        idle = timedelta(minutes=self.settings.idle_close_minutes)
        for site in self.store.sites():
            visit = self.store.active_visit(site.id)
            if visit and not self.clock.replay and now - visit.last_seen_at >= idle:
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
                self._snapshot(visit, site, visit.last_activity_at, "departure")
                changed.append(self._close(visit, site, visit.last_activity_at, reason="idle").visit)  # type: ignore[arg-type]
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

    @atomic
    def close_for_review(self, visit_id: str) -> Visit:
        visit = self.store.visit(visit_id)
        if visit is None or visit.receipt_id:
            raise ValueError("record is missing or already signed")
        site = self.store.site(visit.site_id)
        self._close(visit, site, visit.last_activity_at, reason="coordinator_review")
        return visit

    def _close(self, visit: Visit, site: Site, at: datetime, *, reason: str) -> Outcome:
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
                    message="worker never confirmed presence via check-in link",
                )
            )
        evidence = self.store.evidence_for(visit.id)
        visit.summary = self.summarizer.summarize(
            visit, site, self._schedule(visit), self._worker_name(visit), evidence, self.media
        )
        self.store.put_visit(visit)
        self._issue_receipt(visit, site)
        log.info(
            "record %s closed (%s); observed interval %.1f min",
            visit.id,
            reason,
            visit.observed_span_minutes or 0,
        )
        return Outcome(visit, ["closed"])

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

    def _issue_receipt(self, visit: Visit, site: Site) -> None:
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
            "ring_history": self._reconcile_history(visit, site),
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
        worker_entries = [e for e in entries if e.receipt.payload.get("actor", {}).get("role") == "worker"]
        household_entries = [
            e for e in entries if e.receipt.payload.get("actor", {}).get("role") == "household"
        ]
        resolution_entries = [
            e for e in entries if e.receipt.payload.get("review", {}).get("kind") == "resolution"
        ]
        # The dispute loop closing is itself a ledger metric: how many records
        # carry a signed conclusion, and how long first-worker-statement ->
        # conclusion took. "Resolved" uses the same derivation every other
        # surface does — latest resolution post-dates latest worker statement —
        # so a re-opened record does not count as resolved. Ledger time only.
        resolved_records, resolution_lags = 0, []
        for v in visits:
            v_entries = self.store.reviews_for(v.id)
            worker_ats = [
                e.receipt.payload.get("statement_received_at")
                for e in v_entries
                if e.receipt.payload.get("actor", {}).get("role") == "worker"
            ]
            res_ats = [
                e.receipt.payload.get("statement_received_at")
                for e in v_entries
                if e.receipt.payload.get("review", {}).get("kind") == "resolution"
            ]
            if not res_ats or res_ats[-1] is None:
                continue
            try:
                latest_res = datetime.fromisoformat(res_ats[-1])
                latest_worker = (
                    datetime.fromisoformat(worker_ats[-1]) if worker_ats and worker_ats[-1] else None
                )
                first_worker = datetime.fromisoformat(worker_ats[0]) if worker_ats and worker_ats[0] else None
            except (TypeError, ValueError):
                continue  # corrupt journal-adjacent data — omit rather than sign garbage
            if latest_worker and latest_worker > latest_res:
                continue  # a later worker statement re-opened the record
            resolved_records += 1
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
                1 for e in worker_entries if e.receipt.payload.get("review", {}).get("decision") == "dispute"
            ),
            "household_statements": len(household_entries),
            "coordinator_statements": len(entries)
            - len(worker_entries)
            - len(household_entries)
            - len(resolution_entries),
            "coordinator_resolutions": len(resolution_entries),
            "records_resolved": resolved_records,
            "median_resolution_minutes": (
                round(statistics.median(resolution_lags), 1) if resolution_lags else None
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

    @atomic
    def close_liveview(self, site_id: str, session_id: str) -> LiveViewSession:
        """End a brokered session — DELETE it at Ring, then mark the journaled
        row closed. Closing Ring-side first keeps 'still streaming' from ever
        being recorded when it isn't; a failed close leaves the row open."""
        row = self.store.liveview_session(session_id)
        if row is None or row.site_id != site_id:
            raise ValueError("unknown live-view session")
        if row.closed_at is not None:
            return row
        self.ring.whep_close(row.session_url)
        row.closed_at = self.clock.now()
        row.state = "closed"
        self.store.put_liveview_session(row)
        return row

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

    def _reconcile_history(self, visit: Visit, site: Site) -> list[dict] | None:
        """Corroborate webhook evidence with Ring's own Event History for the visit window.

        Independent of webhook delivery: a receipt that cites history event ids can be
        re-checked against Ring later. Best-effort; ``None`` means history was unavailable.
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

    def _snapshot(self, visit: Visit, site: Site, at: datetime, label: str) -> None:
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
            log.warning("snapshot for %s (%s) failed: %s", visit.id, label, type(exc).__name__)
            visit.flags.append(
                Flag(
                    code="media_unavailable",
                    severity="info",
                    message=f"No usable {label} snapshot was retrieved; imagery does not support this record",
                )
            )
            self.store.put_visit(visit)
            return
        sha, path = self.media.save(visit.id, label, snap.content, snap.content_type)
        self.store.put_evidence(
            Evidence(
                visit_id=visit.id,
                kind=EvidenceKind.SNAPSHOT,
                at=actual_at,
                source_device_id=site.door_camera_id,
                ingestion_source="ring_media_api"
                if self.ring.base_url == "https://api.amazonvision.com"
                else "local_or_test",
                media_sha256=sha,
                media_path=str(path),
                note=label,
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
