"""Visit engine: Ring events in, visit state transitions + evidence + receipts out.

State machine (per site, at most one active visit):

    (no visit) --arrival cue in a schedule window--> OPEN
    (no visit) --arrival cue, no schedule---------> UNMATCHED
    OPEN --worker check-in------------------------> IN_PROGRESS
    OPEN | IN_PROGRESS --departure cue------------> CLOSED (receipt issued)
    OPEN | IN_PROGRESS --idle timeout-------------> CLOSED (receipt issued, flagged)
    schedule window elapsed, no visit-------------> NO_SHOW (receipt issued)

Arrival cues:  motion_detected(human) on the door camera, button_press, door opened (contact sensor).
Departure cue: door open->close, then motion_detected(human) within 2 min, once the visit is at
               least ``min_visit_minutes`` old. Or door closed with no camera activity for
               ``idle_close_minutes``.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ring_sandbox import RingClient, WebhookEvent

from .clock import ExecutionClock
from .config import Settings
from .ledger import Signer
from .media import MediaStore
from .models import CheckinGrant, Evidence, EvidenceKind, Flag, Schedule, Site, Visit, VisitState, utcnow
from .store import Store, atomic
from .summarize import Summarizer

log = logging.getLogger("attest.engine")

_ARRIVAL_MOTION = {"human"}
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
        site = self.store.site_for_device(ev.device_id)
        if site is None:
            return Outcome(ignored_reason=f"device {ev.device_id} not bound to a site")
        if ev.meta.account_id != site.ring_account_id:
            return Outcome(ignored_reason="account mismatch")
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
        return Outcome(ignored_reason=f"{et}/{sub} not used by the visit engine")

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
            "ring_history": self._reconcile_history(visit, site),
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
        try:
            snap = self.ring.snapshot_latest(site.door_camera_id, at - w, min(at + w, utcnow()))
            if snap.timestamp is None or not snap.content:
                raise ValueError("snapshot content or actual timestamp missing")
            actual_at = datetime.fromtimestamp(snap.timestamp / 1000, tz=at.tzinfo)
            if not at - w <= actual_at <= min(at + w, utcnow()):
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
