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

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ring_sandbox import RingClient, WebhookEvent

from .config import Settings
from .ledger import Signer
from .media import MediaStore
from .models import Evidence, EvidenceKind, Flag, Schedule, Site, Visit, VisitState, utcnow
from .store import Store
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

    # ------------------------------------------------------------------ webhooks

    def ingest(self, ev: WebhookEvent) -> Outcome:
        if not self.store.mark_seen(ev.request_id, utcnow()):
            return Outcome(ignored_reason="duplicate request_id")
        site = self.store.site_for_device(ev.device_id)
        if site is None:
            return Outcome(ignored_reason=f"device {ev.device_id} not bound to a site")
        at = ev.occurred_at
        is_camera = ev.device_id == site.door_camera_id
        et, sub = ev.event_type, ev.sub_type

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
            worker_id=schedule.worker_id if schedule else None,
            state=VisitState.OPEN if schedule else VisitState.UNMATCHED,
            arrived_at=at,
            last_activity_at=at,
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

    def check_in(self, token: str, at: datetime | None = None) -> Visit | None:
        at = at or utcnow()
        worker = self.store.worker_by_token(token)
        if worker is None:
            return None
        for site in self.store.sites():
            visit = self.store.active_visit(site.id)
            if visit is None or visit.state == VisitState.CLOSED:
                continue
            if visit.worker_id not in (None, worker.id):
                continue
            visit.worker_id = worker.id
            visit.checked_in_at = at
            # An UNMATCHED visit becomes a real one once a known worker claims it; the
            # "unscheduled" flag stays on the record.
            visit.state = VisitState.IN_PROGRESS
            self._touch(visit, at)
            self.store.put_evidence(
                Evidence(
                    visit_id=visit.id,
                    kind=EvidenceKind.CHECKIN,
                    at=at,
                    note=f"{worker.name} confirmed presence via check-in link",
                )
            )
            return visit
        return None

    # ------------------------------------------------------------------ sweeper

    def sweep(self, now: datetime | None = None) -> list[Visit]:
        """Close idle visits and mark elapsed schedules as no-shows. Call periodically.

        Idleness is *webhook silence* (wall clock since the last cue we ingested), not the
        event timestamp: Ring retries can deliver late, and replayed scenarios are back-dated.
        """
        now = now or utcnow()
        changed: list[Visit] = []
        idle = timedelta(minutes=self.settings.idle_close_minutes)
        for site in self.store.sites():
            visit = self.store.active_visit(site.id)
            if (
                visit
                and now - visit.last_seen_at >= idle
                and visit.last_activity_at - visit.arrived_at >= _MIN_VISIT
            ):
                visit.flags.append(
                    Flag(
                        code="idle_close",
                        severity="info",
                        message=f"closed after {self.settings.idle_close_minutes} min without activity",
                    )
                )
                changed.append(self._close(visit, site, visit.last_activity_at, reason="idle").visit)  # type: ignore[arg-type]
            grace = timedelta(minutes=self.settings.arrival_grace_minutes)
            for sch in self.store.schedules_for_site(site.id):
                if sch.window_end + grace < now and self.store.visit_for_schedule(sch.id) is None:
                    ns = Visit(
                        site_id=site.id,
                        schedule_id=sch.id,
                        worker_id=sch.worker_id,
                        state=VisitState.NO_SHOW,
                        arrived_at=sch.window_start,
                        last_activity_at=sch.window_end,
                        departed_at=sch.window_end,
                        flags=[
                            Flag(
                                code="no_show",
                                severity="critical",
                                message="no arrival detected during the scheduled window",
                            )
                        ],
                    )
                    ns.summary = "No arrival was detected at the door during the scheduled window."
                    self.store.put_visit(ns)
                    self._issue_receipt(ns, site)
                    changed.append(ns)
        return changed

    # ------------------------------------------------------------------ closing

    def _close(self, visit: Visit, site: Site, at: datetime, *, reason: str) -> Outcome:
        visit.departed_at = at
        visit.state = VisitState.CLOSED
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
        log.info("visit %s closed (%s) after %.1f min", visit.id, reason, visit.duration_minutes or 0)
        return Outcome(visit, ["closed"])

    def _apply_duration_flags(self, visit: Visit) -> None:
        sch = self._schedule(visit)
        if sch is None or visit.duration_minutes is None:
            return
        ratio = visit.duration_minutes / sch.expected_minutes if sch.expected_minutes else 1
        if ratio < 0.5:
            visit.flags.append(
                Flag(
                    code="duration_shortfall",
                    severity="critical",
                    message=f"stayed {visit.duration_minutes:.0f} of {sch.expected_minutes} expected min",
                )
            )
        elif ratio < 0.8:
            visit.flags.append(
                Flag(
                    code="duration_short",
                    severity="warn",
                    message=f"stayed {visit.duration_minutes:.0f} of {sch.expected_minutes} expected min",
                )
            )

    def _issue_receipt(self, visit: Visit, site: Site) -> None:
        prev = self.store.latest_receipt()
        sch = self._schedule(visit)
        evidence = self.store.evidence_for(visit.id)
        facts = {
            "visit_id": visit.id,
            "state": visit.state.value,
            "site": {
                "id": site.id,
                "name": site.name,
                "ring_account_id": site.ring_account_id,
                "door_camera_id": site.door_camera_id,
                "door_sensor_id": site.door_sensor_id,
            },
            "worker": self._worker_name(visit),
            "worker_id": visit.worker_id,
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
            "arrived_at": visit.arrived_at.isoformat(),
            "checked_in_at": visit.checked_in_at.isoformat() if visit.checked_in_at else None,
            "departed_at": visit.departed_at.isoformat() if visit.departed_at else None,
            "duration_minutes": round(visit.duration_minutes, 1)
            if visit.duration_minutes is not None
            else None,
            "flags": [f.model_dump() for f in visit.flags],
            "summary": visit.summary,
            "evidence": [
                {
                    "kind": e.kind.value,
                    "at": e.at.isoformat(),
                    "device": e.source_device_id,
                    "ring_event": e.ring_event_type,
                    "ring_sub_type": e.ring_sub_type,
                    "ring_request_id": e.ring_request_id,
                    "media_sha256": e.media_sha256,
                }
                for e in evidence
            ],
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
                ring_request_id=ev.request_id,
            )
        )

    def _snapshot(self, visit: Visit, site: Site, at: datetime, label: str) -> None:
        w = timedelta(seconds=self.settings.snapshot_window_seconds)
        try:
            snap = self.ring.snapshot_latest(site.door_camera_id, at - w, at + w)
        except Exception as exc:  # noqa: BLE001 - Ring media is best-effort evidence
            log.warning("snapshot for %s (%s) failed: %s", visit.id, label, exc)
            return
        sha, path = self.media.save(visit.id, label, snap.content, snap.content_type)
        self.store.put_evidence(
            Evidence(
                visit_id=visit.id,
                kind=EvidenceKind.SNAPSHOT,
                at=at,
                source_device_id=site.door_camera_id,
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
            if s.matches(at, grace) and self.store.visit_for_schedule(s.id) is None
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
