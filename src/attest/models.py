"""Domain model: sites, workers, schedules, visits, evidence, receipts."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, Field


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


class Role(StrEnum):
    HOME_HEALTH_AIDE = "home_health_aide"
    CLEANER = "cleaner"
    DOG_WALKER = "dog_walker"
    CONTRACTOR = "contractor"
    OTHER = "other"


class Site(BaseModel):
    id: str = Field(default_factory=lambda: _id("site"))
    name: str
    ring_account_id: str
    door_camera_id: str
    door_sensor_id: str | None = None
    owner_name: str = ""
    owner_contact: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class Worker(BaseModel):
    id: str = Field(default_factory=lambda: _id("wkr"))
    name: str
    role: Role = Role.OTHER
    agency: str = ""
    phone: str = ""
    checkin_token: str = Field(default_factory=lambda: secrets.token_urlsafe(12))
    created_at: datetime = Field(default_factory=utcnow)


class Schedule(BaseModel):
    id: str = Field(default_factory=lambda: _id("sch"))
    site_id: str
    worker_id: str
    window_start: datetime
    window_end: datetime
    expected_minutes: int
    service: str = ""
    created_at: datetime = Field(default_factory=utcnow)

    def matches(self, at: datetime, grace: timedelta) -> bool:
        return self.window_start - grace <= at <= self.window_end + grace


class VisitState(StrEnum):
    OPEN = "open"  # arrival evidence seen, awaiting worker check-in
    IN_PROGRESS = "in_progress"  # worker checked in
    CLOSED = "closed"  # departure evidence seen, receipt issued
    UNMATCHED = "unmatched"  # arrival with no schedule in window; kept for review
    NO_SHOW = "no_show"  # schedule window elapsed with no arrival


class EvidenceKind(StrEnum):
    ARRIVAL_MOTION = "arrival_motion"
    DOORBELL = "doorbell"
    DOOR_OPENED = "door_opened"
    DOOR_CLOSED = "door_closed"
    CHECKIN = "checkin"
    ACTIVITY = "activity"
    DEPARTURE_MOTION = "departure_motion"
    SNAPSHOT = "snapshot"


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: _id("ev"))
    visit_id: str
    kind: EvidenceKind
    at: datetime
    source_device_id: str | None = None
    ring_event_type: str | None = None
    ring_sub_type: str | None = None
    ring_request_id: str | None = None
    ring_history_event_id: str | None = None
    media_sha256: str | None = None
    media_path: str | None = None
    note: str = ""


class Flag(BaseModel):
    code: str
    severity: str  # info | warn | critical
    message: str


class Visit(BaseModel):
    id: str = Field(default_factory=lambda: _id("vis"))
    site_id: str
    schedule_id: str | None = None
    worker_id: str | None = None
    state: VisitState = VisitState.OPEN
    arrived_at: datetime
    checked_in_at: datetime | None = None
    last_activity_at: datetime  # event time of the latest cue (from Ring timestamps)
    last_seen_at: datetime = Field(default_factory=utcnow)  # wall clock of the latest webhook we ingested
    departed_at: datetime | None = None
    summary: str | None = None
    flags: list[Flag] = Field(default_factory=list)
    receipt_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def duration_minutes(self) -> float | None:
        if self.departed_at is None:
            return None
        return (self.departed_at - self.arrived_at).total_seconds() / 60


class Receipt(BaseModel):
    """Canonical, signed record of a closed visit. ``payload`` is what gets signed."""

    id: str = Field(default_factory=lambda: _id("rcpt"))
    visit_id: str
    sequence: int
    prev_hash: str | None
    payload: dict
    payload_hash: str
    signature: str  # base64 Ed25519 over payload_hash bytes
    public_key: str  # base64 raw Ed25519 public key
    issued_at: datetime = Field(default_factory=utcnow)
