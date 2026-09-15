"""Domain model: sites, workers, schedules, visits, evidence, receipts."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


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


class ReplayTime(BaseModel):
    model_config = ConfigDict(extra="forbid")
    at: AwareDatetime


class Site(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    id: str = Field(default_factory=lambda: _id("site"), pattern=r"^[A-Za-z0-9_-]{1,80}$")
    name: str = Field(min_length=1, max_length=160)
    ring_account_id: str
    door_camera_id: str
    door_sensor_id: str | None = None
    owner_name: str = ""
    owner_contact: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class Worker(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    id: str = Field(default_factory=lambda: _id("wkr"), pattern=r"^[A-Za-z0-9_-]{1,80}$")
    name: str = Field(min_length=1, max_length=160)
    role: Role = Role.OTHER
    agency: str = ""
    phone: str = ""
    checkin_token: str = Field(default_factory=lambda: secrets.token_urlsafe(12))
    created_at: datetime = Field(default_factory=utcnow)


class CheckinGrant(BaseModel):
    id: str
    worker_id: str
    token_hash: str
    expires_at: datetime
    used_at: datetime | None = None


class Schedule(BaseModel):
    id: str = Field(default_factory=lambda: _id("sch"), pattern=r"^[A-Za-z0-9_-]{1,80}$")
    site_id: str
    worker_id: str
    window_start: AwareDatetime
    window_end: AwareDatetime
    expected_minutes: int = Field(gt=0, le=1440, strict=True)
    service: str = Field(default="", max_length=500)
    status: Literal["scheduled", "cancelled"] = "scheduled"
    cancelled_at: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def ordered_window(self):
        if self.window_end <= self.window_start:
            raise ValueError("arrival window end must follow its start")
        return self

    def matches(self, at: datetime, grace: timedelta) -> bool:
        return self.window_start - grace <= at <= self.window_end + grace


class VisitState(StrEnum):
    OPEN = "open"  # arrival evidence seen, awaiting worker check-in
    IN_PROGRESS = "in_progress"  # worker checked in
    CLOSED = "closed"  # departure evidence seen, receipt issued
    UNMATCHED = "unmatched"  # arrival with no schedule in window; kept for review
    NO_SHOW = "no_show"  # schedule window elapsed with no arrival
    NO_OBSERVATION = "no_observation"


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
    ingestion_source: str = "unknown"
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
    checkin_received_at: datetime | None = None
    clock_mode: str = "wall"
    replay_id: str | None = None
    last_activity_at: datetime  # event time of the latest cue (from Ring timestamps)
    last_seen_at: datetime = Field(default_factory=utcnow)  # wall clock of the latest webhook we ingested
    departed_at: datetime | None = None
    departure_candidate_at: datetime | None = None
    closed_at: datetime | None = None
    close_reason: str | None = None
    summary_source: str = "unknown"
    summary_model: str | None = None
    summary_fallback_reason: str | None = None
    summary: str | None = None
    flags: list[Flag] = Field(default_factory=list)
    receipt_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def has_observations(self) -> bool:
        return self.state not in (VisitState.NO_SHOW, VisitState.NO_OBSERVATION)

    @property
    def observed_span_minutes(self) -> float | None:
        if not self.has_observations:
            return None
        return max(0.0, (self.last_activity_at - self.arrived_at).total_seconds() / 60)

    @property
    def duration_minutes(self) -> float | None:
        return None


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


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    decision: Literal["confirm", "dispute", "correction", "inconclusive"]
    statement: str = Field(min_length=1, max_length=2000)
    reported_start: AwareDatetime | None = None
    reported_end: AwareDatetime | None = None

    @model_validator(mode="after")
    def reported_window(self):
        if (self.reported_start is None) != (self.reported_end is None):
            raise ValueError("supply both reported times or neither")
        if self.reported_start is not None:
            duration = self.reported_end - self.reported_start
            if not timedelta(0) < duration <= timedelta(days=1):
                raise ValueError("reported interval must be positive and at most 24 hours")
            if self.reported_end > utcnow():
                raise ValueError("reported interval cannot end in the future")
        return self


class ReviewGrant(CheckinGrant):
    original_hash: str


class ReviewEntry(BaseModel):
    id: str
    visit_id: str
    revision: int
    receipt: Receipt


class ReviewBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["attest.review_bundle/1"] = "attest.review_bundle/1"
    original: Receipt
    reviews: list[ReviewEntry] = Field(default_factory=list, max_length=500)
