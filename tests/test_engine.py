"""Drive the visit engine with v1.1 webhook payloads built by ring-sandbox."""

from datetime import UTC, timedelta

from ring_sandbox import WebhookEvent, webhooks

from attest import ledger
from attest.models import EvidenceKind, VisitState


def ev(device_id: str, etype: str, at, sub=None) -> WebhookEvent:
    payload = webhooks.build_event(event_type=etype, device_id=device_id, occurred_at=at, sub_type=sub)
    return WebhookEvent.model_validate(payload)


def _inject_history(ring_control, device_id, etype, at, sub=None):
    """Mirror the event into the sandbox so snapshots have a recording to attach to."""
    ring_control.post(
        "/_sandbox/events",
        json={
            "device_id": device_id,
            "type": etype,
            "sub_type": sub,
            "at": at.isoformat(),
            "deliver": False,
        },
    ).raise_for_status()


def test_full_visit_matches_schedule_and_issues_receipt(engine, store, household, schedule, t0, ring_control):
    site, worker, cam, sensor = household
    t = t0 + timedelta(minutes=2)

    _inject_history(ring_control, cam.id, "motion_detected", t, "human")
    out = engine.ingest(ev(cam.id, "motion_detected", t, "human"))
    v = out.visit
    assert out.transitions == ["opened"] and v.state == VisitState.OPEN
    assert v.schedule_id == schedule.id and v.worker_id is None
    kinds = [e.kind for e in store.evidence_for(v.id)]
    assert EvidenceKind.ARRIVAL_MOTION in kinds and EvidenceKind.SNAPSHOT in kinds  # arrival snapshot pulled

    engine.ingest(ev(cam.id, "button_press", t + timedelta(seconds=6)))
    engine.ingest(ev(sensor.id, "contact_sensor_faulted", t + timedelta(seconds=20)))
    engine.ingest(ev(sensor.id, "contact_sensor_cleared", t + timedelta(seconds=35)))

    assert (
        engine.check_in(
            engine.issue_checkin(store.active_visit(site.id).id), at=t + timedelta(minutes=1)
        ).state
        == VisitState.IN_PROGRESS
    )

    # 88 minutes later: door opens, closes, person walks away
    leave = t + timedelta(minutes=88)
    engine.ingest(ev(sensor.id, "contact_sensor_faulted", leave))
    engine.ingest(ev(sensor.id, "contact_sensor_cleared", leave + timedelta(seconds=12)))
    _inject_history(ring_control, cam.id, "motion_detected", leave + timedelta(seconds=15), "human")
    out = engine.ingest(ev(cam.id, "motion_detected", leave + timedelta(seconds=15), "human"))

    v = out.visit
    assert out.transitions == ["closed"] and v.state == VisitState.CLOSED
    assert v.duration_minutes is None and 88 <= v.observed_span_minutes <= 89
    assert [f.code for f in v.flags] == ["departure_unconfirmed"]  # on time, checked in, full duration
    assert "Maria Chen" in v.summary and "88 minutes" in v.summary

    r = store.receipt_for_visit(v.id)
    assert r and r.sequence == 1 and r.prev_hash is None
    assert ledger.verify_receipt(r)[0]
    assert r.payload["worker"] == "Maria Chen" and r.payload["schedule"]["expected_minutes"] == 90
    assert sum(1 for e in r.payload["evidence"] if e["kind"] == "snapshot") == 2
    assert all(e["media_sha256"] for e in r.payload["evidence"] if e["kind"] == "snapshot")


def test_short_visit_is_flagged(engine, store, household, schedule, t0):
    site, worker, cam, sensor = household
    t = t0 + timedelta(minutes=10)
    engine.ingest(ev(cam.id, "motion_detected", t, "human"))
    engine.check_in(engine.issue_checkin(store.active_visit(site.id).id), at=t + timedelta(minutes=1))
    leave = t + timedelta(minutes=12)
    engine.ingest(ev(sensor.id, "contact_sensor_faulted", leave))
    engine.ingest(ev(sensor.id, "contact_sensor_cleared", leave + timedelta(seconds=8)))
    v = engine.ingest(ev(cam.id, "motion_detected", leave + timedelta(seconds=20), "human")).visit
    assert v.state == VisitState.CLOSED
    assert {f.code for f in v.flags} == {"observed_interval_short", "departure_unconfirmed"}
    assert any("Observations span 12 min; 90 min scheduled" in f.message for f in v.flags)


def test_departure_requires_door_cycle_and_min_duration(engine, household, schedule, t0):
    site, worker, cam, sensor = household
    t = t0 + timedelta(minutes=1)
    engine.ingest(ev(cam.id, "motion_detected", t, "human"))
    # human motion right after arrival with no door cycle is just activity
    out = engine.ingest(ev(cam.id, "motion_detected", t + timedelta(seconds=40), "human"))
    assert out.transitions == ["activity"] and out.visit.state == VisitState.OPEN
    # door cycle within the first 3 minutes still doesn't close it
    engine.ingest(ev(sensor.id, "contact_sensor_faulted", t + timedelta(minutes=1)))
    engine.ingest(ev(sensor.id, "contact_sensor_cleared", t + timedelta(minutes=1, seconds=5)))
    out = engine.ingest(ev(cam.id, "motion_detected", t + timedelta(minutes=1, seconds=30), "human"))
    assert out.visit.state == VisitState.OPEN


def test_unscheduled_arrival_and_vehicle_ignored(engine, household, t0):
    site, worker, cam, sensor = household
    out = engine.ingest(ev(cam.id, "motion_detected", t0, "vehicle"))
    assert out.visit is None and "non-human" in out.ignored_reason
    out = engine.ingest(ev(cam.id, "motion_detected", t0 + timedelta(seconds=30), "human"))
    assert out.visit.state == VisitState.UNMATCHED
    assert out.visit.flags[0].code == "unscheduled"


def test_duplicate_request_id_is_idempotent(engine, household, schedule, t0):
    site, worker, cam, sensor = household
    payload = webhooks.build_event(event_type="button_press", device_id=cam.id, occurred_at=t0)
    first = engine.ingest(WebhookEvent.model_validate(payload))
    second = engine.ingest(WebhookEvent.model_validate(payload))
    assert first.transitions == ["opened"] and second.ignored_reason == "duplicate request_id"


def test_sweep_closes_idle_visit_and_marks_no_show(engine, store, household, schedule, t0):
    site, worker, cam, sensor = household
    from attest.models import utcnow

    t = t0 + timedelta(minutes=5)
    engine.ingest(ev(cam.id, "motion_detected", t, "human"))
    engine.ingest(ev(cam.id, "motion_detected", t + timedelta(minutes=6), "human"))  # some activity
    assert engine.sweep(now=t0 + timedelta(hours=5)) == []  # webhooks still fresh -> not idle

    v = store.active_visit(site.id)
    v.last_seen_at = utcnow() - timedelta(minutes=25)  # 25 min of webhook silence
    store.put_visit(v)
    changed = engine.sweep(now=utcnow())
    assert len(changed) == 1 and changed[0].state == VisitState.CLOSED
    assert changed[0].departed_at is None and changed[0].last_activity_at == t + timedelta(
        minutes=6
    )  # closed at the last event time
    assert {f.code for f in changed[0].flags} >= {"idle_close", "no_checkin", "observed_interval_short"}

    # a second schedule nobody shows up for
    from attest.models import Schedule

    s2 = store.put_schedule(
        Schedule(
            site_id=site.id,
            worker_id=worker.id,
            window_start=t0 + timedelta(hours=3),
            window_end=t0 + timedelta(hours=4),
            expected_minutes=60,
        )
    )
    changed = engine.sweep(now=t0 + timedelta(hours=4, minutes=45))
    ns = next(v for v in changed if v.schedule_id == s2.id)
    assert ns.state == VisitState.NO_OBSERVATION and ns.flags[0].code == "no_observation"
    receipts = store.receipts()
    assert [r.sequence for r in receipts] == [1, 2] and ledger.verify_chain(receipts)[0]


def test_disconnect_site_tombstones_binding_and_signs_receipt(engine, store, household, schedule, t0):
    """Consent revocation: the binding stays recorded as fact, a signed
    source_disconnected receipt names what was unbound, and new events stop
    binding — while the inbox still acknowledges deliveries."""
    site, worker, cam, sensor = household
    t = t0 + timedelta(minutes=2)
    engine.ingest(ev(cam.id, "motion_detected", t, "human"))
    engine.close_for_review(store.active_visit(site.id).id)

    receipt = engine.disconnect_site(site, "household revoked access")
    assert receipt.payload["record_type"] == "source_disconnected"
    assert receipt.payload["ring_account_id"] == site.ring_account_id
    assert receipt.payload["devices"]["door_camera_id"] == cam.id
    assert receipt.payload["reason"] == "household revoked access"

    site = store.site(site.id)
    assert site.disconnected_at is not None

    # Post-disconnect deliveries are acknowledged but never bound.
    out = engine.ingest(ev(cam.id, "button_press", t + timedelta(minutes=1)))
    assert out.visit is None and "disconnected" in out.ignored_reason

    # Disconnecting twice is refused, not silently re-signed.
    import pytest

    with pytest.raises(ValueError, match="already disconnected"):
        engine.disconnect_site(site)

    # The chain stays intact and includes the disconnect event.
    receipts = store.receipts()
    assert ledger.verify_chain(receipts)[0]
    assert receipts[-1].payload["record_type"] == "source_disconnected"


def test_disconnected_site_is_not_polled(engine, store, household, ring_control):
    """Consent revocation means stop calling their Event History API too —
    no poll_observations rows land for a tombstoned site."""
    from attest.poller import HistoryPoller

    site = household[0]
    cam = household[2]
    engine.disconnect_site(site)
    n = HistoryPoller(engine, store, ring_control).poll_once()
    assert n == 0
    from datetime import datetime

    rows = store.poll_observations(
        cam.id,
        datetime(2020, 1, 1, tzinfo=UTC),
        datetime(2100, 1, 1, tzinfo=UTC),
    )
    assert rows == []
