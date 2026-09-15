"""Webhook-less ingest: history events -> engine, and camera-only departure inference."""

from datetime import timedelta

from attest import ledger
from attest.models import Site, VisitState, utcnow
from attest.poller import HistoryPoller


def _hist(ring_control, device_id, etype, at, sub=None):
    ring_control.post(
        "/_sandbox/events",
        json={"device_id": device_id, "type": etype, "sub_type": sub, "at": at.isoformat(), "deliver": False},
    ).raise_for_status()


def test_poller_ingests_history_idempotently(
    engine, store, household, schedule, ring_client, ring_control, t0
):
    site, worker, cam, sensor = household
    t = t0 + timedelta(minutes=3)
    _hist(ring_control, cam.id, "motion_detected", t, "vehicle")  # filtered out (not human)
    _hist(ring_control, cam.id, "motion_detected", t + timedelta(seconds=10), "human")
    _hist(ring_control, cam.id, "button_press", t + timedelta(seconds=20))

    poller = HistoryPoller(engine, store, ring_client, lookback=timedelta(days=2))
    assert poller.poll_once() == 2
    assert poller.poll_once() == 0  # same history ids -> duplicate request_ids

    v = store.active_visit(site.id)
    assert v.state == VisitState.OPEN and v.schedule_id == schedule.id
    kinds = [e.ring_event_type for e in store.evidence_for(v.id) if e.ring_event_type]
    assert kinds == ["motion_detected", "button_press"]
    assert all(
        e.ring_request_id.startswith("history:") for e in store.evidence_for(v.id) if e.ring_request_id
    )


def test_camera_only_site_infers_departure_and_reconciles_history(engine, store, household, ring_control, t0):
    site, worker, cam, _ = household
    site = store.put_site(Site(**{**site.model_dump(), "door_sensor_id": None}))
    from attest.models import Schedule

    store.put_schedule(
        Schedule(
            site_id=site.id,
            worker_id=worker.id,
            window_start=t0,
            window_end=t0 + timedelta(hours=1),
            expected_minutes=90,
        )
    )
    poller = HistoryPoller(engine, store, engine.ring, lookback=timedelta(days=2))
    t = t0 + timedelta(minutes=5)
    _hist(ring_control, cam.id, "motion_detected", t, "human")
    _hist(ring_control, cam.id, "button_press", t + timedelta(seconds=5))
    _hist(ring_control, cam.id, "motion_detected", t + timedelta(minutes=88), "human")
    assert poller.poll_once() == 3
    v = store.active_visit(site.id)
    assert v.state == VisitState.OPEN  # camera-only: a person at the door is not yet a departure

    v.last_seen_at = utcnow() - timedelta(minutes=30)
    store.put_visit(v)
    (closed,) = engine.sweep()
    assert closed.state == VisitState.CLOSED
    assert closed.departed_at == t + timedelta(minutes=88)
    assert "inferred_departure" in {f.code for f in closed.flags}
    assert "idle_close" not in {f.code for f in closed.flags}
    snaps = [e for e in store.evidence_for(closed.id) if e.kind == "snapshot"]
    assert [s.note for s in snaps] == ["arrival", "departure"]

    r = store.receipt_for_visit(closed.id)
    assert ledger.verify_receipt(r)[0]
    hist = r.payload["ring_history"]
    assert {h["event_type"] for h in hist} == {"motion", "ding"} and len(hist) == 3
