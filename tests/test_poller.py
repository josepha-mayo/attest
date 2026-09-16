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
    _hist(ring_control, cam.id, "button_press", t)
    # History events carry no sub_type (verified against the live API), so a polled
    # motion has unknown classification — it attaches to an open visit as activity
    # but can never open one.
    _hist(ring_control, cam.id, "motion_detected", t + timedelta(seconds=10), "human")

    poller = HistoryPoller(engine, store, ring_client, lookback=timedelta(days=2))
    assert poller.poll_once() == 2
    # The arrival-cue snapshot fetch wrote an on_demand history entry (emulator mirrors
    # the real API); the next poll ingests it as on-demand evidence on the open visit.
    assert poller.poll_once() == 1
    assert poller.poll_once() == 0  # everything now dedupes on request_id

    v = store.active_visit(site.id)
    assert v.state == VisitState.OPEN and v.schedule_id == schedule.id
    kinds = [e.ring_event_type for e in store.evidence_for(v.id) if e.ring_event_type]
    assert kinds == ["button_press", "motion_detected", "on_demand"]
    observations = [e for e in store.evidence_for(v.id) if e.ring_event_type]
    assert all(e.ingestion_source == "history" and e.ring_history_event_id for e in observations)
    assert all(e.ring_request_id is None for e in observations)


def test_poller_on_demand_is_activity_not_arrival(
    engine, store, household, schedule, ring_client, ring_control, t0
):
    """Live-API verified: Playground triggers and media requests surface as on_demand
    history entries. They record as on-demand evidence on an open visit — never as
    doorbell/motion, and they never open a visit (our own snapshot fetches would loop)."""
    site, worker, cam, sensor = household
    t = t0 + timedelta(minutes=3)

    poller = HistoryPoller(engine, store, ring_client, lookback=timedelta(days=2))
    ring_client.snapshot_at(cam.id, int(t.timestamp() * 1000))  # media request -> on_demand entry
    assert poller.poll_once() == 0  # no active visit: ignored, no visit opened
    assert store.active_visit(site.id) is None

    _hist(ring_control, cam.id, "button_press", t + timedelta(seconds=10))
    ring_client.snapshot_at(cam.id, int((t + timedelta(seconds=20)).timestamp() * 1000))
    assert poller.poll_once() == 2

    v = store.active_visit(site.id)
    kinds = [(e.ring_event_type, e.kind) for e in store.evidence_for(v.id) if e.ring_event_type]
    assert ("button_press", "doorbell") in kinds
    assert ("on_demand", "on_demand") in kinds  # honest label, not mislabeled as doorbell


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
    _hist(ring_control, cam.id, "button_press", t)
    _hist(ring_control, cam.id, "motion_detected", t + timedelta(seconds=5), "human")
    _hist(ring_control, cam.id, "motion_detected", t + timedelta(minutes=88), "human")
    # ding opens the visit; history motions carry no sub_type so they attach as activity
    assert poller.poll_once() == 3
    v = store.active_visit(site.id)
    assert v.state == VisitState.OPEN  # camera-only: a person at the door is not yet a departure

    v.last_seen_at = utcnow() - timedelta(minutes=30)
    store.put_visit(v)
    (closed,) = engine.sweep()
    assert closed.state == VisitState.CLOSED
    assert closed.departed_at is None and closed.last_activity_at == t + timedelta(minutes=88)
    assert "observation_gap" in {f.code for f in closed.flags}
    assert "idle_close" not in {f.code for f in closed.flags}
    snaps = [e for e in store.evidence_for(closed.id) if e.kind == "snapshot"]
    assert [s.note for s in snaps] == ["arrival", "departure"]

    r = store.receipt_for_visit(closed.id)
    assert ledger.verify_receipt(r)[0]
    hist = r.payload["ring_history"]
    assert {h["event_type"] for h in hist} == {"motion", "ding"} and len(hist) == 3
