from datetime import timedelta

import pytest

from attest.models import Schedule, Worker
from attest.setup import SetupService


def test_setup_discovers_and_validates_device_binding(engine, store, ring_client, ring_world):
    service = SetupService(store, ring_client, engine.clock, engine.settings.arrival_grace_minutes)
    options = service.discover()
    camera = next(d for d in options if d["camera"])
    sensor = next(d for d in options if d["contact_signal"])
    site = service.register_site("Test residence", camera["id"], sensor["id"])
    assert site.ring_account_id == ring_world.account_id
    with pytest.raises(ValueError):
        service.register_site("Duplicate", camera["id"])
    with pytest.raises(ValueError):
        service.register_site("Wrong type", sensor["id"])
    with pytest.raises(ValueError):
        service.register_site("Unauthorized id", "not-a-device")
    assert len(store.sites()) == 1


def test_schedules_require_related_entities_and_reject_ambiguous_windows(engine, store, household, t0):
    service = SetupService(store, engine.ring, engine.clock, 30)
    site, worker, *_ = household
    first = Schedule(
        site_id=site.id,
        worker_id=worker.id,
        window_start=t0,
        window_end=t0 + timedelta(minutes=30),
        expected_minutes=90,
    )
    service.register_schedule(first)
    with pytest.raises(ValueError):
        service.register_schedule(
            Schedule(
                site_id=site.id,
                worker_id=worker.id,
                window_start=t0 + timedelta(minutes=45),
                window_end=t0 + timedelta(minutes=60),
                expected_minutes=90,
            )
        )
    with pytest.raises(ValueError):
        service.register_schedule(first.model_copy(update={"id": "unknown-worker", "worker_id": "unknown"}))
    with pytest.raises(ValueError):
        service.register_schedule(first)


def test_cancelled_schedule_does_not_create_missing_observation_record(engine, store, household, t0):
    service = SetupService(store, engine.ring, engine.clock, 30)
    site, worker, *_ = household
    schedule = service.register_schedule(
        Schedule(
            site_id=site.id,
            worker_id=worker.id,
            window_start=t0,
            window_end=t0 + timedelta(hours=1),
            expected_minutes=90,
        )
    )
    cancelled = service.cancel_schedule(schedule.id)
    assert cancelled.status == "cancelled" and cancelled.cancelled_at
    assert engine.sweep(t0 + timedelta(hours=4)) == []
    assert store.schedule(schedule.id) is not None


def test_setup_cannot_overwrite_worker_or_accept_invalid_schedule(engine, store, household, t0):
    service = SetupService(store, engine.ring, engine.clock, 30)
    worker = household[1]
    with pytest.raises(ValueError):
        service.register_worker(Worker(id=worker.id, name="Replacement"))
    assert store.worker(worker.id).name == worker.name
    with pytest.raises(ValueError):
        Schedule(site_id="s", worker_id="w", window_start=t0, window_end=t0, expected_minutes=0)
