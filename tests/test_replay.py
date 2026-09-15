from datetime import timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.clock import ExecutionClock
from attest.models import Schedule, Site, Worker, utcnow
from attest.store import Store


def test_replay_clock_is_explicit_persistent_and_monotonic(tmp_path):
    path = tmp_path / "state.sqlite3"
    store = Store(path)
    clock = ExecutionClock(store, replay=True, ring_base_url="http://127.0.0.1:8787")
    start = utcnow() - timedelta(days=1)
    with pytest.raises(ValueError):
        clock.now()
    clock.start(start)
    clock.advance(start + timedelta(minutes=3))
    store.close()
    reopened = Store(path)
    clock = ExecutionClock(reopened, replay=True, ring_base_url="http://127.0.0.1:8787")
    assert clock.now() == start + timedelta(minutes=3)
    with pytest.raises(ValueError):
        clock.advance(start)
    with pytest.raises(ValueError):
        clock.advance(utcnow() + timedelta(minutes=1))
    with pytest.raises(ValueError):
        ExecutionClock(reopened, replay=False, ring_base_url="http://127.0.0.1:8787")
    reopened.close()


def test_replay_cannot_target_real_ring_or_repurpose_existing_data():
    store = Store()
    with pytest.raises(ValueError):
        ExecutionClock(store, replay=True, ring_base_url="https://api.amazonvision.com")
    store.put_worker(Worker(name="Existing worker"))
    with pytest.raises(ValueError):
        ExecutionClock(store, replay=True, ring_base_url="http://127.0.0.1:8787")
    store.close()


def test_replay_checkin_uses_event_clock_but_grants_use_wall_clock(store, settings, ring_client, tmp_path):
    from attest.engine import VisitEngine
    from attest.ledger import Signer
    from attest.media import MediaStore
    from attest.summarize import TemplateSummarizer

    settings.replay_mode = True
    ring_client.base_url = "http://127.0.0.1:8787"
    engine = VisitEngine(
        store, ring_client, Signer.ephemeral(), MediaStore(tmp_path / "media"), TemplateSummarizer(), settings
    )
    t0 = utcnow() - timedelta(days=1)
    engine.clock.start(t0)
    site = store.put_site(
        Site(name="Demo", ring_account_id="ava1.ring.account.SANDBOX", door_camera_id="cam")
    )
    worker = store.put_worker(Worker(name="Demo Worker"))
    store.put_schedule(
        Schedule(
            site_id=site.id,
            worker_id=worker.id,
            window_start=t0,
            window_end=t0 + timedelta(hours=2),
            expected_minutes=90,
        )
    )
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id="cam",
            occurred_at=t0,
        )
    )
    visit = engine.ingest(event).visit
    engine.clock.advance(t0 + timedelta(seconds=30))
    token = engine.issue_checkin(visit.id)
    target = engine.checkin_target(token)
    assert target[0].expires_at > utcnow()
    checked = engine.check_in(token)
    assert checked.checked_in_at == t0 + timedelta(seconds=30)
    assert checked.checkin_received_at > t0 + timedelta(hours=23)
    assert checked.clock_mode == "replay"
    engine.clock.advance(t0 + timedelta(minutes=90))
    engine.close_for_review(visit.id)
    receipt = store.receipt_for_visit(visit.id)
    assert receipt.payload["clock"]["mode"] == "replay"
    assert "clock_conflict" not in {f.code for f in store.visit(visit.id).flags}
