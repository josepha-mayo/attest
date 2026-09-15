import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.models import VisitState, utcnow
from attest.poller import HistoryPoller


def event(cam, at, kind="motion_detected", account="ava1.ring.account.SANDBOX"):
    return WebhookEvent.model_validate(
        webhooks.build_event(
            event_type=kind,
            device_id=cam.id,
            occurred_at=at,
            sub_type="human" if kind == "motion_detected" else None,
            account_id=account,
        )
    )


def test_failed_ingest_can_retry_without_partial_visit(engine, store, household, schedule, t0, monkeypatch):
    cam = household[2]
    ev = event(cam, t0)
    original = store.put_evidence
    with monkeypatch.context() as patch:
        patch.setattr(store, "put_evidence", lambda _: (_ for _ in ()).throw(RuntimeError("disk failure")))
        with pytest.raises(RuntimeError):
            engine.ingest(ev)
    assert store.visits() == []
    assert engine.ingest(ev).transitions == ["opened"]
    assert len(store.visits()) == 1
    assert original is not None


def test_concurrent_arrivals_create_one_active_visit(engine, store, household, schedule, t0):
    cam = household[2]
    events = [event(cam, t0 + timedelta(seconds=i)) for i in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(engine.ingest, events))
    assert len(store.visits()) == 1


def test_account_mismatch_cannot_attach_to_site(engine, store, household, schedule, t0):
    result = engine.ingest(event(household[2], t0, account="different-account"))
    assert result.ignored_reason == "account mismatch"
    assert store.visits() == []


def test_schedule_is_not_identity(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    assert visit.worker_id is None
    assert visit.schedule_id == schedule.id


def test_sensor_pattern_does_not_prove_departure_or_work(engine, store, household, schedule, t0):
    _, _, cam, sensor = household
    engine.ingest(event(cam, t0))
    engine.ingest(event(sensor, t0 + timedelta(minutes=12), "contact_sensor_faulted"))
    engine.ingest(event(sensor, t0 + timedelta(minutes=12, seconds=5), "contact_sensor_cleared"))
    visit = engine.ingest(event(cam, t0 + timedelta(minutes=12, seconds=10))).visit
    assert visit.state == VisitState.CLOSED
    assert visit.departed_at is None
    assert visit.duration_minutes is None
    receipt = store.receipt_for_visit(visit.id)
    assert receipt.payload["assessment"]["identity_verified"] is False
    assert receipt.payload["assessment"]["time_worked_minutes"] is None
    assert "Maria Chen arrived" not in visit.summary
    assert "stayed" not in visit.summary


def test_missing_observations_do_not_certify_no_show(engine, store, household, schedule, t0):
    (visit,) = engine.sweep(t0 + timedelta(hours=3))
    assert visit.state.value == "no_observation"
    assert visit.duration_minutes is None
    receipt = store.receipt_for_visit(visit.id)
    assert receipt.payload["first_observed_at"] is None
    assert receipt.payload["assessment"]["attendance"] == "unknown"


def test_single_cue_event_can_be_archived_without_inventing_departure(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    visit.last_seen_at = utcnow() - timedelta(minutes=25)
    store.put_visit(visit)
    (closed,) = engine.sweep()
    assert closed.departed_at is None
    assert closed.duration_minutes is None


def test_clock_conflict_is_flagged_not_clean(engine, store, household, schedule, t0):
    _, _, cam, sensor = household
    engine.ingest(event(cam, t0))
    engine.check_in(engine.issue_checkin(store.active_visit(household[0].id).id), at=utcnow())
    engine.ingest(event(sensor, t0 + timedelta(minutes=90), "contact_sensor_faulted"))
    engine.ingest(event(sensor, t0 + timedelta(minutes=90, seconds=5), "contact_sensor_cleared"))
    visit = engine.ingest(event(cam, t0 + timedelta(minutes=90, seconds=10))).visit
    assert "clock_conflict" in {f.code for f in visit.flags}
    assert "No discrepancies" not in visit.summary


def test_poller_orders_across_event_types(engine, store, household, schedule, ring_client, ring_control, t0):
    cam = household[2]
    for kind, seconds in [("button_press", 0), ("motion_detected", 10)]:
        ring_control.post(
            "/_sandbox/events",
            json={
                "device_id": cam.id,
                "type": kind,
                "sub_type": "human" if seconds else None,
                "at": (t0 + timedelta(seconds=seconds)).isoformat(),
                "deliver": False,
            },
        ).raise_for_status()
    HistoryPoller(engine, store, ring_client, lookback=timedelta(days=2)).poll_once()
    visit = store.active_visit(household[0].id)
    assert visit.arrived_at == t0


def test_receipt_insert_never_overwrites_existing_receipt(engine, store, household, schedule, t0):
    (visit,) = engine.sweep(t0 + timedelta(hours=3))
    receipt = store.receipt_for_visit(visit.id)
    replacement = receipt.model_copy(update={"payload": {"forged": True}})
    with pytest.raises(sqlite3.IntegrityError):
        store.put_receipt(replacement)
    assert store.receipt(receipt.id).payload == receipt.payload


def test_checkin_grant_is_hashed_scoped_expiring_and_single_use(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    token = engine.issue_checkin(visit.id)
    grant = store.checkin_grant(hashlib.sha256(token.encode()).hexdigest())
    assert grant.id == visit.id and token not in grant.model_dump_json()
    replacement = engine.issue_checkin(visit.id)
    assert engine.check_in(token) is None
    assert engine.check_in(replacement) is not None
    assert engine.check_in(replacement) is None


def test_expired_grant_is_rejected(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    token = engine.issue_checkin(visit.id)
    grant = store.checkin_grant(hashlib.sha256(token.encode()).hexdigest())
    grant.expires_at = utcnow() - timedelta(seconds=1)
    store.put_checkin_grant(grant)
    assert engine.check_in(token) is None


def test_duplicate_checkin_is_atomic(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    token = engine.issue_checkin(visit.id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(engine.check_in, [token, token]))
    assert sum(v is not None for v in results) == 1


def test_bedrock_fallback_provenance_is_explicit(engine, store, household, schedule, t0):
    from attest.summarize import BedrockSummarizer

    summarizer = BedrockSummarizer("test-model", "us-east-1")
    summarizer._client_factory = lambda: (_ for _ in ()).throw(RuntimeError("unavailable"))
    engine.summarizer = summarizer
    visit = engine.ingest(event(household[2], t0)).visit
    visit.last_seen_at = utcnow() - timedelta(minutes=25)
    store.put_visit(visit)
    (closed,) = engine.sweep()
    provenance = store.receipt_for_visit(closed.id).payload["summary_provenance"]
    assert provenance["source"] == "template"
    assert provenance["fallback_reason"] == "RuntimeError"
    assert provenance["model"] is None


def test_source_switch_requires_reconciliation(engine, store, household, schedule, t0):
    ev = event(household[2], t0)
    engine.ingest(ev)
    result = engine.ingest(event(household[2], t0), source="history")
    assert result.ignored_reason == "ingestion source changed; reconciliation required"
    assert len(store.visits()) == 1


def test_late_events_are_retained_without_rewriting_signed_records(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    visit.last_seen_at = utcnow() - timedelta(minutes=25)
    store.put_visit(visit)
    engine.sweep()
    before = store.receipts()[0].model_dump_json()
    outcome = engine.ingest(event(household[2], t0 - timedelta(seconds=1)))
    assert outcome.ignored_reason == "late event retained for review"
    assert len(store.late_events()) == 1
    assert store.receipts()[0].model_dump_json() == before
    assert len(store.visits()) == 1


def test_media_read_stays_within_root_and_relative_save_roundtrips(tmp_path, monkeypatch):
    from attest.media import MediaStore

    monkeypatch.chdir(tmp_path)
    media = MediaStore(__import__("pathlib").Path("media"))
    sha, path = media.save("vis_test", "arrival", b"test", "image/png")
    assert media.verify(path, sha)
    assert media.read(tmp_path / "outside.txt") is None
    with pytest.raises(ValueError):
        media.save("../escape", "arrival", b"test", "image/png")
