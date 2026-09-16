from datetime import timedelta

from ring_sandbox import WebhookEvent, webhooks

from attest.corroborate import corroboration


def _visit(engine, household, t0):
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    return engine.ingest(event).visit


def test_matrix_labels_each_source_honestly(engine, store, household, schedule, t0):
    visit = _visit(engine, household, t0)
    rows = corroboration(
        visit,
        household[0],
        schedule,
        store.evidence_for(visit.id),
        store.receipt_for_visit(visit.id),
    )
    by_source = {r["source"]: r for r in rows}
    assert "planned" in by_source["Scheduled expectation"]["establishes"]
    assert by_source[f"Camera/doorbell {household[2].id[-6:]}"]["status"].startswith("2 events")
    assert by_source["Worker self-report"]["status"] == "none received"
    assert "claim" in by_source["Worker self-report"]["establishes"]


def test_sensor_silence_and_unbound_are_distinct(engine, store, household, schedule, t0):
    visit = _visit(engine, household, t0)
    site = household[0]
    rows = corroboration(visit, site, schedule, store.evidence_for(visit.id), None)
    sensor = next(r for r in rows if r["source"].startswith("Contact sensor"))
    assert sensor["status"] == "silent"

    site.door_sensor_id = None
    rows = corroboration(visit, site, schedule, store.evidence_for(visit.id), None)
    sensor = next(r for r in rows if r["source"].startswith("Contact sensor"))
    assert sensor["status"] == "not bound"


def test_checkin_divergence_is_called_out(engine, store, household, schedule, t0):
    visit = _visit(engine, household, t0)
    visit.checked_in_at = t0 + timedelta(minutes=45)
    rows = corroboration(visit, household[0], schedule, store.evidence_for(visit.id), None)
    divergence = next((r for r in rows if r["source"] == "Source divergence"), None)
    assert divergence is not None and "45 min" in divergence["status"]
    assert "neither source is authoritative" in divergence["establishes"]


def test_no_divergence_when_checkin_close_to_observation(engine, store, household, schedule, t0):
    visit = _visit(engine, household, t0)
    visit.checked_in_at = t0 + timedelta(minutes=5)
    rows = corroboration(visit, household[0], schedule, store.evidence_for(visit.id), None)
    assert not any(r["source"] == "Source divergence" for r in rows)
