import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.attackdemo import run


@pytest.fixture
def seeded(engine, store, household, schedule, t0):
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    visit = engine.ingest(event).visit
    # A lifecycle row too — the retimestamp attack needs one to edit.
    engine.ingest(
        WebhookEvent.model_validate(
            webhooks.build_event(
                event_type="device_offline",
                device_id=household[2].id,
                occurred_at=t0,
            )
        )
    )
    engine.close_for_review(visit.id)
    return visit


def test_battery_catches_everything_and_leaves_store_unchanged(store, seeded):
    out = run(store)
    assert out["unchanged"], out
    for r in out["results"]:
        assert r["caught"], f"{r['attack']} went undetected: {r['detail']}"


def test_receipts_pin_journal_head(store, seeded):
    """The signed payload anchors the ops log at issuance — a later truncation
    cannot hide behind the remaining self-consistent chain."""
    receipt = store.receipt_for_visit(seeded.id)
    assert receipt.payload["journal_head"]
    assert store.verify_journal()["pinned_heads"] >= 1
    # erase the tail through the pinned head
    seq = store._conn.execute(
        "SELECT seq FROM journal WHERE hash=?", (receipt.payload["journal_head"],)
    ).fetchone()[0]
    store._conn.execute("DELETE FROM journal WHERE seq>=?", (seq,))
    report = store.verify_journal()
    assert not report["intact"]
    assert any("pinned head" in m for m in report["mismatches"])
