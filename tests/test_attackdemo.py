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
    # A live-view session too — the session-retimestamp attack needs one.
    row, _answer = engine.open_liveview(household[0].id, "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=x\r\nt=0 0\r\n")
    engine.close_liveview(household[0].id, row.id)
    engine.close_for_review(visit.id)
    # A signed resolution too — the reason-code forge attack needs one.
    from attest.models import ResolutionInput
    from attest.reviews import ReviewService

    ReviewService(store, engine.signer, engine.clock).resolve(
        visit.id,
        ResolutionInput(outcome="inconclusive", statement="Unclear.", reason_code="device_fault"),
    )
    return visit


def test_battery_catches_everything_and_leaves_store_unchanged(store, seeded, tmp_path):
    out = run(store, tmp_path / "media")
    assert out["unchanged"], out
    for r in out["results"]:
        # None = no target on this store (skipped), not a missed defense
        assert r["caught"] is not False, f"{r['attack']} went undetected: {r['detail']}"


def test_battery_catches_inbox_delivery_id_conflict(store, seeded, tmp_path):
    """A reused request_id with different bytes refuses — the inbox lives in
    its own database, so this exercises the inbox= wiring the CLI passes."""
    from attest.inbox import WebhookInbox

    inbox = WebhookInbox(tmp_path / "webhooks.sqlite3")
    try:
        inbox.enqueue("acct:req-1", b'{"delivered": true}', "sig-1")
        out = run(store, tmp_path / "media", inbox=inbox)
        hit = next(r for r in out["results"] if "request_id" in r["attack"])
        assert hit["caught"] is True, hit["detail"]
        assert out["unchanged"], out
    finally:
        inbox.close()


def test_battery_catches_corrupt_row_and_settings_and_pack_names(store, seeded, tmp_path):
    """The fail-closed reads and zip member-name gate run inside the battery —
    the demo's claim is only as strong as the attacks it actually executes."""
    out = run(store, tmp_path / "media")
    by_name = {r["attack"]: r for r in out["results"]}
    assert by_name["corrupt a stored row's body (crash the read surfaces)"]["caught"] is True
    assert by_name["corrupt a settings row (non-dict body)"]["caught"] is True
    assert by_name["inject duplicate + traversal member names into a pack zip"]["caught"] is True


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
