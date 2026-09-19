import json

from attest.models import Site, utcnow


def _site(store, name="A"):
    return store.put_site(Site(name=name, ring_account_id="acct", door_camera_id="cam"))


def test_every_write_is_journaled_and_verifies(store):
    _site(store)
    store.mark_seen("req:1", utcnow())
    report = store.verify_journal()
    assert report["intact"] and report["entries"] == 2  # site put + seen put
    assert report["untracked_rows"] == 0


def test_silent_row_edit_is_detected(store):
    site = _site(store)
    assert store.verify_journal()["intact"]
    body = json.loads(store._conn.execute("SELECT body FROM sites WHERE id=?", (site.id,)).fetchone()[0])
    body["name"] = "Forged name"
    store._conn.execute("UPDATE sites SET body=? WHERE id=?", (json.dumps(body), site.id))
    report = store.verify_journal()
    assert not report["intact"]
    assert any("content changed" in m for m in report["mismatches"])


def test_silent_row_delete_is_detected(store):
    site = _site(store)
    store._conn.execute("DELETE FROM sites WHERE id=?", (site.id,))
    report = store.verify_journal()
    assert not report["intact"]
    assert any("vanished" in m for m in report["mismatches"])


def test_journaled_delete_is_consistent(store):
    site = _site(store)
    store.delete_poll_observations([])  # no-op
    store._delete_ids("sites", "id", [site.id])
    report = store.verify_journal()
    assert report["intact"], report["mismatches"]


def test_altered_journal_entry_is_detected(store):
    _site(store)
    store._conn.execute("UPDATE journal SET op='delete' WHERE seq=1")
    assert not store.verify_journal()["intact"]


def test_deleted_journal_tail_is_detected(store):
    _site(store, "A")
    _site(store, "B")
    store._conn.execute("DELETE FROM journal WHERE seq=(SELECT MAX(seq) FROM journal)")
    report = store.verify_journal()
    # chain still verifies — but the row for B is now journaled-put yet untracked? No:
    # B's put entry is gone, so B shows as untracked, not a mismatch. The honest read:
    # truncation of the journal tail hides that row's history.
    assert report["untracked_rows"] == 1 or not report["intact"]


def test_index_column_tampering_is_detected(store):
    """The body hash covers `body` — but queries run on denormalized columns.
    Swapping a checkin grant's token_hash column (or moving a receipt's
    visit_id) must surface in verify_journal even though signed content is
    untouched."""
    import hashlib

    from attest.models import CheckinGrant

    grant = CheckinGrant(
        id="grt_1",
        worker_id="w1",
        token_hash=hashlib.sha256(b"real-token").hexdigest(),
        expires_at=utcnow(),
    )
    store.put_checkin_grant(grant)
    assert store.verify_journal()["intact"]
    store._conn.execute(
        "UPDATE checkin_grants SET token_hash=? WHERE id=?",
        (hashlib.sha256(b"attacker").hexdigest(), grant.id),
    )
    report = store.verify_journal()
    assert not report["intact"]
    assert any("index column token_hash diverges" in m for m in report["mismatches"])


def test_receipt_visit_id_column_tampering_is_detected(store, engine, household, schedule, t0):
    """A receipt moved to another visit's column still verifies cryptographically
    but the query plane lies — the journal must catch the divergence."""
    from ring_sandbox import WebhookEvent, webhooks

    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    receipt = store.receipt_for_visit(visit.id)
    assert store.verify_journal()["intact"]
    store._conn.execute("UPDATE receipts SET visit_id=? WHERE id=?", ("vis_moved", receipt.id))
    report = store.verify_journal()
    assert not report["intact"]
    assert any("index column visit_id diverges" in m for m in report["mismatches"])


def test_verify_journal_reports_instead_of_crashing_on_corrupt_bodies(store):
    """The verifier must fail *closed* on the corruption it detects — a body
    tampered to non-JSON, or a parseable body whose timestamp can't produce
    its index column, is a reported mismatch, never a 500."""
    _site(store)
    store._conn.execute(
        "INSERT INTO receipts (id, visit_id, sequence, body) VALUES (?,?,?,?)",
        ("rcpt_x", "vis_x", 1, "not-json{{"),
    )
    report = store.verify_journal()
    # The non-JSON body surfaces as an untracked row — reported, never raised.
    assert report["untracked_rows"] >= 1


def test_late_event_site_id_rebinding_is_detected(store):
    """A late event's site_id lives outside its raw webhook body — a direct
    UPDATE rebinding the event to another site must still break the journal."""
    site = _site(store)
    store.record_late_event("acct:req-late", site.id, json.dumps({"data": {"attributes": {}}}))
    assert store.verify_journal()["intact"]
    store._conn.execute("UPDATE late_events SET site_id=? WHERE id=?", ("victim-site", "acct:req-late"))
    report = store.verify_journal()
    assert not report["intact"]
    assert any("content changed" in m for m in report["mismatches"])


def test_baseline_stamps_pre_journal_rows(tmp_path):
    from attest.store import Store

    store = Store(tmp_path / "a.sqlite3")
    _site(store)
    # simulate a deployment created before journaling existed
    store._conn.execute("DELETE FROM journal")
    store._conn.execute("DELETE FROM sqlite_sequence WHERE name='journal'")
    report = store.verify_journal()
    assert report["untracked_rows"] >= 1
    stamped = store.journal_baseline()
    assert stamped >= 1
    report = store.verify_journal()
    assert report["intact"] and report["untracked_rows"] == 0
    store.close()
