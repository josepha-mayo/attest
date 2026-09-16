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
