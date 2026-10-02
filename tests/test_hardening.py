"""Fail-closed hardening: corrupt rows, missing stores, malformed artifacts,
dangling references, inverted windows, and not-yet-admissible deliveries.

Each test pins the honest behavior — an error line or a flagged member, never
a traceback, a silently-skipped record, or a falsely-"intact" verdict."""

import json
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from attest import cli
from attest.config import Settings
from attest.corroborate import corroboration
from attest.inbox import WebhookInbox
from attest.models import Site, utcnow
from attest.store import Store, StoreCorrupt


def _cli_settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path, admin_token="test-admin-token-only-" + "x" * 32, ring_webhook_key="k")


def _file_store(tmp_path: Path) -> Store:
    return Store(tmp_path / "attest.sqlite3")


def test_corrupt_row_fails_closed_not_silently_skipped(tmp_path):
    store = _file_store(tmp_path)
    store.put_site(Site(name="A", ring_account_id="acct", door_camera_id="cam"))
    store.close()
    db = tmp_path / "attest.sqlite3"
    sqlite3.connect(db).execute("UPDATE sites SET body='{' ").connection.commit()
    with pytest.raises(StoreCorrupt, match="corrupt"):
        _file_store(tmp_path).sites()


def test_cli_clean_exit_on_corrupt_store(tmp_path, monkeypatch):
    """A non-dict settings row used to traceback `attest status` at
    `(...).get("mode")` — the top-level guard now exits with an error line."""
    store = _file_store(tmp_path)
    store.put_site(Site(name="A", ring_account_id="acct", door_camera_id="cam"))
    store.close()
    sqlite3.connect(tmp_path / "attest.sqlite3").execute(
        "INSERT INTO settings (name, body) VALUES ('execution_mode', '5')"
    ).connection.commit()
    monkeypatch.setattr(cli, "settings", _cli_settings(tmp_path))
    with pytest.raises(SystemExit) as exc:
        cli.main(["status"])
    assert exc.value.code and "corrupt" in str(exc.value.code)


def test_corrupt_receipt_body_fails_closed_in_journal_and_reads(tmp_path):
    """A garbage receipts row: reads raise StoreCorrupt (never silently skip),
    and verify_journal's body-hash check names the divergent row."""
    store = _file_store(tmp_path)
    store.put_site(Site(name="A", ring_account_id="acct", door_camera_id="cam"))
    conn = sqlite3.connect(tmp_path / "attest.sqlite3")
    cols = [r[1] for r in conn.execute("PRAGMA table_info(receipts)").fetchall()]
    conn.execute(
        f"INSERT INTO receipts ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
        ["bad-row"] + [None] * (len(cols) - 2) + ["{"],
    )
    conn.commit()
    store.close()
    store = _file_store(tmp_path)
    report = store.verify_journal()
    assert report["untracked_rows"] == 1  # the out-of-band write is flagged
    with pytest.raises(StoreCorrupt):
        store.receipts()
    store.close()


def test_journal_refuses_a_store_that_never_existed(tmp_path, monkeypatch):
    """`attest journal` on an empty dir must not mint an empty db and call it
    intact — a false-positive verdict on a verify surface."""
    monkeypatch.setattr(cli, "settings", _cli_settings(tmp_path))
    with pytest.raises(SystemExit):
        cli.main(["journal"])
    assert not (tmp_path / "attest.sqlite3").exists()


def test_verify_malformed_artifact_exits_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "settings", _cli_settings(tmp_path))
    bad = tmp_path / "r.json"
    bad.write_text(json.dumps({"payload": {}, "signature": "x"}))
    with pytest.raises(SystemExit) as exc:
        cli.main(["verify", str(bad)])
    assert exc.value.code != 0


def test_verify_missing_file_exits_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "settings", _cli_settings(tmp_path))
    with pytest.raises(SystemExit) as exc:
        cli.main(["verify", str(tmp_path / "nope.json")])
    assert exc.value.code != 0


def test_corroboration_survives_a_missing_site_row(engine, store, household, t0, ring_world):
    """A visit whose site row is gone still renders its evidence honestly —
    the signed receipt carries the device binding, the row labels say the site
    record is unavailable."""
    from ring_sandbox import WebhookEvent, webhooks

    ring_world.record_event(household[2].id, "button_press", at_ms=int(t0.timestamp() * 1000))
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    receipt = store.receipt_for_visit(visit.id)
    rows = corroboration(visit, None, None, store.evidence_for(visit.id), receipt)
    assert rows  # renders rather than crashing
    assert any("unavailable" in r["source"] for r in rows if "Camera" in r["source"])
    cam = next(r for r in rows if r["source"].startswith("Camera"))
    assert cam["status"] != "silent"  # receipt-carried device id still buckets evidence


def test_coverage_refuses_inverted_window(engine, store, household):
    site = household[0]
    now = utcnow()
    with pytest.raises(ValueError, match="empty"):
        engine.issue_coverage_attestation(site, now, now - timedelta(hours=1))
    with pytest.raises(ValueError, match="empty"):
        engine.issue_period_digest(site, now, now - timedelta(hours=1))


def test_future_dated_delivery_reschedules_past_admissibility(tmp_path):
    """An event 90s early must not burn its five-attempt budget — it waits for
    the instant it becomes admissible, still pending, never 'failed'."""
    inbox = WebhookInbox(tmp_path / "inbox.sqlite3")
    try:
        inbox.enqueue("req", b"body", "sig")
        job = inbox.claim(now=1000.0)
        admissible = 1000.0 + 90
        inbox.fail(job, "future_timestamp", now=1000.0, retry_at=admissible, terminal=False)
        row = inbox._db.execute("SELECT * FROM deliveries WHERE id='req'").fetchone()
        assert row["status"] == "pending" and row["retry_at"] == admissible
        # not claimable before the admissibility instant, claimable at it
        assert inbox.claim(now=admissible - 1) is None
        job = inbox.claim(now=admissible)
        assert job is not None
        # and a NOT-YET-admissible failure never dead-letters even at attempt 5
        for _ in range(4):
            inbox.fail(job, "future_timestamp", now=admissible, retry_at=admissible, terminal=False)
            job = inbox.claim(now=admissible)
            assert job is not None
        assert inbox.counts().get("failed", 0) == 0
    finally:
        inbox.close()


def test_inverted_coverage_window_shape_is_complete(store):
    """coverage_report's no_window early return carries the same keys the
    normal report does — consumers must not see a drifted shape."""
    from attest.coverage import coverage_report

    now = utcnow()
    report = coverage_report(store, "dev", now, now - timedelta(hours=1), now=now, site_id="s")
    for key in (
        "state",
        "fraction",
        "covered",
        "gaps",
        "polls",
        "failed_polls",
        "events",
        "window",
        "claim",
        "interruptions",
        "live_sessions",
    ):
        assert key in report
    assert report["state"] == "no_window"


def test_packdiff_flags_malformed_bundle_member(engine, store, household, schedule, t0, tmp_path):
    """A pack whose bundle member parses as JSON but isn't a bundle must be
    flagged per-member — the diff still reports the other records, it must not
    abort the whole comparison as 'cannot compare'."""
    import zipfile

    from ring_sandbox import WebhookEvent, webhooks

    from attest.disputepack import build_case_pack
    from attest.packdiff import load_artifact
    from attest.reviews import ReviewService, countersign_status

    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    bundle = service.bundle(visit.id)
    good = tmp_path / "good.zip"
    good.write_bytes(
        build_case_pack(store, tmp_path / "media", site, [(visit, bundle, countersign_status(bundle))])
    )
    damaged = tmp_path / "damaged.zip"
    with zipfile.ZipFile(good) as zin, zipfile.ZipFile(damaged, "w") as zout:
        for item in zin.namelist():
            data = zin.read(item)
            if item.endswith("/bundle.json"):
                data = b"{}"
            zout.writestr(item, data)
    loaded = load_artifact(damaged)
    assert any("malformed" in f or "missing" in f for f in loaded["verify_failures"])


def test_explain_attestation_honors_json(engine, store, household, t0, tmp_path, monkeypatch, capsys):
    """`explain --json` must emit the same structured record for attestation
    ids as for visit ids — the machine-readable mode can't silently degrade
    to prose."""

    site = household[0]
    receipt = engine.issue_coverage_attestation(site, t0 - timedelta(minutes=10), t0)
    monkeypatch.setattr(cli, "settings", _cli_settings(tmp_path))
    # explain opens the on-disk store — persist this engine's store there
    file_store = _file_store(tmp_path)
    file_store.put_site(site)
    file_store.put_receipt(receipt)
    file_store.close()
    cli.main(["explain", receipt.visit_id, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert out["record_type"] == "coverage_attestation"
    assert out["signature"]["verified"] is True
    assert "never identity" in out["boundary"]
    assert "never identity" in out["boundary"]
