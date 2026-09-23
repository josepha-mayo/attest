"""Retention preview: reports what policy would touch without deleting anything."""

from datetime import timedelta

from ring_sandbox import webhooks

from attest import retention
from attest.inbox import WebhookInbox
from attest.models import CheckinGrant, Site, Visit, VisitState, utcnow


def _closed_visit(store, site_id, at):
    return store.put_visit(
        Visit(
            site_id=site_id,
            state=VisitState.CLOSED,
            arrived_at=at,
            last_activity_at=at + timedelta(hours=1),
            closed_at=at + timedelta(hours=1),
        )
    )


def test_empty_runtime_reports_zeros(store, tmp_path):
    report = retention.build_report(store, None, tmp_path / "media")
    assert report["mode"] == "preview"
    assert report["totals"]["visits"]["total"] == 0
    assert all(b["total"] == 0 for b in report["candidates"].values())


def test_report_identifies_candidates_without_deleting(store, tmp_path):
    now = utcnow()
    old = now - timedelta(days=400)
    recent = now - timedelta(days=2)
    site = store.put_site(
        Site(name="Demo", ring_account_id="ava1.ring.account.SANDBOX", door_camera_id="cam")
    )
    old_visit = _closed_visit(store, site.id, old)
    new_visit = _closed_visit(store, site.id, recent)
    store.put_checkin_grant(
        CheckinGrant(id="g1", worker_id="w", token_hash="h1", expires_at=now - timedelta(days=30))
    )
    store.put_checkin_grant(
        CheckinGrant(id="g2", worker_id="w", token_hash="h2", expires_at=now + timedelta(hours=1))
    )
    store.mark_seen("acct:req-old", now - timedelta(days=60))
    store.mark_seen("acct:req-new", now)
    store.record_late_event(
        "acct:req-late",
        site.id,
        webhooks.encode(
            webhooks.build_event(
                event_type="motion_detected", device_id="cam", occurred_at=now - timedelta(days=120)
            )
        ).decode(),
    )
    media_root = tmp_path / "media"
    (media_root / old_visit.id).mkdir(parents=True)
    (media_root / old_visit.id / "arrival.abc.png").write_bytes(b"png")
    (media_root / new_visit.id).mkdir(parents=True)
    (media_root / new_visit.id / "arrival.def.png").write_bytes(b"png")
    (media_root / "vis_orphan").mkdir(parents=True)
    (media_root / "vis_orphan" / "x.bin").write_bytes(b"orphan")

    inbox_path = tmp_path / "webhooks.sqlite3"
    inbox = WebhookInbox(inbox_path)
    inbox.enqueue("acct:req-done", b"{}", "sig")
    job = inbox.claim()
    inbox.complete(job, "done")
    inbox._db.execute(
        "UPDATE deliveries SET received_at=?", (now.timestamp() - 40 * 86400,)
    )  # age the delivery
    inbox.enqueue("acct:req-fresh", b"{}", "sig2")

    before = store.stats()
    report = retention.build_report(store, inbox, media_root, now=now)
    after = store.stats()

    # nothing was deleted or modified
    assert before == after
    assert report["totals"]["media"] == {"files": 3, "bytes": 3 + 3 + 6}
    assert report["totals"]["deliveries"] == {"done": 1, "pending": 1}

    c = report["candidates"]
    assert [v["id"] for v in c["closed_visits"]["items"]] == [old_visit.id]
    assert {g["id"] for g in c["grants"]["items"]} == {"g1"}
    assert c["seen_requests"]["items"] == ["acct:req-old"]
    assert [e["id"] for e in c["late_events"]["items"]] == ["acct:req-late"]
    assert [d["id"] for d in c["deliveries"]["items"]] == ["acct:req-done"]
    media_paths = {m["path"] for m in c["media_files"]["items"]}
    assert any(p.startswith(old_visit.id) for p in media_paths)
    assert any(p.startswith("vis_orphan") for p in media_paths)
    assert not any(p.startswith(new_visit.id) for p in media_paths)
    inbox.close()


def test_apply_deletes_only_the_reviewed_set(store, tmp_path):
    import pytest

    now = utcnow()
    old = now - timedelta(days=400)
    site = store.put_site(
        Site(name="Demo", ring_account_id="ava1.ring.account.SANDBOX", door_camera_id="cam")
    )
    old_visit = _closed_visit(store, site.id, old)
    store.put_checkin_grant(
        CheckinGrant(id="g1", worker_id="w", token_hash="h1", expires_at=now - timedelta(days=30))
    )
    store.put_checkin_grant(
        CheckinGrant(id="g2", worker_id="w", token_hash="h2", expires_at=now + timedelta(hours=1))
    )
    store.mark_seen("acct:req-old", now - timedelta(days=60))
    store.mark_seen("acct:req-new", now)
    media_root = tmp_path / "media"
    (media_root / old_visit.id).mkdir(parents=True)
    (media_root / old_visit.id / "arrival.abc.png").write_bytes(b"png")

    inbox = WebhookInbox(tmp_path / "webhooks.sqlite3")
    inbox.enqueue("acct:req-done", b"{}", "sig")
    job = inbox.claim()
    inbox.complete(job, "done")
    inbox._db.execute("UPDATE deliveries SET received_at=?", (now.timestamp() - 40 * 86400,))
    inbox.enqueue("acct:req-pending", b"{}", "sig2")  # stays pending, never deletable

    report = retention.build_report(store, inbox, media_root, now=now)
    token = report["apply_token"]

    with pytest.raises(ValueError):
        retention.apply(store, inbox, media_root, now=now, confirm="bogus")

    # data changes invalidate the token before apply
    store.mark_seen("acct:req-newer", now - timedelta(days=60))
    with pytest.raises(ValueError):
        retention.apply(store, inbox, media_root, now=now, confirm=token)

    report = retention.build_report(store, inbox, media_root, now=now)
    result = retention.apply(store, inbox, media_root, now=now, confirm=report["apply_token"])
    d = result["deleted"]
    assert d["deliveries"] == 1 and d["grants"] == 1
    assert d["seen_requests"] == 2 and d["media_files"] == 1 and d["late_events"] == 0
    assert result["kept"]["closed_visits"] == 1

    assert store.checkin_grant("h1") is None and store.checkin_grant("h2") is not None
    assert store.mark_seen("acct:req-old", now)  # deleted dedupe key re-registers as new
    assert store.visit(old_visit.id) is not None  # chain-linked record preserved
    assert inbox.counts() == {"pending": 1}  # pending delivery untouched
    assert not list(media_root.rglob("*.*"))  # media file gone
    inbox.close()


def test_coverage_events_purge_but_signed_claim_survives(engine, store, household, tmp_path):
    """Raw lifecycle rows are retention-purgeable like poll rows — but the
    signed coverage attestation already copied the interruptions into its
    payload, so purging the log never rewrites the signed explanation."""
    from attest.ledger import verify_receipt
    from attest.models import CoverageEvent, CoverageEventKind

    now = utcnow()
    old = now - timedelta(days=400)
    site, _worker, cam, _sensor = household
    store.put_coverage_event(
        CoverageEvent(site_id=site.id, device_id=cam.id, at=old, kind=CoverageEventKind.DEVICE_OFFLINE)
    )
    store.put_coverage_event(
        CoverageEvent(
            site_id=site.id,
            device_id=cam.id,
            at=now - timedelta(days=1),
            kind=CoverageEventKind.DEVICE_ONLINE,
        )
    )

    receipt = engine.issue_coverage_attestation(site, old - timedelta(hours=1), old + timedelta(hours=1))
    assert [i["kind"] for i in receipt.payload["coverage"]["interruptions"]] == ["device_offline"]

    report = retention.build_report(store, None, tmp_path / "media", now=now)
    assert [e["kind"] for e in report["candidates"]["coverage_events"]["items"]] == ["device_offline"]
    result = retention.apply(store, None, tmp_path / "media", now=now, confirm=report["apply_token"])
    assert result["deleted"]["coverage_events"] == 1
    assert [e.kind for e in store.coverage_events(site.id)] == [CoverageEventKind.DEVICE_ONLINE]
    assert verify_receipt(receipt, public_key=engine.signer.public_key_b64)[0]


def test_apply_endpoint_requires_matching_preview_token(settings, store, ring_client, household):
    from fastapi.testclient import TestClient

    from attest.app import create_app
    from attest.ledger import Signer

    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    admin = ("admin", settings.admin_token.get_secret_value())
    with TestClient(app) as client:
        assert client.post("/api/retention/apply", json={"confirm": "x"}).status_code == 401
        assert client.post("/api/retention/apply", json={"confirm": "bogus"}, auth=admin).status_code == 409
        token = client.get("/api/retention", auth=admin).json()["apply_token"]
        r = client.post("/api/retention/apply", json={"confirm": token}, auth=admin)
        assert r.status_code == 200 and "deleted" in r.json()


def test_retention_endpoint_reports_without_deleting(settings, store, ring_client, household):
    from fastapi.testclient import TestClient

    from attest.app import create_app
    from attest.ledger import Signer

    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    admin = ("admin", settings.admin_token.get_secret_value())
    with TestClient(app) as client:
        assert client.get("/api/retention").status_code == 401
        r = client.get("/api/retention", auth=admin)
        assert r.status_code == 200
        body = r.json()
        assert body["mode"] == "preview"
        assert "policy" in body and "totals" in body and "candidates" in body
        assert client.get("/api/state", auth=admin).json()["sites"]  # data still present
