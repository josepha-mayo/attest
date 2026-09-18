"""HTTP-level: signed webhook in -> dashboard, check-in page, receipt download, verify page."""

from datetime import timedelta

import httpx
import pytest
from ring_sandbox import webhooks

from attest.app import create_app
from attest.ledger import Signer
from attest.models import VisitState

KEY = "k"


@pytest.fixture
def api(settings, store, ring_client, household, schedule):
    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    with _client(app) as c:
        c.auth = ("admin", settings.admin_token.get_secret_value())
        c.attest_state = app.state
        yield c
    app.state.inbox.close()


def _client(app):
    import asyncio

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            async def go():
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://t"
                ) as ac:
                    r = await ac.request(
                        request.method,
                        request.url,
                        headers=request.headers,
                        content=request.content,
                    )
                    await r.aread()
                    return httpx.Response(
                        r.status_code, headers=r.headers, content=r.content, request=request
                    )

            return asyncio.run(go())

    return httpx.Client(transport=T(), base_url="http://t", follow_redirects=False)


def _post_hook(api, device_id, etype, at, sub=None, key=KEY):
    body = webhooks.encode(
        webhooks.build_event(event_type=etype, device_id=device_id, occurred_at=at, sub_type=sub)
    )
    response = api.post(
        "/webhooks/ring",
        content=body,
        headers={
            "Content-Type": "application/json",
            webhooks.SIGNATURE_HEADER: webhooks.sign(key, body),
        },
    )
    if response.status_code == 202:
        assert api.post("/api/process-webhooks").status_code == 200
    return response


@pytest.mark.parametrize(
    "path", ["/", "/api/state", "/receipts.json", "/verify", "/visits/unknown/media/a.png"]
)
def test_records_require_auth(api, path):
    assert api.get(path, auth=None).status_code == 401


def test_admin_writes_require_auth_and_same_origin(api):
    assert api.post("/api/sweep", auth=None).status_code == 401
    assert api.post("/api/sweep", headers={"Origin": "https://untrusted.example"}).status_code == 403
    assert api.get("/api/state").headers["Cache-Control"] == "no-store"


def test_old_worker_tokens_no_longer_authenticate(api):
    assert api.get("/checkin/tok123", auth=None).status_code == 404
    assert api.post("/checkin/tok123", auth=None).status_code == 410  # dead link page


def test_rejects_bad_signature(api, household, t0):
    _, _, cam, _ = household
    r = _post_hook(api, cam.id, "button_press", t0, key="wrong")
    assert r.status_code == 401


def test_webhook_to_receipt(api, store, household, schedule, t0):
    site, worker, cam, sensor = household
    t = t0 + timedelta(minutes=1)
    r = _post_hook(api, cam.id, "motion_detected", t, "human")
    assert r.status_code == 202 and r.json()["status"] == "queued"
    vid = store.active_visit(site.id).id

    claim_path = api.post(f"/api/visits/{vid}/checkin-link").json()["path"]
    page = api.get(claim_path, auth=None)
    assert page.status_code == 200 and "Are you there now" in page.text
    assert api.post(claim_path, auth=None).status_code == 200
    assert api.post(claim_path, auth=None).status_code == 410  # consumed link -> Gone page
    assert store.visit(vid).state == VisitState.IN_PROGRESS

    leave = t + timedelta(minutes=85)
    _post_hook(api, sensor.id, "contact_sensor_faulted", leave)
    _post_hook(api, sensor.id, "contact_sensor_cleared", leave + timedelta(seconds=10))
    r = _post_hook(api, cam.id, "motion_detected", leave + timedelta(seconds=20), "human")
    assert r.status_code == 202 and store.visit(vid).state == VisitState.CLOSED

    dash = api.get("/")
    assert dash.status_code == 200 and "Maria Chen" in dash.text and "chain intact" in dash.text

    visit_page = api.get(f"/visits/{vid}")
    assert "Ed25519 signature valid" in visit_page.text

    receipt_id = store.visit(vid).receipt_id
    rj = api.get(f"/receipts/{receipt_id}.json")
    assert rj.status_code == 200 and rj.json()["payload"]["worker"] == "Maria Chen"

    ok = api.post("/verify", data={"text": rj.text})
    assert "&#10003;" in ok.text or "✓" in ok.text
    tampered = rj.json()
    tampered["payload"]["duration_minutes"] = 90
    import json

    bad = api.post("/verify", data={"text": json.dumps(tampered)})
    assert "hash mismatch" in bad.text

    export = api.get("/receipts.json")
    assert len(export.json()) == 1
    ok = api.post("/verify", data={"text": export.text})
    assert "chain intact" in ok.text


def test_redacted_case_pack_upload_verifies(api, household, t0):
    site, _, cam, _ = household
    r = _post_hook(api, cam.id, "motion_detected", t0, "human")
    assert r.status_code == 202
    vid = api.attest_state.store.active_visit(site.id).id
    assert api.post(f"/api/visits/{vid}/close").status_code == 200

    pack = api.get(f"/sites/{site.id}/pack.zip?redact_media=1")
    assert pack.status_code == 200
    from attest.app import _verify_pack

    ok, detail = _verify_pack(pack.content, api.attest_state.signer.public_key_b64)
    assert ok, detail
    assert "withheld" in detail


def test_verify_pack_page_serves_the_standalone_verifier(api):
    """The dashboard serves the same zero-dependency verifier the packs embed —
    a judge can drop a .zip without extracting anything."""
    r = api.get("/verify-pack")
    assert r.status_code == 200
    assert 'id="drop"' in r.text
    assert "checkReceipt" in r.text  # the self-contained Ed25519 verifier


def test_case_pack_attestations_verify_and_fail_closed(api, household, t0):
    """Site-level attestations travel in the pack: a coverage cert issued before
    export must verify under the issuer key — and removing it must fail."""
    import io
    import zipfile
    from datetime import timedelta

    site, _, cam, _ = household
    r = _post_hook(api, cam.id, "motion_detected", t0, "human")
    assert r.status_code == 202
    vid = api.attest_state.store.active_visit(site.id).id
    assert api.post(f"/api/visits/{vid}/close").status_code == 200
    api.attest_state.engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))

    pack = api.get(f"/sites/{site.id}/pack.zip")
    assert pack.status_code == 200
    from attest.app import _verify_pack

    ok, detail = _verify_pack(pack.content, api.attest_state.signer.public_key_b64)
    assert ok, detail

    zin = zipfile.ZipFile(io.BytesIO(pack.content))
    dropped = [n for n in zin.namelist() if not n.startswith("attestations/")]
    assert len(dropped) < len(zin.namelist())  # attestations were present
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
        for n in dropped:
            zout.writestr(n, zin.read(n))
    ok, detail = _verify_pack(buf.getvalue(), api.attest_state.signer.public_key_b64)
    assert not ok
    assert "attestation" in detail


def test_webhook_ack_does_not_wait_for_enrichment(api, household, t0, monkeypatch):
    called = []
    monkeypatch.setattr(api.attest_state.engine, "ingest", lambda ev: called.append(ev))
    body = webhooks.encode(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    response = api.post(
        "/webhooks/ring",
        content=body,
        auth=None,
        headers={
            "Content-Type": "application/json",
            webhooks.SIGNATURE_HEADER: webhooks.sign(KEY, body),
        },
    )
    assert response.status_code == 202
    assert called == []
    assert api.get("/api/webhook-queue").json() == {"pending": 1}


def test_invalid_delivery_never_enters_queue(api, household, t0):
    response = _post_hook(api, household[2].id, "button_press", t0, key="invalid")
    assert response.status_code == 401
    assert api.get("/api/webhook-queue").json() == {}


def test_requeue_endpoint_revives_failed_deliveries(api):
    inbox = api.attest_state.inbox
    inbox.enqueue("acct:req1", b"{}", "sig")
    for attempt in range(5):
        now = 1000 + attempt * 1000
        inbox.fail(inbox.claim(now=now), "RuntimeError", now=now)
    assert api.get("/api/webhook-queue").json() == {"failed": 1}

    r = api.post("/api/webhook-queue/requeue", json={})
    assert r.status_code == 200 and r.json()["requeued"] == 1
    assert r.json()["queue"] == {"pending": 1}
    r = api.post("/api/webhook-queue/requeue", json={"ids": ["acct:req1"]})
    assert r.json()["requeued"] == 0  # pending rows are not requeued


def test_intake_is_not_blocked_by_a_visit_transaction(api, store, household, t0):
    from concurrent.futures import ThreadPoolExecutor

    body = webhooks.encode(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with store.transaction():
            pending = pool.submit(
                api.post,
                "/webhooks/ring",
                content=body,
                auth=None,
                headers={webhooks.SIGNATURE_HEADER: webhooks.sign(KEY, body)},
            )
            assert pending.result(timeout=2).status_code == 202


def test_lifespan_worker_processes_a_durable_delivery(settings, store, ring_client, household, schedule, t0):
    import time

    from fastapi.testclient import TestClient

    from attest.inbox import WebhookInbox

    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    body = webhooks.encode(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    with TestClient(app) as client:
        assert (
            client.post(
                "/webhooks/ring",
                content=body,
                headers={
                    webhooks.SIGNATURE_HEADER: webhooks.sign(KEY, body),
                },
            ).status_code
            == 202
        )
        deadline = time.monotonic() + 3
        while app.state.inbox.counts().get("done") != 1 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert app.state.inbox.counts() == {"done": 1}
        assert store.active_visit(household[0].id) is not None
    recovered = WebhookInbox(settings.data_dir / "webhooks.sqlite3")
    assert recovered.counts() == {"done": 1}
    assert recovered.claim() is None
    recovered.close()


def test_worker_and_coordinator_review_flow_keeps_original(api, store, household, t0):
    _post_hook(api, household[2].id, "button_press", t0)
    visit = store.active_visit(household[0].id)
    assert api.post(f"/api/visits/{visit.id}/close").status_code == 200
    original = store.receipt_for_visit(visit.id).model_dump_json()
    endpoint = f"/api/visits/{visit.id}/reviews"
    assert api.post(endpoint, auth=None, json={"decision": "dispute", "statement": "x"}).status_code == 401
    assert (
        api.post(endpoint, json={"decision": "confirm", "statement": "x", "actor": "worker"}).status_code
        == 422
    )
    response = api.post(
        endpoint, json={"decision": "inconclusive", "statement": "Requesting worker context."}
    )
    assert response.status_code == 200
    link = api.post(f"/api/visits/{visit.id}/review-link").json()["path"]
    assert api.get(link, auth=None).status_code == 200
    response = api.post(link, auth=None, data={"decision": "correction", "statement": "I remained inside."})
    assert response.status_code == 200 and "Statement recorded" in response.text
    assert api.post(link, auth=None, data={"decision": "confirm", "statement": "Again"}).status_code == 410
    bundle = api.get(f"/visits/{visit.id}/bundle.json")
    assert len(bundle.json()["reviews"]) == 2
    assert bundle.json()["reviews"][1]["receipt"]["payload"]["actor"]["role"] == "worker"
    assert "append-only reviews verified" in api.post("/verify", data={"text": bundle.text}).text
    page = api.get(f"/visits/{visit.id}")
    assert page.status_code == 200 and "I remained inside." in page.text
    assert store.receipt_for_visit(visit.id).model_dump_json() == original


def test_setup_forms_discover_create_and_cancel_without_cli(api, store, ring_world, t0):
    assert api.get("/setup", auth=None).status_code == 401
    page = api.get("/setup?discover=true")
    assert page.status_code == 200 and "Backyard" in page.text
    camera = ring_world.cameras()[1]
    response = api.post(
        "/setup/sites", data={"name": "Second residence", "camera_id": camera.id, "sensor_id": ""}
    )
    assert response.status_code == 303
    site = next(s for s in store.sites() if s.name == "Second residence")
    assert (
        api.post("/setup/workers", data={"name": "Alex", "role": "cleaner", "agency": "Example"}).status_code
        == 303
    )
    worker = next(w for w in store.workers() if w.name == "Alex")
    response = api.post(
        "/setup/schedules",
        data={
            "site_id": site.id,
            "worker_id": worker.id,
            "window_start": t0.isoformat(),
            "window_end": (t0 + timedelta(hours=1)).isoformat(),
            "expected_minutes": "60",
            "service": "Cleaning",
        },
    )
    assert response.status_code == 303
    schedule = store.schedules_for_site(site.id)[0]
    assert api.post(f"/setup/schedules/{schedule.id}/cancel").status_code == 303
    assert store.schedule(schedule.id).status == "cancelled"
    page = api.get("/setup")
    assert "Second residence" in page.text and "Preserved, not deleted" in page.text


def test_replay_controls_are_disabled_in_wall_clock_runtime(api, t0):
    assert api.post("/api/replay/start", json={"at": t0.isoformat()}).status_code == 409
    assert api.post("/api/replay/advance", json={"at": t0.isoformat()}).status_code == 409


def test_declared_request_bodies_are_bounded(api):
    assert api.post("/api/workers", content=b"x" * (1024 * 1024 + 1)).status_code == 413
    body = b"x" * (256 * 1024 + 1)
    assert (
        api.post(
            "/webhooks/ring",
            content=body,
            headers={webhooks.SIGNATURE_HEADER: webhooks.sign(KEY, body)},
        ).status_code
        == 413
    )


def test_verify_input_is_bounded(api):
    oversized = "x" * (2 * 1024 * 1024)  # Starlette caps form fields at 1MB -> 400
    assert api.post("/verify", data={"text": oversized}).status_code == 400


def test_link_tokens_and_ids_have_bounded_length(api):
    assert api.get("/checkin/" + "a" * 200, auth=None).status_code == 422
    assert api.get("/review/" + "a" * 200, auth=None).status_code == 422
    assert api.get("/visits/" + "v" * 200).status_code == 422


def test_triage_endpoint_labels_its_source(api):
    r = api.post("/api/triage")
    assert r.status_code == 200
    data = r.json()
    assert data["source"] in ("strands-agent", "deterministic")
    assert data["brief"]


def test_dashboard_renders_triage_brief(api):
    dash = api.get("/")
    assert dash.status_code == 200
    assert "triage-brief" in dash.text
    assert "Run agent brief" in dash.text


def test_webhook_intake_meets_ring_deadline(api, household, t0):
    """Ring requires webhook ack within ~5s. The intake path (signature check +
    durable inbox enqueue + 202) must stay far under it under a burst."""
    import time

    cam = household[2]
    latencies = []
    for i in range(40):
        body = webhooks.encode(
            webhooks.build_event(
                event_type="motion_detected",
                device_id=cam.id,
                occurred_at=t0 + timedelta(minutes=i),
                sub_type="human",
            )
        )
        start = time.monotonic()
        r = api.post(
            "/webhooks/ring",
            content=body,
            headers={
                "Content-Type": "application/json",
                webhooks.SIGNATURE_HEADER: webhooks.sign(KEY, body),
            },
        )
        latencies.append(time.monotonic() - start)
        assert r.status_code == 202
    worst = max(latencies)
    assert worst < 2.0, f"slowest ack {worst:.2f}s — dangerously close to Ring's deadline"


def test_disconnect_endpoint_tombstones_and_blocks_ingest(api, store, household):
    site, _worker, cam, _sensor = household
    r = api.post(f"/api/sites/{site.id}/disconnect", json={"reason": "moved out"})
    assert r.status_code == 200
    assert r.json()["payload"]["record_type"] == "source_disconnected"
    assert store.site(site.id).disconnected_at is not None

    # second call is refused, not silently re-signed
    assert api.post(f"/api/sites/{site.id}/disconnect").status_code == 409

    # webhook from the bound device is still acked to the inbox but never binds
    from attest.models import utcnow

    body = webhooks.encode(
        webhooks.build_event(event_type="button_press", device_id=cam.id, occurred_at=utcnow())
    )
    assert (
        api.post(
            "/webhooks/ring",
            content=body,
            headers={
                "Content-Type": "application/json",
                webhooks.SIGNATURE_HEADER: webhooks.sign(KEY, body),
            },
        ).status_code
        == 202
    )
    api.post("/api/process-webhooks")
    assert store.visits(site_id=site.id) == []


def test_disconnect_unknown_site_404s(api):
    assert api.post("/api/sites/site_nope/disconnect").status_code == 404


def test_site_page_lists_coverage_attestations(api, household, t0):
    """The household-facing site page surfaces coverage certs with honest framing."""
    from datetime import timedelta

    site, _, cam, _ = household
    r = _post_hook(api, cam.id, "motion_detected", t0, "human")
    assert r.status_code == 202
    vid = api.attest_state.store.active_visit(site.id).id
    assert api.post(f"/api/visits/{vid}/close").status_code == 200
    cert = api.attest_state.engine.issue_coverage_attestation(
        site, t0 - timedelta(hours=1), t0 + timedelta(hours=2)
    )

    page = api.get(f"/sites/{site.id}")
    assert page.status_code == 200
    assert cert.id in page.text
    assert "Coverage" in page.text
    assert "never a claim of absence" in page.text
