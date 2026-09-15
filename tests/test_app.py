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
    assert api.post("/checkin/tok123", auth=None).status_code == 409


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
    assert api.post(claim_path, auth=None).status_code == 409
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
