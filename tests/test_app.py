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


def test_chaos_duplicated_deliveries_collapse_to_one_event(api, store, household, t0):
    """The emulator's chaos.duplicate sends the same signed delivery over and
    over — identical request_ids must collapse at intake, not into duplicate
    events. Ten deliveries, one visit, one evidence row."""
    body = webhooks.encode(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    headers = {
        "Content-Type": "application/json",
        webhooks.SIGNATURE_HEADER: webhooks.sign(KEY, body),
    }
    statuses = [api.post("/webhooks/ring", content=body, headers=headers).status_code for _ in range(10)]
    assert all(s == 202 for s in statuses)  # every copy acked — none silently dropped
    assert api.post("/api/process-webhooks").status_code == 200
    visit = store.active_visit(household[0].id)
    assert visit is not None
    device_events = [e for e in store.evidence_for(visit.id) if e.ring_request_id or e.kind == "doorbell"]
    assert len(device_events) == 1


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
    # The worker's own words render inside the agreement card, quoted, with a
    # jump link to the conclude form.
    assert 'class="dispute-quote"' in page.text and 'href="#coordinator-resolve"' in page.text
    assert store.receipt_for_visit(visit.id).model_dump_json() == original


def test_household_page_is_plain_language_and_honest(api, store, household, t0):
    """The household view renders the same facts without console jargon —
    observed activity, the worker's own words, and the honesty footer."""
    _post_hook(api, household[2].id, "button_press", t0)
    visit = store.active_visit(household[0].id)
    assert api.post(f"/api/visits/{visit.id}/close").status_code == 200
    link = api.post(f"/api/visits/{visit.id}/review-link").json()["path"]
    r = api.post(link, auth=None, data={"decision": "dispute", "statement": "I arrived earlier."})
    assert r.status_code == 200
    page = api.get(f"/visits/{visit.id}/household")
    assert page.status_code == 200
    assert "Activity was observed" in page.text
    assert "I arrived earlier." in page.text  # the worker's words, quoted
    assert "not proof nobody came" in page.text  # the claim boundary is always stated
    assert "not identity, attendance, or time worked" in page.text
    # coordinator jargon must not leak into the household view
    assert "payload_hash" not in page.text and "Ed25519" not in page.text


def test_brief_page_carries_anchors_and_boundary(api, store, household, t0):
    """The printable brief is the hand-to-a-mediator artifact: record state,
    source-by-source table, verbatim voices, signed anchors, verification
    steps — and never media bytes."""
    _post_hook(api, household[2].id, "button_press", t0)
    visit = store.active_visit(household[0].id)
    assert api.post(f"/api/visits/{visit.id}/close").status_code == 200
    link = api.post(f"/api/visits/{visit.id}/review-link").json()["path"]
    api.post(link, auth=None, data={"decision": "dispute", "statement": "I arrived earlier."})
    flink = api.post(f"/api/visits/{visit.id}/family-link").json()["path"]
    api.post(
        flink + "/statement",
        auth=None,
        data={"perception": "saw_someone", "statement": "I saw her at the door myself."},
    )
    page = api.get(f"/visits/{visit.id}/brief")
    assert page.status_code == 200
    assert "visit record brief" in page.text
    assert "disputes this record" in page.text
    assert "I arrived earlier." in page.text
    assert "I saw her at the door myself." in page.text  # the third voice travels
    assert "household account" in page.text
    assert "Payload hash" in page.text and "Issuer key" in page.text
    assert "verified" in page.text  # the chain check reports on the sheet
    assert "To verify independently" in page.text
    assert "not proof nobody came" in page.text  # the boundary prints too
    assert "bytes not included" in page.text.lower() or "media" not in page.text.lower()
    assert "window.print" in page.text
    # the brief is admin-side — it must not be reachable without auth
    assert api.get(f"/visits/{visit.id}/brief", auth=None).status_code == 401
    assert api.get("/visits/vis_missing/brief").status_code == 404


def test_liveview_sessions_journal_and_close(api, store, household):
    """A brokered WHEP session journals as human-attention evidence: opening
    POSTs the SDP offer to Ring and records the session URL; closing marks the
    row — the record says 'a stream was established', never 'someone watched'."""
    site = household[0]
    offer = b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=attest\r\nt=0 0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
    r = api.post(f"/api/sites/{site.id}/liveview", content=offer)
    assert r.status_code == 200
    body = r.json()
    assert body["sdp_answer"].startswith("v=")
    row = store.liveview_session(body["session_id"])
    assert row.site_id == site.id and row.device_id == site.door_camera_id
    assert row.session_url  # Ring's own session identity is on the record
    assert row.closed_at is None

    page = api.get(f"/sites/{site.id}")
    assert "Live view" in page.text and "never proves anyone watched" in page.text

    r2 = api.post(f"/api/sites/{site.id}/liveview/{row.id}/close")
    assert r2.status_code == 200 and r2.json()["closed_at"]
    assert store.liveview_session(row.id).closed_at is not None
    assert store.verify_journal()["intact"]  # put+close both journaled


def test_liveview_refuses_unknown_disconnected_and_bad_offer(api, store, household):
    """Live view ends with consent: a disconnected site can't open a session,
    and a malformed SDP offer is refused before any row is journaled."""
    site = household[0]
    assert api.post("/api/sites/site_nope/liveview", content=b"v=0").status_code == 409
    assert api.post(f"/api/sites/{site.id}/liveview", content=b"not an offer").status_code == 409
    assert api.post(f"/api/sites/{site.id}/liveview/{'lv_none'}/close").status_code == 409
    assert store.stats()["liveview_sessions"] == 0

    api.post(f"/api/sites/{site.id}/disconnect", json={"reason": "consent revoked"})
    r = api.post(
        f"/api/sites/{site.id}/liveview",
        content=b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=x\r\nt=0 0\r\n",
    )
    assert r.status_code == 409 and "disconnect" in r.json()["detail"].lower()


def test_liveview_ring_failure_returns_502_safely(api, store, household, monkeypatch):
    """Ring down mid-broker: the API answers a sanitized 502 and journals a
    'failed' row — the attempt is auditable, but it never claims a stream."""
    site = household[0]
    offer = b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=x\r\nt=0 0\r\n"

    def boom(*a, **k):
        raise httpx.ConnectError("stack internals should not leak")

    monkeypatch.setattr(api.attest_state.engine.ring, "whep_session", boom)
    r = api.post(f"/api/sites/{site.id}/liveview", content=offer)
    assert r.status_code == 502
    assert "stack internals" not in r.text
    assert store.stats()["liveview_sessions"] == 1
    failed = store.liveview_sessions(site.id)[0]
    assert failed.state == "failed" and failed.failure_reason == "Ring unreachable"
    assert not failed.session_url  # nothing was established — no identity to claim
    assert store.verify_journal()["intact"]

    monkeypatch.undo()
    row, _ = api.attest_state.engine.open_liveview(site.id, offer.decode())

    def boom_close(*a, **k):
        raise httpx.ConnectError("unreachable")

    monkeypatch.setattr(api.attest_state.engine.ring, "whep_close", boom_close)
    r2 = api.post(f"/api/sites/{site.id}/liveview/{row.id}/close")
    assert r2.status_code == 502
    # Close Ring-side failed — the row stays open rather than lying 'closed'.
    assert store.liveview_session(row.id).closed_at is None
    assert store.liveview_session(row.id).state == "open"


def test_link_qr_encodes_worker_paths_only(api):
    """The QR helper exists for the door-step scan — scoped to worker-link
    paths, not an open encoder."""
    r = api.get("/qr.svg", params={"target": "/checkin/" + "a" * 40})
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg")
    assert "<svg" in r.text
    assert api.get("/qr.svg", params={"target": "https://evil.example/"}).status_code == 400
    assert api.get("/qr.svg", params={"target": "/api/state"}).status_code == 400


def test_family_link_is_scoped_view_access(api, store, household, t0):
    """A scoped family link opens the household view without admin auth —
    multi-use until expiry, and the admin 'Full record' link stays hidden."""
    _post_hook(api, household[2].id, "button_press", t0)
    visit = store.active_visit(household[0].id)
    assert api.post(f"/api/visits/{visit.id}/close").status_code == 200

    # without a link the household page is admin-only
    assert api.get(f"/visits/{visit.id}/household", auth=None).status_code == 401

    issued = api.post(f"/api/visits/{visit.id}/family-link")
    assert issued.status_code == 200
    path = issued.json()["path"]
    assert path.startswith("/family/")

    page = api.get(path, auth=None)
    assert page.status_code == 200
    assert "Activity was observed" in page.text
    assert "not proof nobody came" in page.text  # the boundary travels with the view
    assert "Full record" not in page.text  # admin chrome stays hidden for link viewers
    assert api.get(path, auth=None).status_code == 200  # multi-use, not consumed

    # an unknown or revoked token lands on the styled dead-link page, never data
    dead = api.get("/family/" + "z" * 40, auth=None)
    assert dead.status_code == 404 and "invalid or expired" in dead.text

    # the QR helper encodes family paths too
    assert api.get("/qr.svg", params={"target": path}).status_code == 200


def test_family_statement_appends_the_households_voice(api, store, household, t0):
    """The family link is read+append: the household's account joins the signed
    chain verbatim as a third voice — without consuming the link, altering the
    worker/coordinator stance, or claiming to verify anyone's presence."""
    from attest.reviews import ReviewService, verify_bundle

    _post_hook(api, household[2].id, "button_press", t0)
    visit = store.active_visit(household[0].id)
    assert api.post(f"/api/visits/{visit.id}/close").status_code == 200
    path = api.post(f"/api/visits/{visit.id}/family-link").json()["path"]

    # the page offers the form only through the scoped link, with honest framing
    page = api.get(path, auth=None)
    assert 'name="perception"' in page.text and "/statement" in page.text
    assert "isn't proof on its own" in page.text
    admin_view = api.get(f"/visits/{visit.id}/household")
    assert admin_view.status_code == 200 and 'name="perception"' not in admin_view.text

    posted = api.post(
        f"{path}/statement",
        auth=None,
        data={"perception": "saw_someone", "statement": "I saw a courier at 10:15, not our aide."},
    )
    assert posted.status_code == 200
    assert "Your account was added to the signed record" in posted.text
    assert "I saw a courier at 10:15" in posted.text  # echoed back verbatim in the chain

    # multi-use: the link still opens after appending
    again = api.get(path, auth=None)
    assert again.status_code == 200 and "household's words" in again.text

    # the signed entry carries the honest actor metadata
    bundle = api.get(f"/visits/{visit.id}/bundle.json").json()
    entry = bundle["reviews"][-1]["receipt"]["payload"]
    assert entry["record_type"] == "review"
    assert entry["actor"]["role"] == "household"
    assert entry["actor"]["authentication"] == "family_link"
    assert entry["actor"]["identity_verified"] is False
    assert entry["review"]["kind"] == "household_account"
    assert entry["review"]["perception"] == "saw_someone"
    assert entry["independently_verified_attendance"] is False

    # a second statement appends a new revision — nothing is edited in place
    api.post(
        f"{path}/statement",
        auth=None,
        data={"perception": "unsure", "statement": "Actually it may have been later."},
    )
    bundle = api.get(f"/visits/{visit.id}/bundle.json").json()
    roles = [r["receipt"]["payload"]["actor"]["role"] for r in bundle["reviews"]]
    assert roles == ["household", "household"]
    assert bundle["reviews"][1]["revision"] == 2

    # the household voice never shifts the worker/coordinator derivation
    svc = ReviewService(store, api.attest_state.signer, api.attest_state.engine.clock)
    assert svc.countersign(visit.id)["state"] == "unrequested"
    assert verify_bundle(svc.bundle(visit.id), public_key=api.attest_state.signer.public_key_b64)[0]


def test_family_statement_rejects_bad_input_and_dead_tokens(api, store, household, t0):
    _post_hook(api, household[2].id, "button_press", t0)
    visit = store.active_visit(household[0].id)
    assert api.post(f"/api/visits/{visit.id}/close").status_code == 200
    path = api.post(f"/api/visits/{visit.id}/family-link").json()["path"]

    # missing fields / a smuggled extra field re-render the form with an error,
    # never a raw JSON 422 and never a partial append
    r = api.post(f"{path}/statement", auth=None, data={"statement": "no perception picked"})
    assert r.status_code == 200 and "needs both parts" in r.text
    r = api.post(
        f"{path}/statement",
        auth=None,
        data={"perception": "unsure", "statement": "x", "role": "coordinator"},
    )
    assert r.status_code == 200 and "needs both parts" in r.text
    bundle = api.get(f"/visits/{visit.id}/bundle.json").json()
    assert bundle["reviews"] == []

    # unknown token → styled dead link on both GET and POST
    dead = "z" * 40
    r = api.post(f"/family/{dead}/statement", auth=None, data={})
    assert r.status_code == 404 and "invalid or expired" in r.text

    # a worker-link token is not a family token — the grant tables stay separate
    worker_link = api.post(f"/api/visits/{visit.id}/review-link").json()["path"]
    worker_token = worker_link.rsplit("/", 1)[-1]
    r = api.post(
        f"/family/{worker_token}/statement",
        auth=None,
        data={"perception": "unsure", "statement": "x"},
    )
    assert r.status_code == 404 and "invalid or expired" in r.text

    # expired family link → dead link on GET and POST
    import hashlib
    from datetime import timedelta as _td

    from attest.models import utcnow

    token = path.rsplit("/", 1)[-1]
    grant = store.family_grant(hashlib.sha256(token.encode()).hexdigest())
    grant.expires_at = utcnow() - _td(seconds=1)
    store.put_family_grant(grant)
    assert api.get(path, auth=None).status_code == 404
    r = api.post(
        f"{path}/statement",
        auth=None,
        data={"perception": "unsure", "statement": "x"},
    )
    assert r.status_code == 404 and "invalid or expired" in r.text


def test_household_voice_coexists_with_worker_dispute(api, store, household, t0):
    """Three voices, one chain: worker dispute + household account + resolution
    all verify, and the derivation still reads worker/coordinator only."""
    from attest.reviews import ReviewService, verify_bundle

    _post_hook(api, household[2].id, "button_press", t0)
    visit = store.active_visit(household[0].id)
    assert api.post(f"/api/visits/{visit.id}/close").status_code == 200
    worker_link = api.post(f"/api/visits/{visit.id}/review-link").json()["path"]
    api.post(worker_link, auth=None, data={"decision": "dispute", "statement": "I was there."})
    family = api.post(f"/api/visits/{visit.id}/family-link").json()["path"]
    api.post(
        f"{family}/statement",
        auth=None,
        data={"perception": "no_one_seen", "statement": "Nobody knocked that morning."},
    )
    api.post(
        f"/api/visits/{visit.id}/resolve",
        json={"outcome": "inconclusive", "statement": "Accounts conflict; camera is inconclusive."},
    )

    svc = ReviewService(store, api.attest_state.signer, api.attest_state.engine.clock)
    bundle = svc.bundle(visit.id)
    assert verify_bundle(bundle, public_key=api.attest_state.signer.public_key_b64)[0]
    roles = [r.receipt.payload["actor"]["role"] for r in bundle.reviews]
    assert roles == ["worker", "household", "coordinator"]
    # derivation: household did not reopen or soften the worker's dispute; the
    # coordinator's resolution still owns the terminal state
    assert svc.countersign(visit.id)["state"] == "resolved"

    page = api.get(f"/visits/{visit.id}/household")
    assert "Nobody knocked that morning." in page.text
    assert "household account" in page.text
    coordinator = api.get(f"/visits/{visit.id}")
    assert "household account — no one seen" in coordinator.text


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


def test_integrity_page_renders_self_audit(api, household, t0):
    """/integrity surfaces the offline audit: chain, journal, custody, coverage."""
    site, _, cam, _ = household
    r = _post_hook(api, cam.id, "motion_detected", t0, "human")
    assert r.status_code == 202
    vid = api.attest_state.store.active_visit(site.id).id
    assert api.post(f"/api/visits/{vid}/close").status_code == 200

    page = api.get("/integrity")
    assert page.status_code == 200
    assert "Self-audit passes" in page.text
    assert "Receipt chain" in page.text and "chain intact" in page.text
    assert "Mutation journal" in page.text and "intact" in page.text
    assert "Signing key" in page.text and "local key file" in page.text
    assert "Watching evidence per site" in page.text
    assert "doesn't prove" in page.text  # the claims boundary stays on the page

    # Tamper out-of-band — the page must flip to attention, not stay green.
    store = api.attest_state.store
    store._conn.execute("UPDATE visits SET body=? WHERE id=?", ('{"forged":true}', vid))
    page = api.get("/integrity")
    assert "Attention" in page.text
    assert "content changed" in page.text


def test_verify_pack_rejects_smuggled_attestation(api, household, t0):
    """An attestations/*.json file the signed manifest does not list must fail
    _verify_pack — parity with the embedded verifier's sweep."""
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
    zin = zipfile.ZipFile(io.BytesIO(pack.content))
    att_name = next(n for n in zin.namelist() if n.startswith("attestations/"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
        for n in zin.namelist():
            zout.writestr(n, zin.read(n))
        zout.writestr("attestations/smuggled.json", zin.read(att_name))

    from attest.app import _verify_pack

    ok, detail = _verify_pack(buf.getvalue(), api.attest_state.signer.public_key_b64)
    assert not ok
    assert "not in the signed manifest" in detail


def test_status_survives_untracked_journal_rows(tmp_path, monkeypatch):
    """A store with rows written outside the journal used to crash `attest
    status` with TypeError — it must print the untracked count instead."""
    import argparse
    import contextlib
    import io as _io
    import sqlite3

    from attest import cli
    from attest.models import Role, Worker
    from attest.store import Store

    store = Store(tmp_path / "attest.sqlite3")
    store.put_worker(Worker(name="Maria Chen", role=Role.HOME_HEALTH_AIDE))
    store.close()
    # Out-of-band write — invisible to the mutation journal.
    conn = sqlite3.connect(tmp_path / "attest.sqlite3")
    conn.execute("INSERT INTO workers (id, checkin_token, body) VALUES ('wkr_oob', 'x', '{}')")
    conn.commit()
    conn.close()

    monkeypatch.setattr(cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(cli.settings, "kms_key_id", None)
    buf = _io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._status(argparse.Namespace())
    out = buf.getvalue()
    assert "untracked" in out
