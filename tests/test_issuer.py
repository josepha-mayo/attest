"""Issuer discovery — the attest.issuer/1 document and --issuer-url pinning.

/.well-known/attest-issuer.json publishes the deployment's issuer key plus
every signed key-lifecycle receipt, so a verifier can pin a pack to a
deployment it reached over HTTPS instead of copying a fingerprint out of
band. The document is public verification material — no admin auth — and
the key receipts inside are self-verifying chain members.
"""

import asyncio
import io
import json
import zipfile
from datetime import timedelta

import httpx
import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest import cli, ledger
from attest.disputepack import build_case_pack
from attest.ledger import Signer
from attest.reviews import ReviewService, countersign_status


@pytest.fixture
def api(settings, store, ring_client, household, schedule):
    """Admin-authed client over ASGI — same harness as test_app."""
    from attest.app import create_app

    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)

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

    with httpx.Client(transport=T(), base_url="http://t", follow_redirects=False) as c:
        c.auth = ("admin", settings.admin_token.get_secret_value())
        yield c
    app.state.inbox.close()


def _closed_visit(engine, household, t0, offset_min=0):
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0 + timedelta(minutes=offset_min),
        )
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    return visit


def _rotate(engine, new_signer=None):
    old_key = engine.signer.public_key_b64
    new_signer = new_signer or Signer.ephemeral()
    rotation = engine.issue_key_rotation(new_signer.public_key_b64, "")
    engine.signer = new_signer
    adoption = engine.issue_key_adoption(old_key, rotation)
    return old_key, new_signer, rotation, adoption


def test_issuer_endpoint_is_public_and_complete(api):
    """The well-known doc serves without auth — it's public crypto material —
    and carries the issuer key + key-lifecycle receipts."""
    doc = api.get("/.well-known/attest-issuer.json", auth=None).json()
    assert doc["schema"] == "attest.issuer/1"
    assert doc["issuer_key"]
    assert isinstance(doc["key_receipts"], list)
    assert "boundary" in doc

    api.post("/api/admin/rotate-key")
    doc2 = api.get("/.well-known/attest-issuer.json", auth=None).json()
    kinds = {r["payload"].get("record_type") for r in doc2["key_receipts"]}
    assert {"key_rotation", "key_adoption"} <= kinds
    assert doc2["issuer_key"] != doc["issuer_key"]  # issuer moved to the successor


def test_issuer_cli_writes_the_same_doc(tmp_path, monkeypatch):
    """`attest issuer --out` produces a byte-valid attest.issuer/1 document
    matching the endpoint's shape — no server needed."""
    from attest.config import Settings
    from attest.models import Site
    from attest.store import Store

    monkeypatch.setattr(
        cli, "settings", Settings(data_dir=tmp_path, admin_token="t" * 40, ring_webhook_key="k")
    )
    store = Store(tmp_path / "attest.sqlite3")
    store.put_site(Site(name="s", ring_account_id="a", door_camera_id="c"))
    store.close()
    cli.main(["rotate-key"])  # chain has one pivot
    cli.main(["issuer", "--out", str(tmp_path / "issuer.json")])
    doc = json.loads((tmp_path / "issuer.json").read_text())
    assert doc["schema"] == "attest.issuer/1"
    assert {r["payload"]["record_type"] for r in doc["key_receipts"]} == {
        "key_rotation",
        "key_adoption",
    }
    assert doc["chain_tip"]["sequence"] >= 2


def test_issuer_doc_extends_trust_to_pre_rotation_packs(engine, store, household, schedule, t0, tmp_path):
    """A pack exported BEFORE the rotation pins to the deployment's CURRENT
    issuer — the doc's signed key_receipts bridge the lineage."""
    from attest.app import _verify_case_pack

    v1 = _closed_visit(engine, household, t0)
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    entries = [(v1, service.bundle(v1.id), countersign_status(service.bundle(v1.id)))]
    pre_pack = build_case_pack(
        store,
        tmp_path / "media",
        site,
        entries,
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        issuer_key=engine.signer.public_key_b64,
    )
    old_key, new_signer, _, _ = _rotate(engine)

    # The pack self-declares the RETIRED issuer — the pre-rotation manifest.
    with zipfile.ZipFile(io.BytesIO(pre_pack)) as z:
        manifest = json.loads(z.read("manifest.json"))
    assert manifest["issuer_key"] == old_key

    # Pinning the deployment's current key alone fails: no pack-side link.
    with zipfile.ZipFile(io.BytesIO(pre_pack)) as z:
        ok, _ = _verify_case_pack(z, new_signer.public_key_b64)
    assert not ok

    # With the issuer doc's lifecycle receipts, the pinned current key walks
    # the signed rotation back to the pack's issuer — verified.
    doc = ledger.issuer_document(new_signer.public_key_b64, store.receipts())
    known = [ledger.Receipt.model_validate(r) for r in doc["key_receipts"]]
    with zipfile.ZipFile(io.BytesIO(pre_pack)) as z:
        ok, detail = _verify_case_pack(z, doc["issuer_key"], known_rotations=known)
    assert ok, detail


def test_issuer_url_rejects_plain_http_off_loopback():
    """--issuer-url over plain http to a remote host is refused — issuer
    authenticity must ride on HTTPS (loopback is fine for local packs)."""
    with pytest.raises(SystemExit, match="HTTPS"):
        cli._fetch_issuer_doc("http://example.com")
    with pytest.raises(SystemExit, match="HTTPS"):
        cli._fetch_issuer_doc("http://192.0.2.10:8080")


def test_issuer_doc_schema_enforced(tmp_path):
    """A file that isn't attest.issuer/1 fails closed."""
    bad = tmp_path / "not-issuer.json"
    bad.write_text('{"schema":"something-else"}')
    with pytest.raises(SystemExit, match="attest.issuer/1"):
        cli._fetch_issuer_doc(str(bad))


def test_issuer_doc_over_loopback_http(tmp_path, settings, store, ring_client, household, schedule):
    """End to end over a real socket: a live deployment's well-known endpoint
    is fetchable over plain HTTP *on loopback* — the remote-verifier path,
    not the file path."""
    import socket
    import threading
    import time
    from contextlib import contextmanager

    import uvicorn

    from attest.app import create_app

    @contextmanager
    def serve(app):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(32)
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
        thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server.started
            yield f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            sock.close()

    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    with serve(app) as base:
        doc = cli._fetch_issuer_doc(base)  # plain http, loopback — allowed
        assert doc["schema"] == "attest.issuer/1"
        assert doc["issuer_key"] == app.state.signer.public_key_b64
    app.state.inbox.close()


def test_embedded_verifier_issuer_flag_bridges_rotation(engine, store, household, schedule, t0, tmp_path):
    """`verify_case.py --issuer doc.json` — the pack's own embedded verifier,
    stdlib-only — pins a pre-rotation export to the deployment's CURRENT
    issuer the same way the server path does."""
    import subprocess
    import sys

    v1 = _closed_visit(engine, household, t0)
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    entries = [(v1, service.bundle(v1.id), countersign_status(service.bundle(v1.id)))]
    pack = build_case_pack(
        store,
        tmp_path / "media",
        site,
        entries,
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        issuer_key=engine.signer.public_key_b64,
    )
    _, new_signer, _, _ = _rotate(engine)
    doc = ledger.issuer_document(new_signer.public_key_b64, store.receipts())
    docfile = tmp_path / "issuer.json"
    docfile.write_text(json.dumps(doc))

    pack_dir = tmp_path / "pack"
    with zipfile.ZipFile(io.BytesIO(pack)) as z:
        z.extractall(pack_dir)
    proc = subprocess.run(
        [sys.executable, str(pack_dir / "verify_case.py"), str(pack_dir), "--issuer", str(docfile)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "pinned to the deployment" in proc.stdout
    # A forged doc naming an unrelated issuer must fail closed.
    bad = tmp_path / "bad-issuer.json"
    bad.write_text(
        json.dumps({"schema": "attest.issuer/1", "issuer_key": "A" * 43 + "=", "key_receipts": []})
    )
    proc = subprocess.run(
        [sys.executable, str(pack_dir / "verify_case.py"), str(pack_dir), "--issuer", str(bad)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "FAIL" in proc.stdout + proc.stderr


def test_issuer_file_roundtrip(tmp_path):
    """--issuer-url accepts a local doc file written by `attest issuer --out`."""
    vec = zipfile.ZipFile("tests/vectors/ok-rotated-case/pack.zip")
    manifest = json.loads(vec.read("manifest.json"))
    doc = {
        "schema": "attest.issuer/1",
        "issuer_key": manifest["issuer_key"],
        "key_receipts": [],
    }
    docfile = tmp_path / "issuer.json"
    docfile.write_text(json.dumps(doc))
    assert cli._fetch_issuer_doc(str(docfile))["issuer_key"] == manifest["issuer_key"]
