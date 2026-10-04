"""The transparency log's live read API and CLI surface — the CT-style
endpoints (``/api/log/head``, ``/api/log/proof``, ``/api/log/consistency``),
``attest checkpoint`` / ``attest prove``, and the ``attest status``
transparency block. Pack-side verification is covered in test_transparency;
these tests pin the serving and operator surfaces."""

import json


def _seed(engine, store, site, n=3, tag="seed"):
    """``n`` chained content receipts via real signing + store writes."""
    out = []
    for i in range(n):
        prev = store.latest_receipt()
        r = engine.signer.issue(
            visit_id=f"coverage:{site.id}:{tag}-{i}",
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={"record_type": "coverage_attestation", "i": i},
        )
        store.put_receipt(r)
        out.append(r)
    return out


def test_log_head_serves_signed_head_and_boundary(
    engine, store, household, schedule, t0, settings, ring_client
):
    """``/api/log/head`` reports the live tree plus the latest checkpoint —
    and needs no admin token: hash paths and roots are verification
    material, not secrets."""
    from fastapi.testclient import TestClient

    from attest.app import create_app
    from attest.ledger import Signer

    _seed(engine, store, household[0])
    cp = engine.issue_log_checkpoint()
    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    with TestClient(app) as client:
        head = client.get("/api/log/head")
        assert head.status_code == 200
        body = head.json()
        size, root = engine.log_head()
        assert body["tree_size"] == size
        assert body["root_sha256"] == root.hex()
        assert body["checkpoint"]["id"] == cp.id
        # Checkpoints are not leaves — the tree holds only content receipts.
        content = [r for r in store.receipts() if r.payload.get("record_type") != "log_checkpoint"]
        assert body["tree_size"] == len(content)


def test_log_proof_serves_a_working_inclusion_path(
    engine, store, household, schedule, t0, settings, ring_client
):
    """``/api/log/proof/{id}`` returns an audit path that independently
    reaches the signed head — verified here with the same RFC 6962 math the
    pack verifiers port."""
    from fastapi.testclient import TestClient

    from attest.app import create_app
    from attest.ledger import Signer
    from attest.transparency import verify_inclusion

    receipts = _seed(engine, store, household[0])
    cp = engine.issue_log_checkpoint()
    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    with TestClient(app) as client:
        assert client.get("/api/log/proof/nope").status_code == 404
        # A checkpoint receipt is not a leaf — it can prove nothing under itself.
        assert client.get(f"/api/log/proof/{cp.id}").status_code == 409
        proof = client.get(f"/api/log/proof/{receipts[1].id}").json()
        assert proof["tree_size"] == cp.payload["tree_size"]
        assert verify_inclusion(
            bytes.fromhex(proof["leaf"]),
            proof["tree_size"],
            proof["leaf_index"],
            [bytes.fromhex(h) for h in proof["path"]],
            bytes.fromhex(cp.payload["root_sha256"]),
        )


def test_log_consistency_proves_extension(engine, store, household, schedule, t0, settings, ring_client):
    """``/api/log/consistency?first=N`` bridges two heads — the proof that
    nothing committed earlier was rewritten."""
    from fastapi.testclient import TestClient

    from attest.app import create_app
    from attest.ledger import Signer
    from attest.transparency import root as mth
    from attest.transparency import verify_consistency

    _seed(engine, store, household[0])
    first_cp = engine.issue_log_checkpoint()
    first_size = first_cp.payload["tree_size"]
    # Grow the log with a window that can't alias the seeded ones.
    _seed(engine, store, household[0], n=1, tag="grow")
    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    with TestClient(app) as client:
        assert client.get("/api/log/consistency", params={"first": 0}).status_code == 422
        assert client.get("/api/log/consistency", params={"first": 9999}).status_code == 404
        got = client.get("/api/log/consistency", params={"first": first_size}).json()
        assert got["first"] == first_size
        leaves = engine.log_leaves()
        assert verify_consistency(
            bytes.fromhex(first_cp.payload["root_sha256"]),
            first_size,
            mth(leaves),
            got["tree_size"],
            [bytes.fromhex(h) for h in got["proof"]],
        )


def test_cli_checkpoint_and_prove(tmp_path, monkeypatch, ring_world, ring_client, settings, t0):
    """``attest checkpoint`` signs a standalone head under the writer lock;
    ``attest prove`` prints one receipt's audit path — operator tools for
    the same proofs packs carry."""
    import argparse
    import contextlib
    import io

    import pytest
    from ring_sandbox.world import DeviceKind

    from attest import cli
    from attest.engine import VisitEngine
    from attest.ledger import Signer
    from attest.media import MediaStore
    from attest.models import Site
    from attest.store import Store
    from attest.summarize import TemplateSummarizer

    disk_store = Store(tmp_path / "attest.sqlite3")
    cam = next(d for d in ring_world.devices.values() if d.kind == DeviceKind.DOORBELL)
    site = disk_store.put_site(
        Site(name="Alvarez residence", ring_account_id=ring_world.account_id, door_camera_id=cam.id)
    )
    disk_engine = VisitEngine(
        disk_store,
        ring_client,
        Signer.ephemeral(),
        MediaStore(tmp_path / "media"),
        TemplateSummarizer("UTC"),
        settings,
    )
    prev = disk_store.latest_receipt()
    seeded = disk_engine.signer.issue(
        visit_id=f"coverage:{site.id}:cli-seed",
        sequence=prev.sequence + 1 if prev else 1,
        prev_hash=prev.payload_hash if prev else None,
        facts={"record_type": "coverage_attestation"},
    )
    disk_store.put_receipt(seeded)
    disk_store.close()

    monkeypatch.setattr(cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(cli.settings, "kms_key_id", None)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._checkpoint(argparse.Namespace(out=str(tmp_path / "cp.json")))
    assert "tree size" in buf.getvalue()
    doc = json.loads((tmp_path / "cp.json").read_text())
    assert doc["checkpoint"]["payload"]["record_type"] == "log_checkpoint"

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._prove(argparse.Namespace(receipt_id=seeded.id))
    proof = json.loads(buf.getvalue())
    assert proof["leaf"] == seeded.payload_hash
    assert proof["tree_size"] >= 1

    # Unknown ids exit non-zero rather than printing a bogus proof.
    with pytest.raises(SystemExit):
        with contextlib.redirect_stdout(io.StringIO()):
            cli._prove(argparse.Namespace(receipt_id="rcpt_missing"))


def test_status_reports_the_log_head(tmp_path, monkeypatch, ring_world, ring_client, settings, t0):
    """``attest status --json`` exposes the same tree commitment the API and
    checkpoints serve — the three surfaces must agree or an auditor sees
    two different logs."""
    import argparse
    import contextlib
    import io

    from ring_sandbox.world import DeviceKind

    from attest import cli
    from attest.engine import VisitEngine
    from attest.ledger import Signer
    from attest.media import MediaStore
    from attest.models import Site
    from attest.store import Store
    from attest.summarize import TemplateSummarizer

    store = Store(tmp_path / "attest.sqlite3")
    cam = next(d for d in ring_world.devices.values() if d.kind == DeviceKind.DOORBELL)
    site = store.put_site(
        Site(name="Alvarez residence", ring_account_id=ring_world.account_id, door_camera_id=cam.id)
    )
    engine = VisitEngine(
        store,
        ring_client,
        Signer.ephemeral(),
        MediaStore(tmp_path / "media"),
        TemplateSummarizer("UTC"),
        settings,
    )
    _seed(engine, store, site)
    cp = engine.issue_log_checkpoint()
    size, head = engine.log_head()
    store.close()

    monkeypatch.setattr(cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(cli.settings, "kms_key_id", None)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._status(argparse.Namespace(json=True))
    body = json.loads(buf.getvalue())
    assert body["transparency"]["tree_size"] == size
    assert body["transparency"]["root_sha256"] == head.hex()
    assert body["transparency"]["checkpoint_size"] == cp.payload["tree_size"]
    assert body["transparency"]["leaves_since_checkpoint"] == size - cp.payload["tree_size"]
