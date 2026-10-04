"""The transparency monitor — the auditor half of the log. A pinned signed
head is only a guarantee while someone watches it: these tests pin a real
deployment's head through the live API, then prove the monitor catches a
rewritten, regressed, or foreign-signed successor."""

import json
from datetime import timedelta

import pytest


def _seed(engine, site, t0, n=3):
    out = []
    for i in range(n):
        out.append(
            engine.issue_coverage_attestation(
                site, t0 - timedelta(hours=n + 1 - i), t0 - timedelta(hours=n - i)
            )
        )
    return out


def _doc_for(engine):
    return {"schema": "attest.issuer/1", "issuer_key": engine.signer.public_key_b64, "key_receipts": []}


def _head(engine, cp):
    size, root = engine.log_head()
    return {
        "tree_size": size,
        "root_sha256": root.hex(),
        "checkpoint": cp.model_dump(mode="json") if cp else None,
    }


def _consistency_fetch(engine):
    return lambda first: engine.consistency_proof(first)


def test_monitor_pins_then_verifies_extension(engine, store, household, schedule, t0):
    """First contact pins the signed head; after the log grows and a new
    checkpoint lands, the consistency proof bridges the two heads."""
    from attest import logmonitor

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    state, ok, lines = logmonitor.check(
        None, _doc_for(engine), _head(engine, cp1), _consistency_fetch(engine), "t1"
    )
    assert ok and "pinned" in lines[0]
    assert state["tree_size"] == cp1.payload["tree_size"]

    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    cp2 = engine.issue_log_checkpoint()
    state2, ok, lines = logmonitor.check(
        state, _doc_for(engine), _head(engine, cp2), _consistency_fetch(engine), "t2"
    )
    assert ok, lines
    assert "log extended" in lines[0]
    assert state2["tree_size"] == cp2.payload["tree_size"] > state["tree_size"]

    # Same head again — unchanged, not a failure.
    _, ok, lines = logmonitor.check(
        state2, _doc_for(engine), _head(engine, cp2), _consistency_fetch(engine), "t3"
    )
    assert ok and "unchanged" in lines[0]


def test_monitor_catches_a_rewritten_log(engine, store, household, schedule, t0):
    """The attack only the log catches: a receipt body edited mid-chain —
    every signature still verifies, but the new checkpoint can no longer
    bridge from the pinned head."""
    from attest import logmonitor

    receipts = _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    state, ok, _ = logmonitor.check(
        None, _doc_for(engine), _head(engine, cp1), _consistency_fetch(engine), "t1"
    )
    assert ok

    # Rewrite one stored receipt body — a leaf the tree already committed to.
    row = store._conn.execute("SELECT id, body FROM receipts WHERE id=?", (receipts[1].id,)).fetchone()
    forged = json.loads(row[1])
    forged["payload_hash"] = "f" * 64
    store._conn.execute("UPDATE receipts SET body=? WHERE id=?", (json.dumps(forged), row[0]))

    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    cp2 = engine.issue_log_checkpoint()
    _, ok, lines = logmonitor.check(
        state, _doc_for(engine), _head(engine, cp2), _consistency_fetch(engine), "t2"
    )
    assert not ok
    assert any("does not extend the pinned head" in line for line in lines)


def test_monitor_catches_a_regressed_head(engine, store, household, schedule, t0):
    """A signed head smaller than the pinned one can't be explained — the
    monitor flags it before even asking for a proof."""
    from attest import logmonitor

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    state, ok, _ = logmonitor.check(
        None, _doc_for(engine), _head(engine, cp1), _consistency_fetch(engine), "t1"
    )
    assert ok

    # The deployment answers the next poll with a signed checkpoint over a
    # smaller tree — signed under the same issuer, only the history differs.
    from attest.transparency import root as mth

    leaf = engine.signer.issue(
        visit_id="export:s:tiny", sequence=1, prev_hash=None, facts={"record_type": "case_export"}
    )
    small_root = mth([bytes.fromhex(leaf.payload_hash)])
    prev = store.latest_receipt()
    cp_small = engine.signer.issue(
        visit_id="log:1:small",
        sequence=prev.sequence + 1,
        prev_hash=prev.payload_hash,
        facts={"record_type": "log_checkpoint", "tree_size": 1, "root_sha256": small_root.hex()},
    )
    small_head = {
        "tree_size": 1,
        "root_sha256": small_root.hex(),
        "checkpoint": cp_small.model_dump(mode="json"),
    }
    _, ok, lines = logmonitor.check(state, _doc_for(engine), small_head, _consistency_fetch(engine), "t2")
    assert not ok
    assert any("regressed" in line for line in lines)


def test_monitor_flags_foreign_signer_and_unsigned_head(engine, store, household, schedule, t0):
    """A checkpoint outside the issuer lineage and a head with no checkpoint
    at all are both unwatchable — reported, never pinned."""
    from attest import logmonitor
    from attest.ledger import Signer

    _seed(engine, household[0], t0)
    foreign = Signer.ephemeral()
    prev = store.latest_receipt()
    bad_cp = foreign.issue(
        visit_id="log:99:ab12",
        sequence=prev.sequence + 1,
        prev_hash=prev.payload_hash,
        facts={"record_type": "log_checkpoint", "tree_size": 99, "root_sha256": "ab" * 32},
    )
    head = _head(engine, bad_cp)
    _, ok, lines = logmonitor.check(None, _doc_for(engine), head, _consistency_fetch(engine), "t1")
    assert not ok and any("outside the issuer" in line for line in lines)

    _, ok, lines = logmonitor.check(
        None, _doc_for(engine), _head(engine, None), _consistency_fetch(engine), "t1"
    )
    assert not ok and any("no signed checkpoint" in line for line in lines)


def test_monitor_fetch_layer_against_the_live_app(
    engine, store, household, schedule, t0, settings, ring_client
):
    """The HTTP path itself: a TestClient (a sync httpx.Client wired to the
    ASGI app) drives the real /api/log/* endpoints — the same bytes a
    remote auditor would see."""
    from fastapi.testclient import TestClient

    from attest import logmonitor
    from attest.app import create_app
    from attest.ledger import Signer

    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)
    client = TestClient(app)
    head = logmonitor.fetch_json("http://127.0.0.1/api/log/head", client=client)
    assert head["checkpoint"]["id"] == cp.id
    proof = logmonitor.fetch_json("http://127.0.0.1/api/log/consistency?first=1", client=client)
    assert proof["first"] == 1
    state, ok, lines = logmonitor.check(None, _doc_for(engine), head, lambda first: proof, "t1")
    assert ok and state["tree_size"] == cp.payload["tree_size"]


def test_monitor_state_roundtrip_and_cli_once(tmp_path, monkeypatch, capsys):
    """``attest monitor --once`` pins state on success and exits 1 on any
    check failure — the CI-gate contract."""
    import argparse
    import contextlib
    import io

    from attest import cli, logmonitor

    state_file = tmp_path / "mon.json"
    head = {"tree_size": 7, "root_sha256": "ab" * 32, "checkpoint": None}
    doc = {"schema": "attest.issuer/1", "issuer_key": "K" * 43, "key_receipts": []}

    monkeypatch.setattr(cli, "_fetch_issuer_doc", lambda url: doc)
    monkeypatch.setattr(logmonitor, "fetch_json", lambda url, client=None: head)

    # No checkpoint → nothing to pin → exit 1.
    with pytest.raises(SystemExit) as e:
        cli._monitor(
            argparse.Namespace(
                url="https://deploy.example",
                issuer=None,
                state=str(state_file),
                interval=60,
                once=True,
                json=False,
            )
        )
    assert e.value.code == 1
    assert not state_file.exists()

    # A signed checkpoint → pinned, state written, exit 0.
    cp = {
        "id": "rcpt_cp",
        "visit_id": "log:7:ab",
        "sequence": 7,
        "payload_hash": "cd" * 32,
        "signature": "s",
        "public_key": doc["issuer_key"],
        "payload": {"record_type": "log_checkpoint", "tree_size": 7, "root_sha256": "ab" * 32},
    }

    def fake_check(state, doc_, head_, fc, at):
        assert state is None or state["schema"] == logmonitor.STATE_SCHEMA
        return (
            {
                "schema": logmonitor.STATE_SCHEMA,
                "issuer_key": doc_["issuer_key"],
                "tree_size": 7,
                "root_sha256": "ab" * 32,
                "checkpoint_id": "rcpt_cp",
                "checked_at": at,
            },
            True,
            ["pinned checkpoint rcpt_cp…"],
        )

    monkeypatch.setattr(logmonitor, "check", fake_check)
    monkeypatch.setattr(
        logmonitor,
        "fetch_json",
        lambda url, client=None: {"tree_size": 7, "root_sha256": "ab" * 32, "checkpoint": cp},
    )
    buf = io.StringIO()
    with pytest.raises(SystemExit) as e:
        with contextlib.redirect_stdout(buf):
            cli._monitor(
                argparse.Namespace(
                    url="https://deploy.example",
                    issuer=None,
                    state=str(state_file),
                    interval=60,
                    once=True,
                    json=False,
                )
            )
    assert e.value.code == 0
    assert "pinned" in buf.getvalue()
    assert json.loads(state_file.read_text())["tree_size"] == 7
