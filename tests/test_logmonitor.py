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
    return lambda first, size: engine.consistency_proof(first, size)


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


def test_monitor_accepts_a_checkpoint_behind_the_live_tip(engine, store, household, schedule, t0):
    """The normal live-deployment state: content receipts land constantly
    but checkpoints only mint on export or `attest checkpoint`, so the
    newest SIGNED head almost always lags the tip. The monitor must bridge
    to the checkpoint's tree — a proof to the unsigned live head can never
    close on it."""
    from attest import logmonitor

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    state, ok, _ = logmonitor.check(
        None, _doc_for(engine), _head(engine, cp1), _consistency_fetch(engine), "t1"
    )
    assert ok

    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    # A legacy-shape checkpoint: signed head with NO embedded `extends`
    # bridge (pre-chaining issuance) — the monitor must fall back to the
    # served consistency proof, bounded at the checkpoint's tree.
    size, root = engine.log_head()
    cp2 = engine.signer.issue(
        visit_id=f"log:{size}:{root.hex()[:16]}",
        sequence=store.receipts()[-1].sequence + 1,
        prev_hash=store.receipts()[-1].payload_hash,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": size,
            "root_sha256": root.hex(),
        },
    )
    store.put_receipt(cp2)
    # One more content receipt lands AFTER the checkpoint — live tip runs
    # ahead of the newest signed head, the steady state of a real log.
    _seed(engine, household[0], t0 - timedelta(hours=6), n=1)
    live_head = _head(engine, cp2)  # tree_size = cp2.size + 1, checkpoint = cp2
    assert live_head["tree_size"] == cp2.payload["tree_size"] + 1
    state2, ok, lines = logmonitor.check(state, _doc_for(engine), live_head, _consistency_fetch(engine), "t2")
    assert ok, lines
    assert state2["tree_size"] == cp2.payload["tree_size"]
    assert any("log extended" in line and "consistency proof" in line for line in lines)


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
    # The checkpoint's own embedded bridge catches it first — the signed
    # `extends` cannot reach the pinned root over rewritten leaves.
    assert any("contradicts the pinned history" in line for line in lines)


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
    state, ok, lines = logmonitor.check(None, _doc_for(engine), head, lambda first, size: proof, "t1")
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


def test_live_check_proves_the_pack_log_is_the_served_one(engine, store, household, schedule, t0):
    """``live_check`` is the fork-killer: a pack's signed head verifies on its
    own, but only a consistency bridge to the deployment's CURRENT head proves
    the pack's log is the one still being served — a per-victim fork cannot
    produce that bridge."""
    from attest import logmonitor
    from attest.ledger import Signer

    trusted = {engine.signer.public_key_b64}
    _seed(engine, household[0], t0)
    pack_cp = engine.issue_log_checkpoint()

    # Same head — trivially the same log.
    verdict, line = logmonitor.live_check(
        pack_cp.model_dump(mode="json"), _head(engine, pack_cp), lambda a, b: None, trusted
    )
    assert verdict is True and "live head" in line

    # Live log extended past the pack's head — the bridge must close.
    _seed(engine, household[0], t0 - timedelta(hours=5), n=2)
    live_cp = engine.issue_log_checkpoint()
    verdict, line = logmonitor.live_check(
        pack_cp.model_dump(mode="json"), _head(engine, live_cp), _consistency_fetch(engine), trusted
    )
    assert verdict is True and "extends the pack's head" in line

    # A forked same-size head (valid signature, different history) fails closed.
    foreign = Signer.ephemeral().issue(
        visit_id="log:fork",
        sequence=99,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": pack_cp.payload["tree_size"],
            "root_sha256": "00" * 32,
        },
    )
    # Foreign signers never enter the check — fails at signature lineage.
    verdict, line = logmonitor.live_check(
        foreign.model_dump(mode="json"), _head(engine, live_cp), _consistency_fetch(engine), trusted
    )
    assert verdict is False
    # Same-size DIFFERENT root under the real key — the classic split-view fork.
    real_fork = engine.signer.issue(
        visit_id="log:fork2",
        sequence=100,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": pack_cp.payload["tree_size"],
            "root_sha256": "00" * 32,
        },
    )
    verdict, line = logmonitor.live_check(
        real_fork.model_dump(mode="json"),
        _head(engine, pack_cp),
        _consistency_fetch(engine),
        trusted,
    )
    assert verdict is False and "FORK" in line

    # Deployment serving no head — undecidable, never a pass.
    verdict, line = logmonitor.live_check(
        pack_cp.model_dump(mode="json"),
        {"tree_size": 5, "checkpoint": None},
        _consistency_fetch(engine),
        trusted,
    )
    assert verdict is None

    # Pack head postdates the live head — undecidable, honestly said.
    verdict, line = logmonitor.live_check(
        live_cp.model_dump(mode="json"), _head(engine, pack_cp), _consistency_fetch(engine), trusted
    )
    assert verdict is None and "postdates" in line


def test_verify_cross_checks_the_packs_head_against_the_live_log(
    engine, store, household, schedule, t0, tmp_path, monkeypatch, capsys
):
    """End-to-end: `attest verify pack.zip --issuer-url <url>` must not just
    pin the issuer — the pack's signed head is cross-checked against the
    deployment's live /api/log/head, so a per-victim forked log fails."""
    import argparse
    import contextlib
    import io
    import zipfile
    from io import BytesIO

    from attest import cli, logmonitor
    from attest.disputepack import build_case_pack, log_member
    from attest.reviews import ReviewService, countersign_status
    from tests.test_regressions import event

    # A real pack whose log_checkpoint.json commits to the engine's tree.
    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
        log_fn=lambda rs: log_member(engine, rs),
    )
    pack = tmp_path / "case.zip"
    pack.write_bytes(data)

    doc = _doc_for(engine)
    monkeypatch.setattr(cli, "_fetch_issuer_doc", lambda url: doc)

    def live_fetch(url, client=None):
        if url.endswith("/api/log/head"):
            size, root = engine.log_head()
            cps = [r for r in store.receipts() if r.payload.get("record_type") == "log_checkpoint"]
            return {
                "tree_size": size,
                "root_sha256": root.hex(),
                "checkpoint": cps[-1].model_dump(mode="json") if cps else None,
            }
        import urllib.parse as up

        q = up.parse_qs(up.urlsplit(url).query)
        return engine.consistency_proof(int(q["first"][0]), int(q["size"][0]))

    monkeypatch.setattr(logmonitor, "fetch_json", live_fetch)

    def run_verify():
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli._verify(
                argparse.Namespace(
                    bundle=str(pack),
                    key=None,
                    issuer_url="http://deploy.example",
                    json=True,
                    checkpoint=None,
                    against=None,
                )
            )
        return json.loads(buf.getvalue())

    # The pack's checkpoint IS the deployment's live head — same log proven.
    verdict = run_verify()
    assert verdict["ok"] is True
    assert verdict["live_log"]["same_log"] is True

    # Grow the real log, checkpoint again — the pack's older head must bridge.
    _seed(engine, site, t0 - timedelta(hours=5), n=2)
    engine.issue_log_checkpoint()
    verdict = run_verify()
    assert verdict["ok"] is True
    assert verdict["live_log"]["same_log"] is True

    # Now the live deployment serves a forked head — a VALIDLY SIGNED checkpoint
    # at the pack's tree size committing to a different root (the split-view
    # attack): verify must fail even though the pack itself is perfectly valid.
    with zipfile.ZipFile(BytesIO(data)) as z:
        pack_size = json.loads(z.read("log_checkpoint.json"))["checkpoint"]["payload"]["tree_size"]
    fork_cp = engine.signer.issue(
        visit_id="log:fork",
        sequence=1000,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": pack_size,
            "root_sha256": "00" * 32,
        },
    ).model_dump(mode="json")

    def forked_fetch(url, client=None):
        if url.endswith("/api/log/head"):
            return {"tree_size": pack_size, "root_sha256": "00" * 32, "checkpoint": fork_cp}
        return None

    monkeypatch.setattr(logmonitor, "fetch_json", forked_fetch)
    with pytest.raises(SystemExit) as exc:
        run_verify()
    assert exc.value.code == 1


def test_monitor_prefers_the_checkpoints_own_signed_bridge(engine, store, household, schedule, t0):
    """A checkpoint issued after the first carries its `extends` bridge in
    the SIGNED payload — the monitor verifies continuity from the signed
    material alone and never touches the consistency endpoint."""
    from attest import logmonitor

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    state, ok, _ = logmonitor.check(
        None, _doc_for(engine), _head(engine, cp1), _consistency_fetch(engine), "t1"
    )
    assert ok

    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    cp2 = engine.issue_log_checkpoint()
    assert "extends" in cp2.payload  # engine chained the heads at issuance

    def unreachable(first, size):
        raise AssertionError("the consistency endpoint must not be fetched")

    state2, ok, lines = logmonitor.check(state, _doc_for(engine), _head(engine, cp2), unreachable, "t2")
    assert ok, lines
    assert any("own signed bridge" in line for line in lines)
    assert state2["tree_size"] == cp2.payload["tree_size"]


def test_monitor_catches_a_self_contradicting_bridge(engine, store, household, schedule, t0):
    """A checkpoint whose embedded `extends` claims our pinned size but
    starts from a different root is a signed self-contradiction — the
    deployment's own material attests the fork. Caught without a fetch."""
    from attest import logmonitor

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    state, ok, _ = logmonitor.check(
        None, _doc_for(engine), _head(engine, cp1), _consistency_fetch(engine), "t1"
    )
    assert ok
    old_size = state["tree_size"]

    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    forged = engine.signer.issue(
        visit_id="log:forked-bridge",
        sequence=store.receipts()[-1].sequence + 1,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": engine.log_head()[0],
            "root_sha256": engine.log_head()[1].hex(),
            "extends": {
                "first": old_size,
                "first_root_sha256": "00" * 32,  # claims our size, not our root
                "checkpoint_id": "forged",
                "proof": [],
            },
        },
    )

    def unreachable(first, size):
        raise AssertionError("the consistency endpoint must not be fetched")

    _, ok, lines = logmonitor.check(state, _doc_for(engine), _head(engine, forged), unreachable, "t2")
    assert not ok
    assert any("extends" in line and "contradicts" in line for line in lines)


def test_live_check_fast_paths_on_the_embedded_bridge(engine, store, household, schedule, t0):
    """When the live checkpoint's own bridge names the pack's head, the
    cross-check closes from signed material alone — no proof fetch — and
    a bridge claiming our size from a foreign root is a hard fork."""
    from attest import logmonitor

    trusted = {engine.signer.public_key_b64}
    _seed(engine, household[0], t0)
    pack_cp = engine.issue_log_checkpoint()
    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    live_cp = engine.issue_log_checkpoint()
    assert live_cp.payload["extends"]["first"] == pack_cp.payload["tree_size"]

    def unreachable(first, size):
        raise AssertionError("the consistency endpoint must not be fetched")

    verdict, line = logmonitor.live_check(
        pack_cp.model_dump(mode="json"), _head(engine, live_cp), unreachable, trusted
    )
    assert verdict is True and "own signed bridge" in line
