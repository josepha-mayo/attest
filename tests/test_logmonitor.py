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


def _witness_deployment():
    """A second Attest deployment acting as the cosigning witness — its own
    store and signer, completely independent of the issuer under test."""
    from attest.ledger import Signer
    from attest.store import Store

    return Store(":memory:"), Signer.ephemeral()


def test_witness_cosigns_only_extending_heads(engine, store, household, schedule, t0):
    """The witness pins each issuer's head and signs only what it can prove
    extends that pin — first contact pins + signs, a grown head bridges via
    its own embedded extends, a fork/regression is refused with the pin."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    doc = _doc_for(engine)

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp1.model_dump(mode="json")}
    )
    assert status == 200
    assert out["cosignature"]["payload"]["record_type"] == "witness_cosignature"
    assert out["cosignature"]["payload"]["subject_root_sha256"] == cp1.payload["root_sha256"]
    assert out["pinned"]["tree_size"] == cp1.payload["tree_size"]

    # The witness's own ledger carries the attestation — auditable.
    assert any(r.payload.get("record_type") == "witness_cosignature" for r in w_store.receipts())

    # Grown log: the new checkpoint's embedded extends closes the bridge —
    # no consistency document needed.
    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    cp2 = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp2.model_dump(mode="json")}
    )
    assert status == 200 and out["pinned"]["tree_size"] == cp2.payload["tree_size"]

    # A same-size different-root head is a fork — refused, pin intact.
    fork = engine.signer.issue(
        visit_id="log:witness-fork",
        sequence=999,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": cp2.payload["tree_size"],
            "root_sha256": "00" * 32,
        },
    )
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": fork.model_dump(mode="json")}
    )
    assert status == 409 and out["pinned"]["tree_size"] == cp2.payload["tree_size"]

    # A REGRESSED head is refused too.
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp1.model_dump(mode="json")}
    )
    assert status == 409

    # Malformed input never reaches the ledger.
    status, _ = logmonitor.witness_cosign(w_store, w_signer, {"issuer_doc": {}})
    assert status == 422
    assert len([r for r in w_store.receipts() if r.payload.get("record_type") == "witness_cosignature"]) == 2


def test_witness_bridges_a_multi_checkpoint_gap(engine, store, household, schedule, t0):
    """The witness pinned cp1; the requester's checkpoint is cp3 — the
    embedded extends only reaches cp2, so the exchange needs the retry
    with a served consistency proof from the pinned size."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    doc = _doc_for(engine)

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    status, _ = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp1.model_dump(mode="json")}
    )
    assert status == 200

    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    engine.issue_log_checkpoint()  # cp2 — the witness never sees it
    _seed(engine, household[0], t0 - timedelta(hours=6), n=1)
    cp3 = engine.issue_log_checkpoint()
    assert cp3.payload["extends"]["first"] != cp1.payload["tree_size"]  # gap exists

    # First attempt: the embedded bridge doesn't apply → 409 + the pin.
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp3.model_dump(mode="json")}
    )
    assert status == 409 and out["pinned"]["tree_size"] == cp1.payload["tree_size"]

    # Retry with the consistency proof from the pinned size — cosigned.
    status, out = logmonitor.witness_cosign(
        w_store,
        w_signer,
        {
            "issuer_doc": doc,
            "checkpoint": cp3.model_dump(mode="json"),
            "consistency": engine.consistency_proof(cp1.payload["tree_size"], cp3.payload["tree_size"]),
        },
    )
    assert status == 200


def test_check_cosignatures_counts_subject_bound_sigs(engine, store, household, schedule, t0):
    """Cosigns verify under their own signers' keys and only count when the
    subject binds THIS head — a cosig of another root, a wrong record type,
    or a foreign-signed entry is reported absent, never counted."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": _doc_for(engine), "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200
    cpj = cp.model_dump(mode="json")

    doc = {"checkpoint": cpj, "cosignatures": [out["cosignature"]]}
    n, keys = logmonitor.check_cosignatures(doc, cp.id, cp.payload["tree_size"], cp.payload["root_sha256"])
    assert n == 1 and keys == [w_signer.public_key_b64]

    # A cosig naming a different root is not a cosig of THIS head.
    other = dict(out["cosignature"])
    other["payload"] = dict(other["payload"], subject_root_sha256="00" * 32)
    n, _ = logmonitor.check_cosignatures(
        {"cosignatures": [other]}, cp.id, cp.payload["tree_size"], cp.payload["root_sha256"]
    )
    assert n == 0

    # A random receipt is not a cosig at all.
    n, _ = logmonitor.check_cosignatures(
        {"cosignatures": [cpj]}, cp.id, cp.payload["tree_size"], cp.payload["root_sha256"]
    )
    assert n == 0

    # Garbage entries don't taint the count — reported absent, not fatal.
    n, _ = logmonitor.check_cosignatures(
        {"cosignatures": [{"not": "a receipt"}, None, "x"]},
        cp.id,
        cp.payload["tree_size"],
        cp.payload["root_sha256"],
    )
    assert n == 0


def test_witness_heads_publishes_pinned_views(engine, store, household, schedule, t0):
    """witness_heads enumerates every issuer pin this deployment attested —
    the published viewpoint a third party compares against the issuer's
    own head. Malformed pin rows are dropped, not served."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": _doc_for(engine), "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200

    heads = logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    assert heads["schema"] == "attest.witness-heads/1"
    assert heads["witness_key"] == w_signer.public_key_b64
    assert len(heads["pins"]) == 1
    pin = heads["pins"][0]
    assert pin["tree_size"] == cp.payload["tree_size"]
    assert pin["root_sha256"] == cp.payload["root_sha256"]
    assert pin["checkpoint_id"] == cp.id
    assert pin["cosignature_id"] == out["cosignature"]["id"]

    # A corrupt pin row is dropped from the published view, not served raw.
    w_store.put_setting("witness:corrupt", {"schema": "bogus"})
    w_store.put_setting("other", {"schema": logmonitor.WITNESS_SCHEMA})
    heads = logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    assert len(heads["pins"]) == 1


def test_compare_views_agree_diverge_lag(engine, store, household, schedule, t0):
    """The cross-view verdict — but only on SIGNED views: the pin's unsigned
    fields are serving hints, the cosignature receipt is the attestation.
    Unsigned, wrongly-signed, or subject-mismatched views are 'unverifiable',
    never silently compared and never a fork accusation."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": _doc_for(engine), "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200
    heads = logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    pin = heads["pins"][0]
    wtrusted = {w_signer.public_key_b64}

    mine = {"tree_size": pin["tree_size"], "root_sha256": pin["root_sha256"]}
    verdict, line = logmonitor.compare_views(mine, pin, wtrusted)
    assert verdict == "agree" and "two independent observers" in line

    verdict, _ = logmonitor.compare_views(mine, None, wtrusted)
    assert verdict == "unseen"
    verdict, _ = logmonitor.compare_views(None, pin, wtrusted)
    assert verdict == "no_pin"

    # Unsigned views can't be believed — a pin without its receipt is
    # unverifiable, not comparable.
    bare = {k: v for k, v in pin.items() if k != "cosignature"}
    verdict, line = logmonitor.compare_views(mine, bare, wtrusted)
    assert verdict == "unverifiable" and "unsigned" in line

    # A cosig signed by a key outside the witness's lineage can't be
    # attributed to it — a verified attribution failure is 'dishonest'.
    verdict, _ = logmonitor.compare_views(mine, pin, {"some-other-key"})
    assert verdict == "dishonest"

    # A pin claiming a different size than the signed receipt attests is
    # tampered serving data — the receipt verifies, so the contradiction
    # is a served lie: 'dishonest', not a transient 'unverifiable'.
    lying = dict(pin, tree_size=pin["tree_size"] + 5)
    verdict, line = logmonitor.compare_views(mine, lying, wtrusted)
    assert verdict == "dishonest" and "disagree" in line

    # The real fork: a cosig VALIDLY signed by the witness attesting a
    # different root at the same size — the unforgeable divergence.
    w_store2, w_signer2 = _witness_deployment()
    # Mint a second witness cosig over a forged head at the same size.
    import hashlib

    prev = w_store2.latest_receipt()
    fork_root = hashlib.sha256(b"fork").hexdigest()
    cosig2 = w_signer2.issue(
        visit_id=f"witness:x:{cp.id}",
        sequence=prev.sequence + 1 if prev else 1,
        prev_hash=prev.payload_hash if prev else None,
        facts={
            "record_type": "witness_cosignature",
            "subject_checkpoint": cp.id,
            "subject_tree_size": pin["tree_size"],
            "subject_root_sha256": fork_root,
            "subject_issuer": pin["issuer_key"],
        },
    )
    fork_pin = dict(pin, root_sha256=fork_root, cosignature=cosig2.model_dump(mode="json"))
    verdict, line = logmonitor.compare_views(mine, fork_pin, {w_signer2.public_key_b64})
    assert verdict == "diverged" and "forked log" in line

    # A head the witness signed at a different size: honestly undecidable —
    # cadence lags growth, so lag is reported, never alarmed.
    behind_pin = dict(
        pin,
        tree_size=pin["tree_size"] - 1,
        cosignature=cosig2.model_dump(mode="json"),
    )
    verdict, _ = logmonitor.compare_views(mine, behind_pin, {w_signer2.public_key_b64})
    assert verdict == "dishonest"  # subject size disagrees with the claim

    smaller_cosig = w_signer2.issue(
        visit_id="witness:x:smaller",
        sequence=cosig2.sequence + 1,
        prev_hash=cosig2.payload_hash,
        facts={
            "record_type": "witness_cosignature",
            "subject_checkpoint": "rcpt_older",
            "subject_tree_size": pin["tree_size"] - 1,
            "subject_root_sha256": "00" * 32,
            "subject_issuer": pin["issuer_key"],
        },
    )
    behind = dict(
        pin,
        tree_size=pin["tree_size"] - 1,
        root_sha256="00" * 32,
        checkpoint_id="rcpt_older",
        cosignature=smaller_cosig.model_dump(mode="json"),
    )
    verdict, line = logmonitor.compare_views(mine, behind, {w_signer2.public_key_b64})
    assert verdict == "witness_behind" and "undecidable" in line

    ahead = dict(
        behind,
        tree_size=pin["tree_size"] + 3,
        checkpoint_id="rcpt_newer",
        cosignature=w_signer2.issue(
            visit_id="witness:x:newer",
            sequence=smaller_cosig.sequence + 1,
            prev_hash=smaller_cosig.payload_hash,
            facts={
                "record_type": "witness_cosignature",
                "subject_checkpoint": "rcpt_newer",
                "subject_tree_size": pin["tree_size"] + 3,
                "subject_root_sha256": "11" * 32,
                "subject_issuer": pin["issuer_key"],
            },
        ).model_dump(mode="json"),
    )
    ahead["root_sha256"] = "11" * 32
    verdict, line = logmonitor.compare_views(mine, ahead, {w_signer2.public_key_b64})
    assert verdict == "witness_ahead" and "undecidable" in line


def test_settings_by_prefix_reads_only_matching_rows(store):
    """The witness pin enumeration helper: prefix-scoped, dict-only,
    corrupt rows fail loudly like every other store read."""
    import pytest

    from attest.store import StoreCorrupt

    store.put_setting("witness:aaa", {"n": 1})
    store.put_setting("witness:bbb", {"n": 2})
    store.put_setting("witnessed:ccc", {"n": 3})  # prefix must not bleed
    store.put_setting("other", {"n": 4})
    got = store.settings_by_prefix("witness:")
    assert got == {"witness:aaa": {"n": 1}, "witness:bbb": {"n": 2}}

    # A non-dict row under the prefix fails loudly, never silently skipped.
    store._conn.execute("INSERT INTO settings (name, body) VALUES ('witness:bad', 'not json')")
    with pytest.raises(StoreCorrupt):
        store.settings_by_prefix("witness:")


def test_monitor_witness_cross_view_cli(tmp_path, monkeypatch, capsys):
    """`attest monitor --witness` compares the pinned head against the
    witness's published pins — and only believes SIGNED views: the witness's
    cosignature must verify under the witness's own issuer lineage before
    its (size, root) means anything."""
    import argparse
    import contextlib
    import io

    from attest import cli, logmonitor
    from attest.ledger import Signer

    state_file = tmp_path / "mon.json"
    cp = {
        "id": "rcpt_cp",
        "visit_id": "log:7:ab",
        "sequence": 7,
        "payload_hash": "cd" * 32,
        "signature": "s",
        "public_key": "K" * 43,
        "payload": {"record_type": "log_checkpoint", "tree_size": 7, "root_sha256": "ab" * 32},
    }
    doc = {"schema": "attest.issuer/1", "issuer_key": "K" * 43, "key_receipts": []}
    head = {"tree_size": 7, "root_sha256": "ab" * 32, "checkpoint": cp}
    w_signer = Signer.ephemeral()
    wdoc = {"schema": "attest.issuer/1", "issuer_key": w_signer.public_key_b64, "key_receipts": []}
    monkeypatch.setattr(cli, "_fetch_issuer_doc", lambda url: wdoc if "witness" in str(url) else doc)

    state = {
        "schema": logmonitor.STATE_SCHEMA,
        "issuer_key": doc["issuer_key"],
        "tree_size": 7,
        "root_sha256": "ab" * 32,
        "checkpoint_id": "rcpt_cp",
    }
    monkeypatch.setattr(logmonitor, "check", lambda *a, **k: (state, True, ["head unchanged"]))

    ns = argparse.Namespace(
        url="https://deploy.example",
        issuer=None,
        state=str(state_file),
        interval=60,
        once=True,
        json=False,
        witness="https://witness.example",
    )

    def cosig(tree_size=7, root="ab" * 32, cp_id="rcpt_cp"):
        r = w_signer.issue(
            visit_id=f"witness:x:{cp_id}:{tree_size}",
            sequence=1,
            prev_hash=None,
            facts={
                "record_type": "witness_cosignature",
                "subject_checkpoint": cp_id,
                "subject_tree_size": tree_size,
                "subject_root_sha256": root,
                "subject_issuer": doc["issuer_key"],
            },
        )
        return r.model_dump(mode="json")

    def pin(tree_size=7, root="ab" * 32, cp_id="rcpt_cp", with_cosig=True):
        p = {
            "issuer_key": doc["issuer_key"],
            "tree_size": tree_size,
            "root_sha256": root,
            "checkpoint_id": cp_id,
        }
        if with_cosig:
            p["cosignature"] = cosig(tree_size, root, cp_id)
        return p

    def run(heads):
        monkeypatch.setattr(
            logmonitor,
            "fetch_json",
            lambda url, client=None: heads if "witness" in url else head,
        )
        buf = io.StringIO()
        with pytest.raises(SystemExit) as e:
            with contextlib.redirect_stdout(buf):
                cli._monitor(ns)
        return e.value.code, buf.getvalue()

    # Same signed head attested by the witness → agree, exit 0.
    code, out = run({"pins": [pin()]})
    assert code == 0 and "[agree]" in out

    # Witness never cosigned this issuer → reported, still passes.
    code, out = run({"pins": []})
    assert code == 0 and "[unseen]" in out

    # An unsigned pin is serving data, not an attestation → unverifiable.
    code, out = run({"pins": [pin(with_cosig=False)]})
    assert code == 1 and "[unverifiable]" in out

    # A pin whose claim disagrees with its signed cosig → dishonest: the
    # receipt verifies, so the contradiction is the witness's own lie —
    # it freezes repins exactly like a divergence.
    lying = pin()
    lying["tree_size"] = 9
    code, out = run({"pins": [lying]})
    assert code == 1 and "[dishonest]" in out

    # Validly-signed fork attestation at the same size → diverged, exit 1.
    code, out = run({"pins": [pin(root="ff" * 32)]})
    assert code == 1 and "[diverged]" in out
    assert not state_file.exists() or logmonitor.state_load(state_file)["root_sha256"] == "ab" * 32

    # A malformed heads body fails the cycle honestly.
    code, out = run({"pins": "not-a-list"})
    assert code == 1 and "malformed" in out


def test_verify_witness_key_gates_on_named_witnesses(
    engine, store, household, schedule, t0, tmp_path, capsys
):
    """`attest verify pack.zip --witness-key K` is the sigsum-style named-
    witness policy: a cosig from ANY key is reported, but only a cosig from
    a REQUIRED key satisfies the gate — an issuer's own sock-puppet cosig
    cannot vouch for itself under a pinned witness."""
    import argparse
    import contextlib
    import io

    from attest import cli, logmonitor
    from attest.disputepack import build_case_pack, log_member
    from attest.ledger import Signer
    from attest.reviews import ReviewService, countersign_status
    from tests.test_regressions import event

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]

    w_store, w_signer = _witness_deployment()
    issuer_doc = _doc_for(engine)

    def log_with_cosig(rs):
        doc = log_member(engine, rs)
        status, out = logmonitor.witness_cosign(
            w_store, w_signer, {"issuer_doc": issuer_doc, "checkpoint": doc["checkpoint"]}
        )
        assert status == 200
        doc["cosignatures"] = [out["cosignature"]]
        return doc

    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
        log_fn=log_with_cosig,
    )
    pack = tmp_path / "case.zip"
    pack.write_bytes(data)

    def run(witness_keys):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli._verify(
                argparse.Namespace(
                    bundle=str(pack),
                    key=None,
                    issuer_url=None,
                    json=False,
                    checkpoint=None,
                    against=None,
                    witness_key=witness_keys,
                )
            )
        return buf.getvalue()

    # Named witness present → verified AND vouched.
    out = run([w_signer.public_key_b64])
    assert "vouched by required witness" in out

    # A different named key → the pack is valid but unvouched: hard fail.
    other = Signer.ephemeral().public_key_b64
    with pytest.raises(SystemExit) as e:
        run([other])
    assert "required witnesses insufficient" in str(e.value.code)

    # k-of-n: the named witness among several required keys still satisfies.
    out = run([other, w_signer.public_key_b64])
    assert "vouched by required witness" in out

    # No flag → the old behavior: reported, never gated.
    out = run(None)
    assert "cosigned by 1 witness" in out


def test_witness_cosign_serializes_concurrent_offers(engine, store, household, schedule, t0):
    """The pin-check → sign → repin section is one store transaction: parallel
    offers can't interleave into two signed divergent heads (the witness's
    whole reason to exist), and concurrent sequence allocation can't collide
    into an IntegrityError/500 — before the transaction wrap, both raced."""
    import concurrent.futures

    from attest import logmonitor
    from attest.ledger import Signer

    w_store, w_signer = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    body = {"issuer_doc": _doc_for(engine), "checkpoint": cp.model_dump(mode="json")}

    # The same head offered six ways concurrently: idempotent — one cosig.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(lambda _: logmonitor.witness_cosign(w_store, w_signer, body), range(6)))
    assert {s for s, _ in results} == {200}
    assert len({o["cosignature"]["id"] for _, o in results}) == 1
    assert len([r for r in w_store.receipts() if r.payload.get("record_type") == "witness_cosignature"]) == 1

    # Six FOREIGN issuers racing their first contact: independent pins,
    # unique sequences — a collision would have surfaced as a thread error.
    foreigners = []
    for i in range(6):
        fk = Signer.ephemeral()
        fk_cp = fk.issue(
            visit_id=f"log:fk{i}",
            sequence=1,
            prev_hash=None,
            facts={
                "record_type": "log_checkpoint",
                "tree_size": 3,
                "root_sha256": f"{i:02x}" * 32,
            },
        )
        foreigners.append((fk, fk_cp))

    def offer(fk_cp):
        fk, fcp = fk_cp
        fdoc = {"schema": "attest.issuer/1", "issuer_key": fk.public_key_b64, "key_receipts": []}
        return logmonitor.witness_cosign(
            w_store, w_signer, {"issuer_doc": fdoc, "checkpoint": fcp.model_dump(mode="json")}
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(offer, foreigners))
    assert {s for s, _ in results} == {200}
    seqs = [r.sequence for r in w_store.receipts()]
    assert len(seqs) == len(set(seqs))
    assert len(w_store.settings_by_prefix("witness:")) == 7


def test_witness_cosign_reissues_when_subject_diverges(engine, store, household, schedule, t0, monkeypatch):
    """Idempotent return binds THIS head: an issuer that re-signs the same
    checkpoint receipt id over DIFFERENT content can't make the witness
    repin a stored cosig attesting a different (size, root) — the mismatch
    issues a fresh attestation under a root-qualified pseudo instead."""
    import uuid as _uuid

    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    doc = _doc_for(engine)
    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    status, out1 = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp1.model_dump(mode="json")}
    )
    assert status == 200

    # The grown log's head honestly extends the pin — but the issuer ships a
    # checkpoint under cp1's receipt id (receipt ids are issuer-chosen):
    # same id, different signed content. Minted directly on the signer so it
    # never sits in the engine's own store.
    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    new_size, new_root = engine.log_head()
    cons = engine.consistency_proof(cp1.payload["tree_size"], new_size)
    monkeypatch.setattr(_uuid, "uuid4", lambda: _uuid.UUID(cp1.id[5:]))
    cp2 = engine.signer.issue(
        visit_id="log:twin-id",
        sequence=9999,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": new_size,
            "root_sha256": new_root.hex(),
            "extends": {
                "first": cp1.payload["tree_size"],
                "first_root_sha256": cp1.payload["root_sha256"],
                "checkpoint_id": cp1.id,
                "proof": cons["proof"],
            },
        },
    )
    assert cp2.id == cp1.id and cp2.payload["tree_size"] != cp1.payload["tree_size"]
    status, out2 = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp2.model_dump(mode="json")}
    )
    assert status == 200
    cosig = out2["cosignature"]
    # The returned attestation is about cp2's head, never cp1's stale one —
    # and both attestations survive independently on the ledger.
    assert cosig["payload"]["subject_tree_size"] == cp2.payload["tree_size"]
    assert cosig["payload"]["subject_root_sha256"] == cp2.payload["root_sha256"]
    assert cosig["id"] != out1["cosignature"]["id"]
    heads = logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    pin = next(p for p in heads["pins"] if p["issuer_key"] == doc["issuer_key"])
    assert pin["tree_size"] == cp2.payload["tree_size"]
    assert pin["cosignature_id"] == cosig["id"]


def test_witness_cosign_bounds_requester_key_pool(engine, store, household, schedule, t0):
    """The requester-supplied key_receipts pool feeds signature walks — an
    oversized pool is a CPU denial-of-service amplifier, so the endpoint
    refuses it before a single verification runs."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    doc = _doc_for(engine)
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()

    fat = dict(doc, key_receipts=[cp.model_dump(mode="json")] * 65)
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": fat, "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 422 and "bound" in out["error"]

    wrong_shape = dict(doc, key_receipts={"not": "a list"})
    status, _ = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": wrong_shape, "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 422

    # A sane lineage still passes — the bound is generous, not tight.
    status, _ = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200


def test_witness_cosign_refuses_corrupt_pin_fields(engine, store, household, schedule, t0):
    """A pin row with the right schema but unusable typed fields fails
    closed like every other corrupt store read — a crash is not a repin."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    doc = _doc_for(engine)
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()

    w_store.put_setting(
        f"witness:{doc['issuer_key']}",
        {
            "schema": logmonitor.WITNESS_SCHEMA,
            "issuer_key": doc["issuer_key"],
            "tree_size": "not-an-int",
            "root_sha256": "ab" * 32,
        },
    )
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc, "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 500 and "corrupt" in out["error"]


def test_check_cosignatures_counts_distinct_witnesses(engine, store, household, schedule, t0):
    """'cosigned by N' is a count of INDEPENDENT attestations: a pasted
    duplicate counts once, two cosigs from one signer count once, and a
    cosig from the issuer's own lineage is self-vouching — never a witness."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    w_store2, w_signer2 = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    doc_issuer = _doc_for(engine)
    status, out1 = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc_issuer, "checkpoint": cp.model_dump(mode="json")}
    )
    status, out2 = logmonitor.witness_cosign(
        w_store2, w_signer2, {"issuer_doc": doc_issuer, "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200
    cosig1, cosig2 = out1["cosignature"], out2["cosignature"]

    doc = {"checkpoint": cp.model_dump(mode="json"), "cosignatures": [cosig1, cosig2]}
    n, keys = logmonitor.check_cosignatures(doc, cp.id, cp.payload["tree_size"], cp.payload["root_sha256"])
    assert n == 2 and set(keys) == {w_signer.public_key_b64, w_signer2.public_key_b64}

    # The same cosig pasted twice still counts once.
    n, _ = logmonitor.check_cosignatures(
        {"checkpoint": cp.model_dump(mode="json"), "cosignatures": [cosig1, cosig1, cosig2]},
        cp.id,
        cp.payload["tree_size"],
        cp.payload["root_sha256"],
    )
    assert n == 2

    # A second, different cosig receipt from the SAME witness key counts once.
    dup = w_signer.issue(
        visit_id="witness:x:second-cosig",
        sequence=99,
        prev_hash=None,
        facts={
            "record_type": "witness_cosignature",
            "subject_checkpoint": cp.id,
            "subject_tree_size": cp.payload["tree_size"],
            "subject_root_sha256": cp.payload["root_sha256"],
            "subject_issuer": doc_issuer["issuer_key"],
        },
    )
    n, keys = logmonitor.check_cosignatures(
        {
            "checkpoint": cp.model_dump(mode="json"),
            "cosignatures": [cosig1, dup.model_dump(mode="json"), cosig2],
        },
        cp.id,
        cp.payload["tree_size"],
        cp.payload["root_sha256"],
    )
    assert n == 2 and w_signer.public_key_b64 in keys

    # Self-vouching: the issuer's own key countersigning its head is not a
    # witness — excluded even though the signature verifies.
    self_cosig = engine.signer.issue(
        visit_id="log:self-cosig",
        sequence=999,
        prev_hash=None,
        facts={
            "record_type": "witness_cosignature",
            "subject_checkpoint": cp.id,
            "subject_tree_size": cp.payload["tree_size"],
            "subject_root_sha256": cp.payload["root_sha256"],
            "subject_issuer": doc_issuer["issuer_key"],
        },
    )
    n, _ = logmonitor.check_cosignatures(
        {
            "checkpoint": cp.model_dump(mode="json"),
            "cosignatures": [self_cosig.model_dump(mode="json")],
        },
        cp.id,
        cp.payload["tree_size"],
        cp.payload["root_sha256"],
    )
    assert n == 0

    # A lineage-aware caller can exclude ANY issuer-lineage key, not just the
    # checkpoint's immediate signer — the sock-puppet rotated-key case.
    n, _ = logmonitor.check_cosignatures(
        {"checkpoint": cp.model_dump(mode="json"), "cosignatures": [cosig1]},
        cp.id,
        cp.payload["tree_size"],
        cp.payload["root_sha256"],
        issuer_keys={w_signer.public_key_b64},
    )
    assert n == 0


def test_cosign_at_survives_malformed_witness_responses():
    """A hostile or buggy witness can't crash the CLI path: a 409 without a
    usable pinned head, or a 200 without a real cosignature, is reported as
    refusal — never a traceback. A body's own 'status' key can't overwrite
    the real HTTP status either."""
    from attest import logmonitor

    class R:
        def __init__(self, status, doc):
            self.status_code = status
            self.content = json.dumps(doc).encode()

    class FakeClient:
        def __init__(self, responses):
            self.responses = iter(responses)

        def post(self, url, json=None, timeout=None):
            return R(*next(self.responses))

    def cosign(responses):
        orig = logmonitor.post_json
        logmonitor.post_json = lambda url, body: orig(url, body, client=FakeClient(responses))
        try:
            return logmonitor.cosign_at("http://w", {"issuer_key": "k"}, {"id": "rcpt_x"}, lambda f: None)
        finally:
            logmonitor.post_json = orig

    # A 409 carrying {"pinned": {}} — no tree_size — is a refusal, not a KeyError.
    cosig_out, line, _anchor = cosign([(409, {"pinned": {}})])
    assert cosig_out is None and "refused" in line

    # A 409 with pinned as a string — a refusal, not a TypeError.
    cosig_out, line, _anchor = cosign([(409, {"pinned": "bogus"})])
    assert cosig_out is None and "refused" in line

    # A 200 whose cosignature isn't a receipt — a refusal, not a KeyError.
    cosig_out, line, _anchor = cosign([(200, {"cosignature": {}})])
    assert cosig_out is None and "refused" in line and "malformed" in line

    # A body's "status" key can't overwrite the real HTTP status.
    cosig_out, line, _anchor = cosign([(409, {"status": 200, "pinned": {}})])
    assert cosig_out is None and "refused" in line


def test_post_json_body_status_cannot_clobber_http_status():
    """The transport verdict is authoritative: a response body carrying its
    own 'status' key never overrides the real HTTP status — kept as
    body_status so nothing is silently lost."""
    from attest import logmonitor

    class R:
        status_code = 409
        content = b'{"status": 200, "pinned": {"tree_size": 5}}'

    class FakeClient:
        def post(self, url, json=None, timeout=None):
            return R()

    out = logmonitor.post_json("http://w/api/witness/cosign", {}, client=FakeClient())
    assert out["status"] == 409
    assert out["body_status"] == 200
    assert out["pinned"]["tree_size"] == 5


def test_compare_views_rejects_wrong_issuer_pin(engine, store, household, schedule, t0):
    """A pin selected for the wrong issuer can never yield an honest verdict:
    the cosig's signed subject_issuer must name the issuer the monitor is
    tracking — else 'diverged' would accuse the wrong log."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": _doc_for(engine), "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200
    heads = logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    pin = heads["pins"][0]

    # My pin tracks a DIFFERENT issuer — the witness's cosig names the real
    # one, so the comparison refuses rather than accusing. A signed cosig
    # that doesn't attest the pin's claimed subject is a VERIFIED lie —
    # 'dishonest', not a transient 'unverifiable'.
    mine = {
        "issuer_key": "different-issuer-key",
        "tree_size": pin["tree_size"],
        "root_sha256": pin["root_sha256"],
    }
    verdict, _ = logmonitor.compare_views(mine, pin, {w_signer.public_key_b64})
    assert verdict == "dishonest"

    # Same pin, correct issuer → agree.
    mine["issuer_key"] = pin["issuer_key"]
    verdict, _ = logmonitor.compare_views(mine, pin, {w_signer.public_key_b64})
    assert verdict == "agree"


def test_monitor_repin_survives_witness_outage_but_not_divergence(tmp_path, monkeypatch, capsys):
    """Repin policy: a locally-verified new head persists even when the
    witness is unreachable or its view unverifiable — a downed witness can't
    freeze honest advancement. Only 'diverged' (someone may be on a fork)
    freezes the pin for a human."""
    import argparse
    import contextlib
    import io

    from attest import cli, logmonitor
    from attest.ledger import Signer

    state_file = tmp_path / "mon.json"
    doc = {"schema": "attest.issuer/1", "issuer_key": "K" * 43, "key_receipts": []}
    w_signer = Signer.ephemeral()
    wdoc = {"schema": "attest.issuer/1", "issuer_key": w_signer.public_key_b64, "key_receipts": []}
    monkeypatch.setattr(cli, "_fetch_issuer_doc", lambda url: wdoc if "witness" in str(url) else doc)

    grown = {
        "schema": logmonitor.STATE_SCHEMA,
        "issuer_key": doc["issuer_key"],
        "tree_size": 9,
        "root_sha256": "cd" * 32,
        "checkpoint_id": "rcpt_grown",
    }
    monkeypatch.setattr(logmonitor, "check", lambda *a, **k: (grown, True, ["log extended"]))
    head = {"tree_size": 9, "root_sha256": "cd" * 32, "checkpoint": {"id": "rcpt_grown"}}

    ns = argparse.Namespace(
        url="https://deploy.example",
        issuer=None,
        state=str(state_file),
        interval=60,
        once=True,
        json=False,
        witness="https://witness.example",
    )

    def run(heads_or_exc):
        if isinstance(heads_or_exc, Exception):

            def fetch(url, client=None):
                if "witness" in url:
                    raise heads_or_exc
                return head

            monkeypatch.setattr(logmonitor, "fetch_json", fetch)
        else:
            monkeypatch.setattr(
                logmonitor,
                "fetch_json",
                lambda url, client=None: heads_or_exc if "witness" in url else head,
            )
        buf = io.StringIO()
        with pytest.raises(SystemExit) as e:
            with contextlib.redirect_stdout(buf):
                cli._monitor(ns)
        return e.value.code, buf.getvalue()

    # Witness unreachable: the cycle reports failure BUT the locally-verified
    # head still repins — availability of a third party can't stall the pin.
    code, out = run(ValueError("connection refused"))
    assert code == 1 and "unreachable" in out
    assert state_file.exists() and logmonitor.state_load(state_file)["tree_size"] == 9

    # Divergence: validly-signed different root at the same size — the pin
    # stays frozen; a human must reconcile which observer saw the fork.
    divergent_cosig = w_signer.issue(
        visit_id="witness:x:div",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "witness_cosignature",
            "subject_checkpoint": "rcpt_grown",
            "subject_tree_size": 9,
            "subject_root_sha256": "ff" * 32,
            "subject_issuer": doc["issuer_key"],
        },
    )
    pin = {
        "issuer_key": doc["issuer_key"],
        "tree_size": 9,
        "root_sha256": "ff" * 32,
        "checkpoint_id": "rcpt_grown",
        "cosignature": divergent_cosig.model_dump(mode="json"),
    }
    state_file.unlink()
    code, out = run({"pins": [pin]})
    assert code == 1 and "[diverged]" in out
    assert not state_file.exists()  # never repinned onto the possibly-forked head


def test_verify_witness_url_resolves_deployments_and_threshold(
    engine, store, household, schedule, t0, tmp_path, capsys, monkeypatch
):
    """--witness-url names DEPLOYMENTS, not raw keys: the witness's own issuer
    document resolves its certified lineage, so 'vouched by https://w.example'
    survives the witness's key rotations. --witness-threshold makes it k-of-n —
    one cooperating witness can't satisfy a two-witness policy alone."""
    import argparse
    import contextlib
    import io

    from attest import cli, logmonitor
    from attest.disputepack import build_case_pack, log_member
    from attest.reviews import ReviewService, countersign_status
    from tests.test_regressions import event

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]

    w1_store, w1_signer = _witness_deployment()
    w2_store, w2_signer = _witness_deployment()
    issuer_doc = _doc_for(engine)

    def log_with_cosigs(rs):
        doc = log_member(engine, rs)
        doc["cosignatures"] = []
        for w_store, w_signer in ((w1_store, w1_signer), (w2_store, w2_signer)):
            status, out = logmonitor.witness_cosign(
                w_store, w_signer, {"issuer_doc": issuer_doc, "checkpoint": doc["checkpoint"]}
            )
            assert status == 200
            doc["cosignatures"].append(out["cosignature"])
        return doc

    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
        log_fn=log_with_cosigs,
    )
    pack = tmp_path / "case.zip"
    pack.write_bytes(data)

    w1_doc = {
        "schema": "attest.issuer/1",
        "issuer_key": w1_signer.public_key_b64,
        "key_receipts": [],
    }
    w2_doc = {
        "schema": "attest.issuer/1",
        "issuer_key": w2_signer.public_key_b64,
        "key_receipts": [],
    }
    monkeypatch.setattr(
        cli,
        "_fetch_issuer_doc",
        lambda url: {"https://w1.example": w1_doc, "https://w2.example": w2_doc}[str(url)],
    )

    def run(witness_urls, threshold=1):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli._verify(
                argparse.Namespace(
                    bundle=str(pack),
                    key=None,
                    issuer_url=None,
                    json=False,
                    checkpoint=None,
                    against=None,
                    witness_key=None,
                    witness_url=witness_urls,
                    witness_threshold=threshold,
                )
            )
        return buf.getvalue()

    # A named deployment vouches — reported by host, not an opaque key prefix.
    out = run(["https://w1.example"])
    assert "vouched by required witness w1.example" in out

    # k-of-n: two named witnesses, threshold 2 — both cosigs present, passes.
    out = run(["https://w1.example", "https://w2.example"], threshold=2)
    assert "vouched by 2 required witnesses" in out

    # One witness missing from the named set fails the threshold.
    only_w1 = tmp_path / "case-w1.zip"
    data1 = build_case_pack(
        store,
        tmp_path / "media2",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
        log_fn=lambda rs: {
            **log_member(engine, rs),
            "cosignatures": [
                logmonitor.witness_cosign(
                    w1_store,
                    w1_signer,
                    {"issuer_doc": issuer_doc, "checkpoint": log_member(engine, rs)["checkpoint"]},
                )[1]["cosignature"]
            ],
        },
    )
    only_w1.write_bytes(data1)
    with pytest.raises(SystemExit) as e:
        with contextlib.redirect_stdout(io.StringIO()):
            cli._verify(
                argparse.Namespace(
                    bundle=str(only_w1),
                    key=None,
                    issuer_url=None,
                    json=False,
                    checkpoint=None,
                    against=None,
                    witness_key=None,
                    witness_url=["https://w1.example", "https://w2.example"],
                    witness_threshold=2,
                )
            )
    assert "1 distinct witness(es) of 2 required" in str(e.value.code)


def test_witness_heads_anchor_attestations_in_the_witness_log(engine, store, household, schedule, t0):
    """Each published pin can carry the WITNESS's own log anchor: the cosig is
    a leaf in the witness's tree, and a covering checkpoint + inclusion proof
    makes 'the witness attested this' publicly anchored — the witness can't
    double-speak across auditors without forking its own log too. An anchor
    present but not verifying is served falsehood, so unverifiable."""
    from attest import logmonitor
    from attest.transparency import leaf_hashes, root

    w_store, w_signer = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": _doc_for(engine), "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200

    heads = logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    heads = logmonitor.anchor_published_pins(w_store, heads)
    # The witness hasn't checkpointed its own log yet — no anchor is claimed.
    assert "witness_anchor" not in heads["pins"][0]

    # The witness checkpoints its own ledger — the cosig becomes anchored.
    leaves = leaf_hashes(w_store.receipts())
    w_cp = w_signer.issue(
        visit_id="log:wcp",
        sequence=99,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": len(leaves),
            "root_sha256": root(leaves).hex(),
        },
    )
    w_store.put_receipt(w_cp)
    heads = logmonitor.anchor_published_pins(w_store, heads)
    pin = heads["pins"][0]
    anchor = pin["witness_anchor"]
    assert anchor["checkpoint"]["id"] == w_cp.id
    assert anchor["proof"]["leaf"] == out["cosignature"]["payload_hash"]

    # The cross-view verifies the anchor under the witness lineage and
    # reports the attestation as publicly anchored.
    issuer = _doc_for(engine)["issuer_key"]
    mine = {
        "issuer_key": issuer,
        "tree_size": cp.payload["tree_size"],
        "root_sha256": cp.payload["root_sha256"],
    }
    verdict, line = logmonitor.compare_views(mine, pin, {w_signer.public_key_b64})
    assert verdict == "agree" and "publicly anchored" in line

    # A tampered anchor is a served falsehood — 'dishonest', not ignored:
    # the anchor claims inclusion the math can't prove.
    forged = dict(pin)
    forged["witness_anchor"] = {
        **anchor,
        "proof": {**anchor["proof"], "leaf_index": 99},
    }
    verdict, _ = logmonitor.compare_views(mine, forged, {w_signer.public_key_b64})
    assert verdict == "dishonest"


def test_verify_threshold_counts_witness_identities_not_lineage_keys(
    engine, store, household, schedule, t0, tmp_path, capsys, monkeypatch
):
    """A rotated witness is ONE witness for k-of-n: its two lineage keys both
    resolve to the same deployment name, so cosigs minted under old AND new
    keys still count once — the gate can't be satisfied by one cooperating
    witness alone (audit: the gate counted signer KEYS)."""
    import argparse
    import contextlib
    import io

    from attest import cli, logmonitor
    from attest.disputepack import build_case_pack, log_member
    from attest.ledger import Signer
    from attest.reviews import ReviewService, countersign_status
    from tests.test_regressions import event

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]

    # A rotated witness: consented rotation pair makes both keys lineage.
    w_store, w_old = _witness_deployment()
    w_new = Signer.ephemeral()
    rot = w_old.issue(
        visit_id="key:rot",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "key_rotation",
            "previous_key": w_old.public_key_b64,
            "new_key": w_new.public_key_b64,
        },
    )
    adop = w_new.issue(
        visit_id="key:adopt",
        sequence=2,
        prev_hash=rot.payload_hash,
        facts={
            "record_type": "key_adoption",
            "previous_key": w_old.public_key_b64,
            "rotation_receipt": {"id": rot.id, "hash": rot.payload_hash},
        },
    )
    w_doc = {
        "schema": "attest.issuer/1",
        "issuer_key": w_new.public_key_b64,
        "key_receipts": [rot.model_dump(mode="json"), adop.model_dump(mode="json")],
    }
    assert logmonitor._trusted_set(w_doc) == {w_old.public_key_b64, w_new.public_key_b64}

    def log_with_cosigs(rs):
        doc = log_member(engine, rs)
        cpd = doc["checkpoint"]  # the head that actually ships in this pack
        facts = {
            "record_type": "witness_cosignature",
            "subject_checkpoint": cpd["id"],
            "subject_tree_size": cpd["payload"]["tree_size"],
            "subject_root_sha256": cpd["payload"]["root_sha256"],
            "subject_issuer": engine.signer.public_key_b64,
        }
        # One cooperating witness, two signatures — one under each lineage key.
        c_old = w_old.issue(visit_id="wit:o", sequence=3, prev_hash=adop.payload_hash, facts=facts)
        c_new = w_new.issue(visit_id="wit:n", sequence=4, prev_hash=c_old.payload_hash, facts=facts)
        doc["cosignatures"] = [c_old.model_dump(mode="json"), c_new.model_dump(mode="json")]
        return doc

    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
        log_fn=log_with_cosigs,
    )
    pack = tmp_path / "case.zip"
    pack.write_bytes(data)

    monkeypatch.setattr(cli, "_fetch_issuer_doc", lambda url: w_doc)

    def run(threshold):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli._verify(
                argparse.Namespace(
                    bundle=str(pack),
                    key=None,
                    issuer_url=None,
                    json=False,
                    checkpoint=None,
                    against=None,
                    witness_key=None,
                    witness_url=["https://w1.example"],
                    witness_threshold=threshold,
                )
            )
        return buf.getvalue()

    # Two cosigs, but ONE witness — threshold 1 passes, threshold 2 must not.
    assert "vouched by required witness w1.example" in run(1)
    with pytest.raises(SystemExit) as e:
        with contextlib.redirect_stdout(io.StringIO()):
            cli._verify(
                argparse.Namespace(
                    bundle=str(pack),
                    key=None,
                    issuer_url=None,
                    json=False,
                    checkpoint=None,
                    against=None,
                    witness_key=None,
                    witness_url=["https://w1.example"],
                    witness_threshold=2,
                )
            )
    assert "1 distinct witness(es) of 2 required" in str(e.value.code)


def test_monitor_survives_malformed_consistency_proof(engine, store, household, schedule, t0):
    """A hostile deployment can serve non-integer first/tree_size in its
    consistency response — int() used to raise outside the guard and crash
    the monitor, stalling fork-detection until restart (audit)."""
    from attest import logmonitor

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    state, ok, _ = logmonitor.check(
        None, _doc_for(engine), _head(engine, cp1), _consistency_fetch(engine), "t1"
    )
    assert ok

    _seed(engine, household[0], t0 - timedelta(hours=6), n=2)
    size, root = engine.log_head()
    cp2 = engine.signer.issue(  # legacy shape: no embedded extends → fetch path
        visit_id=f"log:{size}:{root.hex()[:16]}",
        sequence=store.receipts()[-1].sequence + 1,
        prev_hash=store.receipts()[-1].payload_hash,
        facts={"record_type": "log_checkpoint", "tree_size": size, "root_sha256": root.hex()},
    )
    store.put_receipt(cp2)

    def bad_fetch(first, size):
        return {"first": "abc", "tree_size": "zzz", "proof": []}

    state2, ok2, lines = logmonitor.check(state, _doc_for(engine), _head(engine, cp2), bad_fetch, "t2")
    assert not ok2 and state2 is None
    assert any("different tree sizes" in line for line in lines)


def test_check_cosignatures_binds_subject_issuer(engine, store, household, schedule, t0):
    """A cosig attesting THIS head but naming a DIFFERENT issuer must not
    count — compare_views already enforces the binding; the counting path
    now matches (audit)."""
    from attest import logmonitor

    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    w_store, w_signer = _witness_deployment()
    issuer_doc = _doc_for(engine)
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": issuer_doc, "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200

    doc = {"checkpoint": cp.model_dump(mode="json"), "cosignatures": [out["cosignature"]]}
    lineage = {engine.signer.public_key_b64}
    n, signers = logmonitor.check_cosignatures(
        doc, cp.id, cp.payload["tree_size"], cp.payload["root_sha256"], issuer_keys=lineage
    )
    assert n == 1 and signers == [w_signer.public_key_b64]

    # Same cosig, foreign subject_issuer — valid signature, wrong context.
    foreign = dict(out["cosignature"])
    foreign["payload"] = dict(foreign["payload"], subject_issuer="AAAA" + "A" * 40)
    doc2 = {"checkpoint": cp.model_dump(mode="json"), "cosignatures": [foreign]}
    n2, signers2 = logmonitor.check_cosignatures(
        doc2, cp.id, cp.payload["tree_size"], cp.payload["root_sha256"], issuer_keys=lineage
    )
    assert n2 == 0 and signers2 == []


def test_compare_views_binds_anchor_to_the_watched_witness_log(engine, store, household, schedule, t0):
    """A served witness_anchor verified in isolation is only as strong as
    the tree it names — a witness minting per-victim anchor checkpoints
    would pass. Bound to the monitor's own pin of the witness log, the
    anchor must provably reconcile with the watched head (audit)."""
    from attest import logmonitor
    from attest.transparency import leaf_hashes, root

    w_store, w_signer = _witness_deployment()
    # One content leaf before the cosig so the 'pin behind the anchor'
    # case has a real non-empty prefix to bridge from.
    w_store.put_receipt(
        w_signer.issue(visit_id="w:seed", sequence=1, prev_hash=None, facts={"record_type": "note"})
    )
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    issuer_doc = _doc_for(engine)
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": issuer_doc, "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200

    # The witness checkpoints its own ledger (anchor time).
    leaves = leaf_hashes(w_store.receipts())
    w_cp = w_signer.issue(
        visit_id="log:anchor",
        sequence=99,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": len(leaves),
            "root_sha256": root(leaves).hex(),
        },
    )
    w_store.put_receipt(w_cp)
    heads = logmonitor.anchor_published_pins(
        w_store, logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    )
    pin = heads["pins"][0]
    wpin = {"tree_size": len(leaves), "root_sha256": root(leaves).hex()}

    issuer = issuer_doc["issuer_key"]
    mine = {
        "issuer_key": issuer,
        "tree_size": cp.payload["tree_size"],
        "root_sha256": cp.payload["root_sha256"],
    }
    verdict, line = logmonitor.compare_views(mine, pin, {w_signer.public_key_b64}, witness_pin=wpin)
    assert verdict == "agree" and "verified against our own pin" in line

    # A witness pinning a DIFFERENT log than the anchor names — fork caught.
    # The anchor is witness-signed and self-contradicting: 'dishonest',
    # not a transient 'unverifiable' — the monitor freezes repins on it.
    other = {"tree_size": len(leaves), "root_sha256": "00" * 32}
    verdict2, line2 = logmonitor.compare_views(mine, pin, {w_signer.public_key_b64}, witness_pin=other)
    assert verdict2 == "dishonest" and "reconciled" in line2

    # Our pin BEHIND the anchor — a real earlier head the anchor provably
    # extends: the served consistency proof bridges prefix → anchor.
    from attest.transparency import consistency_nodes

    behind = {
        "tree_size": len(leaves) - 1,
        "root_sha256": root(leaves[: len(leaves) - 1]).hex(),
    }
    fetch = lambda f, s: {  # noqa: E731
        "proof": [h.hex() for h in consistency_nodes(leaves, f)]
    }
    verdict3, line3 = logmonitor.compare_views(
        mine,
        pin,
        {w_signer.public_key_b64},
        witness_pin=behind,
        fetch_wconsistency=fetch,
    )
    assert verdict3 == "agree" and "verified against our own pin" in line3

    # Pin BEHIND the anchor with a root the real prefix never had: the
    # served consistency proof can't reach it — but a failed UNSIGNED
    # proof can't convict either. No signed material contradicts the pin
    # at a non-checkpoint size, so this is 'unverifiable', not 'dishonest'
    # (a same-size root mismatch or the anchor's own signed `extends`
    # disagreeing are the provable lies, covered above).
    fake = {"tree_size": len(leaves) - 1, "root_sha256": "11" * 32}
    verdict4, line4 = logmonitor.compare_views(
        mine,
        pin,
        {w_signer.public_key_b64},
        witness_pin=fake,
        fetch_wconsistency=fetch,
    )
    assert verdict4 == "unverifiable" and "unproven" in line4


def test_check_cosig_anchors_verifies_a_packed_witness_anchor(engine, store, household, schedule, t0):
    """A pack can carry the witness's self-anchor next to each cosig:
    the anchor only counts when its head is signed by the cosig's OWN key
    and the cosig reaches that head — a claimed anchor that fails is a
    lie indicator, not a downgrade."""
    from attest import logmonitor
    from attest.transparency import inclusion_path, leaf_hashes, root

    w_store, w_signer = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": _doc_for(engine), "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200
    cosig = out["cosignature"]

    # The witness checkpoints its own log — the cosig becomes a leaf.
    leaves = leaf_hashes(w_store.receipts())
    w_cp = w_signer.issue(
        visit_id="log:wcp",
        sequence=99,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": len(leaves),
            "root_sha256": root(leaves).hex(),
        },
    )
    w_store.put_receipt(w_cp)
    idx = leaves.index(bytes.fromhex(cosig["payload_hash"]))
    anchor = {
        "checkpoint": w_cp.model_dump(mode="json"),
        "proof": {
            "leaf_index": idx,
            "path": [p.hex() for p in inclusion_path(leaves, idx)],
        },
    }
    doc = {"cosignatures": [cosig], "cosig_anchors": {cosig["id"]: anchor}}
    anchored, errors = logmonitor.check_cosig_anchors(doc)
    assert anchored == 1 and errors == []

    # No anchors at all — legacy pack, nothing to count or fail.
    assert logmonitor.check_cosig_anchors({"cosignatures": [cosig]}) == (0, [])

    # An anchor keyed to a cosig the doc doesn't carry is a lie indicator.
    a2, e2 = logmonitor.check_cosig_anchors(
        {"cosignatures": [cosig], "cosig_anchors": {"rcpt_ghost": anchor}}
    )
    assert a2 == 0 and e2

    # An anchor head signed by anyone but the cosig's own witness anchors
    # nothing about this attestation.
    bad = json.loads(json.dumps(anchor))
    bad["checkpoint"] = cp.model_dump(mode="json")  # the ISSUER's checkpoint
    a3, e3 = logmonitor.check_cosig_anchors({"cosignatures": [cosig], "cosig_anchors": {cosig["id"]: bad}})
    assert a3 == 0 and any("own witness key" in e for e in e3)

    # A proof that doesn't reach the anchor head fails closed — a
    # one-leaf tree needs an empty path, so a supplied node can't be right.
    bad2 = json.loads(json.dumps(anchor))
    bad2["proof"]["path"] = ["00" * 32]
    a4, e4 = logmonitor.check_cosig_anchors({"cosignatures": [cosig], "cosig_anchors": {cosig["id"]: bad2}})
    assert a4 == 0 and e4


def _rotated_issuer(engine, store):
    """Rotate the engine's signer for real (consented pivot) and return
    (new_key, receipts) — the issuer doc fields the witness consumes."""
    from attest.ledger import Signer

    new_signer = Signer.ephemeral()
    new_key = new_signer.public_key_b64
    engine.rotate_signing_key(new_key, lambda: new_signer)
    receipts = [
        r.model_dump(mode="json")
        for r in store.receipts()
        if r.payload.get("record_type") in ("key_rotation", "key_adoption")
    ]
    return new_key, receipts


def test_witness_pin_binds_the_lineage_root_not_the_claimed_tip(engine, store, household, schedule, t0):
    """HIGH audit fix: the pin slot keys on the issuer family's ROOT — the
    stable identity — not the claimed issuer_key. A rotated tip (or a
    claimed ancestor, or any in-lineage alias) resolves to the SAME slot,
    so a rotation can't launder a forked head into a fresh pin."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    k_old = engine.signer.public_key_b64

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    doc_v1 = _doc_for(engine)
    status, _ = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc_v1, "checkpoint": cp1.model_dump(mode="json")}
    )
    assert status == 200
    assert w_store.setting(f"witness:{k_old}")["tree_size"] == cp1.payload["tree_size"]

    # The issuer rotates: it now claims — and signs with — k_new. The
    # canonical identity stays the root key, so the pin slot never moves.
    k_new, receipts = _rotated_issuer(engine, store)
    doc_v2 = {"schema": "attest.issuer/1", "issuer_key": k_new, "key_receipts": receipts}
    from attest.ledger import lineage_root

    assert lineage_root(k_new, logmonitor._doc_receipts(doc_v2)) == k_old

    # A grown head under the NEW tip cosigns — rotation is not a new issuer.
    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    cp2 = engine.issue_log_checkpoint()
    assert cp2.public_key == k_new
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc_v2, "checkpoint": cp2.model_dump(mode="json")}
    )
    assert status == 200 and out["pinned"]["tree_size"] == cp2.payload["tree_size"]
    assert out["cosignature"]["payload"]["subject_issuer"] == k_old
    assert out["cosignature"]["payload"]["subject_issuer_claimed"] == k_new
    assert w_store.setting(f"witness:{k_old}")["tree_size"] == cp2.payload["tree_size"]
    assert w_store.setting(f"witness:{k_new}") is None  # no second slot

    # The exploit itself: a FORKED head under the rotated tip — same size,
    # different root. Under claimed-key pinning this minted a fresh slot
    # and got signed; under the root slot it is the same 409 any fork gets.
    fork = engine.signer.issue(
        visit_id="log:forked-tip",
        sequence=999,
        prev_hash=None,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": cp2.payload["tree_size"],
            "root_sha256": "00" * 32,
        },
    )
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc_v2, "checkpoint": fork.model_dump(mode="json")}
    )
    assert status == 409 and out["pinned"]["tree_size"] == cp2.payload["tree_size"]

    # Claiming the ANCESTOR lands in the same slot too — a regressed head
    # offered under the old key is refused, not welcomed as a new issuer.
    doc_alias = {"schema": "attest.issuer/1", "issuer_key": k_old, "key_receipts": receipts}
    status, _ = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc_alias, "checkpoint": cp1.model_dump(mode="json")}
    )
    assert status == 409

    # The published view names the canonical identity — the monitor's
    # lineage-membership match finds it whatever tip is claimed.
    heads = logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    assert [p["issuer_key"] for p in heads["pins"]] == [k_old]


def test_witness_migrates_a_claimed_key_pin_into_the_canonical_slot(engine, store, household, schedule, t0):
    """Pins minted before canonical slots live under the claimed key — the
    upgrade must carry their continuity forward, not read them as 'no
    prior view'. Migration adopts the family-member pin, repins under the
    root, and tombstones the old slot out of /api/witness/heads."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    k_old = engine.signer.public_key_b64

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()

    # The issuer rotates: it now claims — and signs with — k_new. k_old is
    # the family root, i.e. the canonical slot name.
    k_new, receipts = _rotated_issuer(engine, store)
    doc_v2 = {"schema": "attest.issuer/1", "issuer_key": k_new, "key_receipts": receipts}

    # Pre-canonical world: this issuer's pin was written under the key it
    # claimed THEN — the rotated tip — not under the root. The slot holds
    # cp1's real head, so offering cp1 must satisfy continuity, not reset.
    w_store.put_setting(
        f"witness:{k_new}",
        {
            "schema": logmonitor.WITNESS_SCHEMA,
            "issuer_key": k_new,
            "tree_size": cp1.payload["tree_size"],
            "root_sha256": cp1.payload["root_sha256"],
            "checkpoint_id": cp1.id,
        },
    )
    assert w_store.setting(f"witness:{k_old}") is None  # canonical slot absent

    _seed(engine, household[0], t0 - timedelta(hours=5), n=1)
    cp2 = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": doc_v2, "checkpoint": cp2.model_dump(mode="json")}
    )
    assert status == 200 and out["pinned"]["tree_size"] == cp2.payload["tree_size"]
    # Continuity came from the migrated pin — repinned under the root.
    assert w_store.setting(f"witness:{k_old}")["tree_size"] == cp2.payload["tree_size"]
    tomb = w_store.setting(f"witness:{k_new}")
    assert tomb["schema"] == "attest.witness-pin-migrated/1"

    # The tombstoned slot no longer publishes a second view.
    heads = logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    assert [p["issuer_key"] for p in heads["pins"]] == [k_old]


def test_witness_migration_never_adopts_a_foreign_slot(engine, store, household, schedule, t0):
    """A legacy slot is family-bound: a slot whose stored issuer_key lies
    OUTSIDE the requester's certified lineage is not this issuer's pin —
    migrating it would let one deployment inherit another's continuity."""
    from attest import logmonitor
    from attest.ledger import Signer

    w_store, w_signer = _witness_deployment()

    # A foreign issuer's pin — a completely different key family.
    stranger = Signer.ephemeral()
    w_store.put_setting(
        f"witness:{stranger.public_key_b64}",
        {
            "schema": logmonitor.WITNESS_SCHEMA,
            "issuer_key": stranger.public_key_b64,
            "tree_size": 50,
            "root_sha256": "ab" * 32,
            "checkpoint_id": "rcpt_x",
        },
    )

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": _doc_for(engine), "checkpoint": cp1.model_dump(mode="json")}
    )
    # First-contact for THIS issuer — the foreign pin was never adopted.
    assert status == 200 and out["pinned"]["tree_size"] == cp1.payload["tree_size"]
    assert w_store.setting(f"witness:{stranger.public_key_b64}")["tree_size"] == 50


def test_compare_views_reports_dishonest_for_signed_lies(engine, store, household, schedule, t0):
    """Verdict taxonomy: 'unverifiable' is transient/missing material;
    'dishonest' is a VERIFIED lie — a cosig that fails signature checks,
    signs subjects contradicting the pin, or carries malformed signed
    subject fields. Dishonest freezes repins like a divergence."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    _seed(engine, household[0], t0)
    cp = engine.issue_log_checkpoint()
    status, _ = logmonitor.witness_cosign(
        w_store, w_signer, {"issuer_doc": _doc_for(engine), "checkpoint": cp.model_dump(mode="json")}
    )
    assert status == 200
    pin = logmonitor.witness_heads(w_store, w_signer.public_key_b64)["pins"][0]
    mine = {
        "issuer_key": engine.signer.public_key_b64,
        "tree_size": pin["tree_size"],
        "root_sha256": pin["root_sha256"],
    }

    # A cosig whose signature no longer verifies is a served lie.
    forged = dict(pin)
    forged["cosignature"] = dict(pin["cosignature"])
    forged["cosignature"]["signature"] = "AA=="
    verdict, _ = logmonitor.compare_views(mine, forged, {w_signer.public_key_b64})
    assert verdict == "dishonest"

    # Unsigned pin fields contradicting the signed subjects — a served lie.
    lied = dict(pin)
    lied["tree_size"] = pin["tree_size"] + 1
    verdict, _ = logmonitor.compare_views(mine, lied, {w_signer.public_key_b64})
    assert verdict == "dishonest"

    # A cosig whose SIGNED subject is malformed — the witness signed it, so
    # the lie is its own attestation (the signature fails too — either way,
    # never a crash).
    bad_subj = dict(pin)
    bad_subj["cosignature"] = dict(pin["cosignature"])
    bad_subj["cosignature"]["payload"] = dict(pin["cosignature"]["payload"])
    bad_subj["cosignature"]["payload"]["subject_tree_size"] = "not-an-int"
    verdict, _ = logmonitor.compare_views(mine, bad_subj, {w_signer.public_key_b64})
    assert verdict == "dishonest"

    # No cosignature at all — nothing attested, nothing to accuse.
    bare = {k: v for k, v in pin.items() if k != "cosignature"}
    verdict, _ = logmonitor.compare_views(mine, bare, {w_signer.public_key_b64})
    assert verdict == "unverifiable"

    # Malformed LOCAL state is unverifiable — corrupt pin, not a witness verdict.
    verdict, line = logmonitor.compare_views(
        {"issuer_key": mine["issuer_key"], "tree_size": "x", "root_sha256": None},
        pin,
        {w_signer.public_key_b64},
    )
    assert verdict == "unverifiable" and "monitor's own pin" in line


def test_monitor_journal_signs_each_cycle_and_exports_evidence(tmp_path, monkeypatch, capsys):
    """`monitor --journal` mints a signed monitor_observation per cycle into
    the local runtime's transparency log; `checkpoint --include monitor:`
    exports the trail as one self-verifying evidence doc."""
    import argparse
    import contextlib
    import io

    from attest import cli, logmonitor
    from attest.store import Store

    monkeypatch.setattr(cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(cli.settings, "kms_key_id", None)
    state_file = tmp_path / "mon.json"
    doc = {"schema": "attest.issuer/1", "issuer_key": "K" * 43, "key_receipts": []}
    cp = {
        "id": "rcpt_cp",
        "visit_id": "log:7:ab",
        "sequence": 7,
        "payload_hash": "cd" * 32,
        "signature": "s",
        "public_key": doc["issuer_key"],
        "payload": {"record_type": "log_checkpoint", "tree_size": 7, "root_sha256": "ab" * 32},
    }
    head = {"tree_size": 7, "root_sha256": "ab" * 32, "checkpoint": cp}
    monkeypatch.setattr(cli, "_fetch_issuer_doc", lambda url: doc)
    monkeypatch.setattr(logmonitor, "fetch_json", lambda url, client=None: head)

    def fake_check(state, doc_, head_, fc, at):
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
    ns = argparse.Namespace(
        url="https://deploy.example",
        issuer=None,
        state=str(state_file),
        interval=60,
        once=True,
        json=False,
        witness=None,
        journal=True,
    )
    buf = io.StringIO()
    with pytest.raises(SystemExit) as excinfo:
        with contextlib.redirect_stdout(buf):
            cli._monitor(ns)
    assert excinfo.value.code == 0
    assert "journaled observation" in buf.getvalue()

    store = Store(tmp_path / "attest.sqlite3")
    obs = [r for r in store.receipts() if r.payload.get("record_type") == "monitor_observation"]
    assert len(obs) == 1
    assert obs[0].payload["outcome"] == "pinned"
    assert obs[0].payload["subject"]["url"] == "https://deploy.example"
    assert obs[0].payload["served_head"]["tree_size"] == 7
    assert obs[0].payload["served_doc"] is None  # steady-state stays lean
    # Idempotent: re-journaling the identical observation reuses the receipt.
    from attest.engine import VisitEngine  # noqa: F401 — shape check only

    store.close()

    # --include monitor: embeds the trail + proofs in the checkpoint doc.
    out = tmp_path / "evidence.json"
    with contextlib.redirect_stdout(io.StringIO()):
        cli._checkpoint(argparse.Namespace(out=str(out), timestamp=False, witness=[], include=["monitor:"]))
    evdoc = json.loads(out.read_text(encoding="utf-8"))
    assert len(evdoc["receipts"]) == 1
    assert evdoc["receipts"][0]["payload"]["record_type"] == "monitor_observation"
    assert evdoc["receipts"][0]["payload_hash"] in evdoc["proofs"]

    def verify_doc(**kw):
        v = argparse.Namespace(
            **{
                "key": None,
                "issuer_url": None,
                "json": True,
                "checkpoint": None,
                "against": None,
                "witness_url": None,
                "witness_key": None,
                "witness_threshold": 1,
                **kw,
            }
        )
        b = io.StringIO()
        with contextlib.redirect_stdout(b):
            cli._verify(v)
        return json.loads(b.getvalue())

    verdict = verify_doc(bundle=str(out))
    assert verdict["ok"] and verdict["kind"] == "log_checkpoint"
    assert "1 embedded receipt(s)" in verdict["detail"]

    # A tampered embedded receipt fails closed — payload hash no longer
    # matches its signature.
    bad = json.loads(out.read_text(encoding="utf-8"))
    bad["receipts"][0]["payload"]["outcome"] = "diverged"
    bad_path = tmp_path / "bad-evidence.json"
    bad_path.write_text(json.dumps(bad))
    with pytest.raises(SystemExit) as excinfo:
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            cli._verify(
                argparse.Namespace(
                    bundle=str(bad_path),
                    key=None,
                    issuer_url=None,
                    json=True,
                    checkpoint=None,
                    against=None,
                    witness_url=None,
                    witness_key=None,
                    witness_threshold=1,
                )
            )
    assert excinfo.value.code == 1

    # An embedded receipt without an inclusion proof fails closed too —
    # 'inside the log' must be proven, not implied.
    noproof = json.loads(out.read_text(encoding="utf-8"))
    noproof["proofs"] = {}
    noproof_path = tmp_path / "noproof.json"
    noproof_path.write_text(json.dumps(noproof))
    with pytest.raises(SystemExit) as excinfo:
        buf3 = io.StringIO()
        with contextlib.redirect_stdout(buf3):
            cli._verify(
                argparse.Namespace(
                    bundle=str(noproof_path),
                    key=None,
                    issuer_url=None,
                    json=True,
                    checkpoint=None,
                    against=None,
                    witness_url=None,
                    witness_key=None,
                    witness_threshold=1,
                )
            )
    assert excinfo.value.code == 1

    # A receipt signed by a foreign key must not ride the issuer's doc —
    # lineage membership is checked before the signature.
    from attest.ledger import Signer

    foreign = Signer.ephemeral().issue(
        visit_id="monitor:foreign",
        sequence=1,
        prev_hash=None,
        facts={"record_type": "monitor_observation", "outcome": "diverged"},
    )
    grafted = json.loads(out.read_text(encoding="utf-8"))
    grafted["receipts"].append(foreign.model_dump(mode="json"))
    grafted_path = tmp_path / "grafted.json"
    grafted_path.write_text(json.dumps(grafted))
    with pytest.raises(SystemExit) as excinfo:
        buf4 = io.StringIO()
        with contextlib.redirect_stdout(buf4):
            cli._verify(
                argparse.Namespace(
                    bundle=str(grafted_path),
                    key=None,
                    issuer_url=None,
                    json=True,
                    checkpoint=None,
                    against=None,
                    witness_url=None,
                    witness_key=None,
                    witness_threshold=1,
                )
            )
    assert excinfo.value.code == 1


def test_monitor_observation_mints_and_is_idempotent(engine):
    """The journal receipt chains like every other receipt and dedups on
    identical observation content."""
    obs = {
        "observed_at": "2026-01-01T00:00:00+00:00",
        "subject": {"url": "https://deploy.example", "issuer_key": "K"},
        "outcome": "steady",
        "served_head": {"tree_size": 3, "root_sha256": "ab" * 32, "checkpoint_id": "x"},
    }
    r1 = engine.issue_monitor_observation(dict(obs))
    r2 = engine.issue_monitor_observation(dict(obs))
    assert r1.id == r2.id
    assert r1.visit_id.startswith("monitor:")
    assert r1.payload["record_type"] == "monitor_observation"
    assert r1.payload["outcome"] == "steady"
    other = engine.issue_monitor_observation({**obs, "outcome": "alert"})
    assert other.id != r1.id


def test_monitor_journal_mints_alert_outcome_with_served_material(tmp_path, monkeypatch, capsys):
    """An ALERT cycle embeds the verbatim served doc — the signed
    contradiction is the evidence, and it rides inside the receipt."""
    import argparse
    import contextlib
    import io

    from attest import cli, logmonitor
    from attest.store import Store

    monkeypatch.setattr(cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(cli.settings, "kms_key_id", None)
    state_file = tmp_path / "mon.json"
    # Pre-seed a pin so the cycle has prior state to contradict.
    state_file.write_text(
        json.dumps(
            {
                "schema": logmonitor.STATE_SCHEMA,
                "issuer_key": "K" * 43,
                "tree_size": 9,
                "root_sha256": "ef" * 32,
                "checkpoint_id": "rcpt_old",
                "checked_at": "t",
            }
        ),
        encoding="utf-8",
    )
    doc = {"schema": "attest.issuer/1", "issuer_key": "K" * 43, "key_receipts": []}
    cp = {
        "id": "rcpt_new",
        "visit_id": "log:7:cd",
        "sequence": 7,
        "payload_hash": "ab" * 32,
        "signature": "s",
        "public_key": doc["issuer_key"],
        "payload": {"record_type": "log_checkpoint", "tree_size": 7, "root_sha256": "cd" * 32},
    }
    head = {"tree_size": 7, "root_sha256": "cd" * 32, "checkpoint": cp}
    monkeypatch.setattr(cli, "_fetch_issuer_doc", lambda url: doc)
    monkeypatch.setattr(logmonitor, "fetch_json", lambda url, client=None: head)
    monkeypatch.setattr(
        logmonitor,
        "check",
        lambda state, d, h, fc, at: (
            None,
            False,
            ["ALERT: signed head regressed — was 9 leaves, now 7"],
        ),
    )
    ns = argparse.Namespace(
        url="https://deploy.example",
        issuer=None,
        state=str(state_file),
        interval=60,
        once=True,
        json=False,
        witness=None,
        journal=True,
    )
    with pytest.raises(SystemExit) as excinfo:
        with contextlib.redirect_stdout(io.StringIO()):
            cli._monitor(ns)
    assert excinfo.value.code == 1  # the watch failed — but the evidence wrote

    store = Store(tmp_path / "attest.sqlite3")
    obs = [r for r in store.receipts() if r.payload.get("record_type") == "monitor_observation"]
    assert len(obs) == 1
    assert obs[0].payload["outcome"] == "alert"
    assert obs[0].payload["served_doc"]["checkpoint"]["id"] == "rcpt_new"
    assert obs[0].payload["pin_before"]["tree_size"] == 9
    store.close()


def test_witness_refusal_never_touches_a_migrating_legacy_pin(engine, store, household, schedule, t0):
    """HIGH audit fix: the legacy→canonical migration scan is read-only until
    the offer is PROVEN. A refused offer must leave every slot untouched —
    otherwise a fork offer could burn the very pin that refused it, and the
    retry would sail through on a wiped slate."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    k_old = engine.signer.public_key_b64
    _seed(engine, household[0], t0)
    cp_small = engine.issue_log_checkpoint()

    k_new, receipts = _rotated_issuer(engine, store)
    doc_v2 = {"schema": "attest.issuer/1", "issuer_key": k_new, "key_receipts": receipts}

    # Pre-fix debris: a pin minted under the CLAIMED tip (pre-canonical
    # builds keyed on issuer_key as presented). It attests a LARGER tree
    # than the head about to be offered — the offer must be refused.
    legacy = {
        "schema": logmonitor.WITNESS_SCHEMA,
        "issuer_key": k_new,
        "tree_size": cp_small.payload["tree_size"] + 5,
        "root_sha256": "aa" * 32,
        "checkpoint_id": "rcpt_stale",
    }
    w_store.put_setting(f"witness:{k_new}", legacy)
    assert w_store.setting(f"witness:{k_old}") is None  # canonical slot empty

    status, _ = logmonitor.witness_cosign(
        w_store,
        w_signer,
        {"issuer_doc": doc_v2, "checkpoint": cp_small.model_dump(mode="json")},
    )
    assert status == 409
    # The refused offer wrote NOTHING: no canonical repin, no tombstone —
    # the migrated-candidate pin survives to refuse the retry.
    assert w_store.setting(f"witness:{k_new}") == legacy
    assert w_store.setting(f"witness:{k_old}") is None


def test_witness_success_tombstones_every_family_alias_slot(engine, store, household, schedule, t0):
    """MEDIUM audit fix: two historical claims can each leave a legacy slot.
    Migration binds the NEWEST family pin — the furthest head the witness
    attested — and a success tombstones EVERY losing alias, or the stale
    slots would keep publishing old heads as if independent issuers."""
    from attest import logmonitor

    w_store, w_signer = _witness_deployment()
    k_old = engine.signer.public_key_b64

    _seed(engine, household[0], t0)
    cp1 = engine.issue_log_checkpoint()
    k_mid, _ = _rotated_issuer(engine, store)
    _seed(engine, household[0], t0 - timedelta(hours=1), n=2)
    cp2 = engine.issue_log_checkpoint()
    k_new, receipts = _rotated_issuer(engine, store)

    w_store.put_setting(
        f"witness:{k_mid}",
        {
            "schema": logmonitor.WITNESS_SCHEMA,
            "issuer_key": k_mid,
            "tree_size": cp1.payload["tree_size"],
            "root_sha256": cp1.payload["root_sha256"],
            "checkpoint_id": cp1.id,
        },
    )
    w_store.put_setting(
        f"witness:{k_new}",
        {
            "schema": logmonitor.WITNESS_SCHEMA,
            "issuer_key": k_new,
            "tree_size": cp2.payload["tree_size"],
            "root_sha256": cp2.payload["root_sha256"],
            "checkpoint_id": cp2.id,
        },
    )

    doc_v3 = {"schema": "attest.issuer/1", "issuer_key": k_new, "key_receipts": receipts}
    _seed(engine, household[0], t0 - timedelta(hours=2), n=3)
    cp3 = engine.issue_log_checkpoint()
    status, out = logmonitor.witness_cosign(
        w_store,
        w_signer,
        {"issuer_doc": doc_v3, "checkpoint": cp3.model_dump(mode="json")},
    )
    assert status == 200
    # The newest legacy won: continuity bridged from cp2's head — pinned
    # under the lineage root, not either claimed alias.
    assert out["pinned"]["issuer_key"] == k_old
    assert w_store.setting(f"witness:{k_old}")["tree_size"] == cp3.payload["tree_size"]
    # Every losing family slot is a tombstone now — neither publishes a
    # stale head from /api/witness/heads again.
    for slot in (k_mid, k_new):
        dead = w_store.setting(f"witness:{slot}")
        assert dead["schema"] == "attest.witness-pin-migrated/1"
        assert dead["migrated_to"] == k_old


def test_lineage_root_is_deterministic_under_a_reordered_merge(engine):
    """MEDIUM audit fix: the requester orders the key_receipts pool. Two
    predecessors consent-rotating into the SAME successor is a merge — the
    walk must pick the same hop every time, or an issuer could order its
    pool to yield whichever 'canonical' pin slot it prefers."""
    from attest.ledger import Signer, lineage_root

    sa, sb, sn = Signer.ephemeral(), Signer.ephemeral(), Signer.ephemeral()
    receipts = []
    for retiring in (sa, sb):
        rot = retiring.issue(
            visit_id="key:rot",
            sequence=1,
            prev_hash=None,
            facts={
                "record_type": "key_rotation",
                "previous_key": retiring.public_key_b64,
                "new_key": sn.public_key_b64,
            },
        )
        adopt = sn.issue(
            visit_id="key:adopt",
            sequence=len(receipts) + 2,
            prev_hash=None,
            facts={
                "record_type": "key_adoption",
                "rotation_receipt": {"id": rot.id, "hash": rot.payload_hash},
                "previous_key": retiring.public_key_b64,
                "new_key": sn.public_key_b64,
            },
        )
        receipts += [rot, adopt]

    expected = min(sa.public_key_b64, sb.public_key_b64)
    assert lineage_root(sn.public_key_b64, receipts) == expected
    assert lineage_root(sn.public_key_b64, list(reversed(receipts))) == expected
