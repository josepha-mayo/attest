"""The split-view demo: one issuer key signs two histories, a witness pins
one, the monitor pins the other — and the cross-view reports 'diverged',
the one verdict no honest log can produce. The exported evidence document
must verify through the real offline verifier."""

import argparse
import contextlib
import io
import json


def test_split_demo_catches_the_fork_and_exports_verifiable_evidence(tmp_path, capsys):
    from attest import splitdemo

    story = splitdemo.run(tmp_path, echo=lambda *_: None)

    assert story["verdict"] == "diverged"
    # Same issuer lineage, same tree size, different roots — the one
    # signature shape no honest append-only log can produce.
    assert story["true_head"]["tree_size"] == story["fork_head"]["tree_size"]
    assert story["true_head"]["root_sha256"] != story["fork_head"]["root_sha256"]
    assert story["issuer_key"] != story["witness_key"]
    assert any("DIVERGED" in s for s in story["steps"])

    evidence = tmp_path / "divergence-checkpoint.json"
    assert evidence.exists()

    # The emitted document verifies through the REAL verifier path — a
    # signed head + the embedded observation + its inclusion proof.
    from attest import cli

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._verify(
            argparse.Namespace(
                bundle=str(evidence),
                key=None,
                issuer_url=None,
                json=False,
                checkpoint=None,
                against=None,
            )
        )
    out = buf.getvalue()
    assert "OK:" in out and "1 embedded receipt(s) verified" in out

    # And the embedded receipt is the divergence observation itself —
    # verbatim served material rides inside it for independent re-checking.
    doc = json.loads(evidence.read_text(encoding="utf-8"))
    obs = doc["receipts"][0]
    assert obs["payload"]["record_type"] == "monitor_observation"
    assert obs["payload"]["outcome"] == "diverged"
    assert obs["payload"]["served_witness_pin"]["cosignature"]
    assert obs["payload"]["served_witness_head"]["checkpoint"]
    assert obs["payload"]["served_doc"]["checkpoint"]


def test_split_demo_without_out_writes_no_evidence(tmp_path, capsys):
    """No --out means narrative only — nothing is written anywhere the
    caller didn't ask for."""
    from attest import splitdemo

    story = splitdemo.run(None, echo=lambda *_: None)
    assert story["verdict"] == "diverged"
    assert story["evidence"] is None
    assert list(tmp_path.iterdir()) == []
