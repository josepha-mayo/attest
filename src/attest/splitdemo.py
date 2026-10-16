"""Split-view demonstration: one issuer, two histories, one caught fork.

The transparency log's whole premise is that a deployment CAN serve two
observers different versions of its history and every self-consistent check
still passes — each signed head verifies, each proof closes, and neither
observer alone can tell. The catch requires a second pair of eyes: an
independent witness countersigns what IT was shown, and the monitor's
cross-view compares the two signed views. Same size, different roots — the
one outcome no honest log can produce.

This command fabricates exactly that scenario in scratch space: one issuer
key signs two divergent receipt histories (the classic backup-restore-then-
keep-signing accident, or a deliberate double-serve), a witness pins the
fork, and a monitor pinned on the true log catches the divergence and signs
the catch into its journal as a monitor_observation receipt.

What is simulated: the network — endpoints are called transport-free, the
same functions the HTTP handlers use.
What is real: every signature, every Merkle proof, the witness pin, the
divergence verdict, and the exported evidence document — verify it offline
with `attest verify`.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path


def _engine(store, signer, data_dir: Path):
    """A VisitEngine over a scratch store — the ring client is inert; the
    demo only uses the issuance and log surfaces."""
    from ring_sandbox import RingClient

    from .config import Settings
    from .engine import VisitEngine
    from .media import MediaStore
    from .summarize import TemplateSummarizer

    return VisitEngine(
        store,
        RingClient("split-demo", base_url="http://127.0.0.1:9"),
        signer,
        MediaStore(data_dir / "media"),
        TemplateSummarizer("UTC"),
        Settings(data_dir=data_dir),
    )


def _seed(store, signer, tag: str, n: int = 3) -> None:
    """Stand-in content receipts — the log's leaves don't care about
    record_type, only that these bytes were signed into this position."""
    prev = store.latest_receipt()
    for i in range(n):
        r = signer.issue(
            visit_id=f"demo:{tag}:{i}",
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "demo_leaf",
                "observed_at": datetime.now(tz=UTC).isoformat(),
                "narrative": f"history '{tag}' event {i}",
                "boundary": (
                    "Demo content — a stand-in for real attestation receipts; "
                    "only its position in the Merkle tree matters here."
                ),
            },
        )
        store.put_receipt(r)
        prev = r


def run(out_dir: Path | None = None, *, echo=print) -> dict:
    """Fabricate the fork, catch it, and (optionally) write the evidence
    document. Returns the story dict — every claim in it is verifiable."""
    from . import ledger, logmonitor
    from .ledger import Signer
    from .store import Store

    scratch = Path(tempfile.mkdtemp(prefix="attest-split-demo-"))
    story: dict = {"steps": []}

    def step(text: str) -> None:
        story["steps"].append(text)
        echo(text)

    # --- Act 1: one issuer, one honest log ---------------------------------
    issuer_store = Store(":memory:")
    issuer_keypair = Signer.ephemeral()
    issuer = _engine(issuer_store, issuer_keypair, scratch / "issuer")
    _seed(issuer_store, issuer_keypair, "true")
    cp_true = issuer.issue_log_checkpoint()
    true_size, true_root = cp_true.payload["tree_size"], cp_true.payload["root_sha256"]
    step(f"1. issuer signs {true_size} receipt(s), checkpoint {cp_true.id[:20]}… — root {true_root[:24]}…")

    # --- Act 2: the same key signs a SECOND history ------------------------
    # Backup restored and kept writing, or a deliberate double-serve: the
    # fork carries different payloads at the same positions, so both heads
    # are validly signed by the same lineage — signature checks alone pass.
    fork_store = Store(":memory:")
    fork = _engine(fork_store, issuer_keypair, scratch / "fork")
    _seed(fork_store, issuer_keypair, "fork")
    cp_fork = fork.issue_log_checkpoint()
    fork_size, fork_root = cp_fork.payload["tree_size"], cp_fork.payload["root_sha256"]
    if not (fork_size == true_size and fork_root != true_root):
        raise RuntimeError(
            "split-demo: fabricated fork is not divergent — the demo cannot "
            "proceed without two same-size, different-root histories"
        )
    step(
        f"2. same issuer key signs a different {fork_size}-leaf history — "
        f"checkpoint {cp_fork.id[:20]}…, root {fork_root[:24]}… — both verify"
    )

    doc = ledger.issuer_document(issuer_keypair.public_key_b64, issuer_store.receipts())

    # --- Act 3: an independent witness pins the FORK ------------------------
    w_store = Store(":memory:")
    w_signer = Signer.ephemeral()
    status, out = logmonitor.witness_cosign(
        w_store,
        w_signer,
        {"issuer_doc": doc, "checkpoint": cp_fork.model_dump(mode="json")},
    )
    if status != 200:
        raise RuntimeError(f"split-demo: witness refused the fork pin — {out}")
    step(
        f"3. witness was shown the FORK — cosigned it (rcpt "
        f"{out['cosignature']['id'][:20]}…) and pinned size {fork_size}"
    )
    # Anchor the attestation inside the witness's own log, exactly like a
    # live witness that checkpoints itself — the pin then proves the cosig
    # was publicly committed, not handed over privately.
    w_engine = _engine(w_store, w_signer, scratch / "witness")
    w_engine.issue_log_checkpoint()
    heads = logmonitor.anchor_published_pins(
        w_store, logmonitor.witness_heads(w_store, w_signer.public_key_b64)
    )
    w_pin = heads["pins"][0]
    wlog_engine = w_engine
    wlive_size, wlive_root = w_engine.log_head()
    w_head = {
        "tree_size": wlive_size,
        "root_sha256": wlive_root.hex(),
        "checkpoint": w_engine.issue_log_checkpoint().model_dump(mode="json"),
    }

    # --- Act 4: the monitor pins the TRUE log — and the views diverge -------
    true_tip, true_tip_root = issuer.log_head()
    served_head = {
        "tree_size": true_tip,
        "root_sha256": true_tip_root.hex(),
        "checkpoint": cp_true.model_dump(mode="json"),
    }
    now = datetime.now(tz=UTC).isoformat()
    mine, ok, lines = logmonitor.check(None, doc, served_head, issuer.consistency_proof, now)
    if not (ok and mine is not None):
        raise RuntimeError(f"split-demo: monitor pin of the true head failed — {lines}")
    step(f"4. monitor pins the TRUE head (size {mine['tree_size']}) — locally green")
    verdict, line = logmonitor.compare_views(
        mine,
        w_pin,
        {w_signer.public_key_b64},
        witness_pin={"tree_size": wlive_size, "root_sha256": wlive_root.hex()},
        fetch_wconsistency=wlog_engine.consistency_proof,
        issuer_lineage={issuer_keypair.public_key_b64},
    )
    step(f"   cross-view: [{verdict}] {line}")
    if verdict != "diverged":
        # Under -O an assert would silently skip this and the observation
        # below would be signed claiming 'diverged' over agreeing views —
        # a false attestation. The gate is a runtime check, not an assert.
        raise RuntimeError(
            f"split-demo: cross-view did not detect the fork — [{verdict}] {line}; "
            "refusing to sign a monitor_observation that claims divergence"
        )

    # --- Act 5: the catch is itself evidence --------------------------------
    j_store = Store(":memory:")
    j_engine = _engine(j_store, Signer.ephemeral(), scratch / "journal")
    obs = j_engine.issue_monitor_observation(
        {
            "observed_at": now,
            "subject": {"url": "demo://issuer", "issuer_key": issuer_keypair.public_key_b64},
            "outcome": "diverged",
            "served_head": {
                "checkpoint_id": cp_true.id,
                "tree_size": true_size,
                "root_sha256": true_root,
            },
            "pin_before": None,
            "pin_after": {
                k: mine.get(k) for k in ("issuer_key", "tree_size", "root_sha256", "checkpoint_id")
            },
            "witness_view": {
                "url": "demo://witness",
                "verdict": verdict,
                "pin_issuer_key": w_pin.get("issuer_key"),
            },
            "served_doc": served_head,
            "served_witness_pin": w_pin,
            "served_witness_head": w_head,
        }
    )
    step(f"5. the catch is signed as monitor_observation {obs.id[:20]}…")

    doc_out = None
    if out_dir is not None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        # The self-verifying document: the journal's signed checkpoint +
        # the observation receipt + its inclusion proof — the same format
        # `attest checkpoint --include monitor:` emits, verifiable offline.
        j_cp = j_engine.issue_log_checkpoint()
        from .transparency import inclusion_path

        leaves = j_engine.log_leaves()[: int(j_cp.payload["tree_size"])]
        idx = leaves.index(bytes.fromhex(obs.payload_hash))
        doc_out = {
            "schema": "attest.log-checkpoint/1",
            "checkpoint": j_cp.model_dump(mode="json"),
            "boundary": j_cp.payload.get("boundary"),
            "receipts": [obs.model_dump(mode="json")],
            "proofs": {
                obs.payload_hash: {
                    "leaf_index": idx,
                    "path": [n.hex() for n in inclusion_path(leaves, idx)],
                }
            },
            "demo": (
                "split-view demonstration — the embedded monitor_observation "
                "carries two signed views of one issuer's log that cannot "
                "both be true (same size, different roots). Simulated "
                "endpoints; every signature and proof is real."
            ),
        }
        path = out_dir / "divergence-checkpoint.json"
        # Atomic like every evidence output — a truncated evidence doc is
        # worse than none.
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(doc_out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)
        step(f"6. evidence written: {path}")
        step(
            "   verify it: attest verify "
            f"{path} — the observation inside is signed AND inside the "
            "journal's signed tree head"
        )

    story.update(
        {
            "verdict": verdict,
            "issuer_key": issuer_keypair.public_key_b64,
            "witness_key": w_signer.public_key_b64,
            "true_head": {"tree_size": true_size, "root_sha256": true_root, "checkpoint_id": cp_true.id},
            "fork_head": {"tree_size": fork_size, "root_sha256": fork_root, "checkpoint_id": cp_fork.id},
            "observation_id": obs.id,
            "evidence": str(out_dir / "divergence-checkpoint.json") if doc_out else None,
        }
    )
    return story
