"""Merkle transparency log: RFC 6962 semantics + adversarial properties."""

import hashlib

import pytest

from attest.transparency import (
    consistency_nodes,
    inclusion_path,
    leaf_hash,
    root,
    verify_consistency,
    verify_inclusion,
)

# RFC 6962 §2.1.1: MTH({}) is the empty hash; MTH of one empty leaf is
# SHA-256(0x00) — the domain-separated leaf digest, not the raw string.
EMPTY_ROOT = hashlib.sha256(b"").digest()
EMPTY_LEAF = bytes.fromhex("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")


def _leaves(n: int) -> list[bytes]:
    """Deterministic distinct leaves — receipt payload-hash stand-ins."""
    return [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n)]


def test_rfc6962_known_roots():
    assert root([]) == EMPTY_ROOT
    assert root([b""]) == EMPTY_LEAF
    # n=2: node(leaf(d0), leaf(d1)) — computed by hand per the RFC layout.
    d0, d1 = b"\x00", b"\x01"
    expected = hashlib.sha256(b"\x01" + leaf_hash(d0) + leaf_hash(d1)).digest()
    assert root([d0, d1]) == expected


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def test_rfc6962_worked_example():
    """The §2.1.3 seven-leaf tree — every named audit path and consistency
    proof must match the RFC's node layout exactly."""
    d = _leaves(7)
    a, b, c, e, f = (leaf_hash(x) for x in (d[0], d[1], d[2], d[4], d[5]))
    dd, j = leaf_hash(d[3]), leaf_hash(d[6])
    g, h, i = _node(a, b), _node(c, dd), _node(e, f)
    k, right = _node(g, h), _node(i, j)
    assert root(d) == _node(k, right)

    # Audit paths quoted in the RFC.
    assert inclusion_path(d, 0) == [b, h, right]
    assert inclusion_path(d, 3) == [c, g, right]
    assert inclusion_path(d, 4) == [f, j, k]
    assert inclusion_path(d, 6) == [i, k]

    # Consistency proofs quoted in the RFC.
    assert consistency_nodes(d, 3) == [c, dd, g, right]
    assert consistency_nodes(d, 4) == [right]
    assert consistency_nodes(d, 6) == [i, j, k]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 64, 100, 128, 150])
def test_inclusion_every_index(n):
    leaves = _leaves(n)
    expected = root(leaves)
    for i in range(n):
        path = inclusion_path(leaves, i)
        assert verify_inclusion(leaves[i], n, i, path, expected), f"n={n} i={i}"


def test_inclusion_rejects_tampered_path_and_wrong_members():
    leaves = _leaves(9)
    expected = root(leaves)
    path = inclusion_path(leaves, 4)
    flipped = [bytes([p[0] ^ 1]) + p[1:] for p in path]
    assert not verify_inclusion(leaves[4], 9, 4, flipped, expected)
    # Right leaf, wrong index: the path is positional.
    assert not verify_inclusion(leaves[5], 9, 4, inclusion_path(leaves, 4), expected)
    # A leaf never in the tree cannot forge a path.
    assert not verify_inclusion(b"outsider", 9, 4, path, expected)
    # Wrong root fails even with a valid path.
    assert not verify_inclusion(leaves[4], 9, 4, path, root(_leaves(10)))
    # Out-of-range index and empty tree fail closed.
    assert not verify_inclusion(leaves[0], 9, 9, [], expected)
    assert not verify_inclusion(leaves[0], 0, 0, [], EMPTY_ROOT)


@pytest.mark.parametrize("n,m", [(2, 1), (3, 1), (5, 2), (8, 5), (9, 8), (16, 9), (17, 16), (100, 37)])
def test_consistency_proves_extension(n, m):
    leaves = _leaves(n)
    proof = consistency_nodes(leaves, m)
    assert verify_consistency(root(leaves[:m]), m, root(leaves), n, proof)


def test_consistency_rejects_rewritten_history():
    leaves = _leaves(10)
    proof = consistency_nodes(leaves, 5)
    # An "old tree" that rewrote leaf 2 is not a prefix — proof must fail.
    forged_old = _leaves(5)
    forged_old[2] = b"rewritten"
    assert not verify_consistency(root(forged_old), 5, root(leaves), 10, proof)
    # Truncated or padded proofs fail.
    assert not verify_consistency(root(leaves[:5]), 5, root(leaves), 10, proof[:-1])
    assert not verify_consistency(root(leaves[:5]), 5, root(leaves), 10, proof + [b"x" * 32])
    # A root pair from unrelated trees cannot be bridged.
    assert not verify_consistency(root(_leaves(3)), 3, root(_leaves(10)), 10, proof)


def test_consistency_equal_trees():
    leaves = _leaves(7)
    assert verify_consistency(root(leaves), 7, root(leaves), 7, [])
    assert not verify_consistency(root(leaves), 7, root(_leaves(7)[::-1]), 7, [])


def test_proof_lengths_are_logarithmic():
    # 10k leaves: inclusion path ≤ ceil(log2 n) nodes — the whole point.
    leaves = _leaves(10_000)
    assert len(inclusion_path(leaves, 4242)) <= 14
    proof = consistency_nodes(leaves, 4096)
    assert len(proof) <= 14


"""Engine surface: the checkpoint receipt and proofs a deployment emits."""


def _chain(engine, store, n, prefix="r"):
    """Append n validly-chained receipts — what the engine's log reads."""
    out = []
    for i in range(n):
        prev = store.latest_receipt()
        seq = prev.sequence + 1 if prev else 1
        r = engine.signer.issue(
            visit_id=f"{prefix}:{seq}",
            sequence=seq,
            prev_hash=prev.payload_hash if prev else None,
            facts={"record_type": "visit", "note": f"{prefix} {i}"},
        )
        store.put_receipt(r)
        out.append(r)
    return out


def test_engine_log_leaves_and_head(engine, store):
    assert engine.log_leaves() == []
    assert engine.log_head() == (0, root([]))
    rs = _chain(engine, store, 5)
    leaves = engine.log_leaves()
    assert leaves == [bytes.fromhex(r.payload_hash) for r in rs]
    assert engine.log_head() == (5, root(leaves))


def test_engine_checkpoint_signed_idempotent_postdated(engine, store):
    from attest.ledger import verify_receipt

    _chain(engine, store, 4)
    cp = engine.issue_log_checkpoint()
    p = cp.payload
    assert p["record_type"] == "log_checkpoint"
    assert p["tree_size"] == 4
    assert p["root_sha256"] == root(engine.log_leaves()[:4]).hex()
    ok, _ = verify_receipt(cp, public_key=cp.public_key)
    assert ok
    # The checkpoint commits to the tree BEFORE its own append — it signs
    # the head that preceded it, so its leaf sits outside the committed tree.
    assert cp.sequence == 5
    assert engine.issue_log_checkpoint().id == cp.id  # unchanged head: idempotent
    _chain(engine, store, 1)
    cp2 = engine.issue_log_checkpoint()
    assert cp2.id != cp.id
    assert cp2.payload["tree_size"] == 5  # checkpoints aren't leaves
    assert cp2.sequence == 7


def test_engine_inclusion_proof(engine, store):
    rs = _chain(engine, store, 7)
    size, head = engine.log_head()
    for i, r in enumerate(rs):
        p = engine.inclusion_proof(r)
        assert p["tree_size"] == size and p["leaf_index"] == i
        assert verify_inclusion(
            bytes.fromhex(r.payload_hash),
            size,
            i,
            [bytes.fromhex(x) for x in p["path"]],
            head,
        )
    # Bounded to an earlier head: leaves past the checkpoint carry no proof.
    assert engine.inclusion_proof(rs[6], size=3) is None
    p = engine.inclusion_proof(rs[2], size=3)
    assert verify_inclusion(
        bytes.fromhex(rs[2].payload_hash),
        3,
        2,
        [bytes.fromhex(x) for x in p["path"]],
        root(engine.log_leaves()[:3]),
    )
    # A receipt never chained cannot prove a place it never held.
    foreign = engine.signer.issue(
        visit_id="v:foreign", sequence=1, prev_hash=None, facts={"record_type": "visit"}
    )
    assert engine.inclusion_proof(foreign) is None


def test_engine_consistency_proof(engine, store):
    _chain(engine, store, 9)
    leaves = engine.log_leaves()
    for m in (1, 2, 3, 5, 8, 9):
        p = engine.consistency_proof(m)
        assert p is not None and p["first"] == m
        assert verify_consistency(
            root(leaves[:m]),
            m,
            root(leaves),
            len(leaves),
            [bytes.fromhex(x) for x in p["proof"]],
        )
    assert engine.consistency_proof(0) is None
    assert engine.consistency_proof(10) is None


def _visit_pack(engine, store, household, t0, tmp_path, **kw):
    """A real signed visit exported with the full tool pin + checkpoint —
    the pack every verifier surface must agree on."""
    import io
    import zipfile
    from datetime import timedelta

    from ring_sandbox import WebhookEvent, webhooks

    from attest.disputepack import build_pack, log_member
    from attest.reviews import ReviewBundle

    ev = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0 + timedelta(minutes=1),
        )
    )
    visit = engine.ingest(ev).visit
    engine.close_for_review(visit.id)
    bundle = ReviewBundle(original=store.receipt_for_visit(visit.id), reviews=[])
    data = build_pack(
        store,
        tmp_path / "media",
        bundle,
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"visit:{visit.id}", t),
        log_fn=lambda rs: log_member(engine, rs),
        **kw,
    )
    return data, zipfile.ZipFile(io.BytesIO(data))


def test_checkpoint_pack_verifies_everywhere(engine, store, household, schedule, t0, tmp_path):
    import json
    import subprocess
    import sys

    data, z = _visit_pack(engine, store, household, t0, tmp_path)
    assert "log_checkpoint.json" in z.namelist()
    doc = json.loads(z.read("log_checkpoint.json"))
    cp = doc["checkpoint"]
    assert cp["payload"]["record_type"] == "log_checkpoint"
    # Every receipt-bearing member carries a proof — bundle original, tool pin.
    assert {
        doc_r["payload_hash"]
        for doc_r in (
            json.loads(z.read("bundle.json"))["original"],
            json.loads(z.read("verifier_manifest.json")),
        )
    } <= set(doc["proofs"])
    assert cp["payload_hash"] not in doc["proofs"]  # the STH anchors itself

    from attest.app import _verify_pack

    ok, detail = _verify_pack(data, engine.signer.public_key_b64)
    assert ok, detail
    assert "transparency log" in detail

    # The embedded stdlib verifier — and the pack carries NO key_rotations.json
    # (no rotations happened), covering the rotation-free verifier path.
    out = tmp_path / "pack"
    z.extractall(out)
    result = subprocess.run(
        [sys.executable, "verify_bundle.py", "bundle.json"],
        cwd=out,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "transparency" in result.stdout

    # packdiff's offline surface reports the same proven-members note.
    from attest.packdiff import load_artifact

    pack_zip = tmp_path / "pack.zip"
    pack_zip.write_bytes(data)
    art = load_artifact(pack_zip)
    assert not art["verify_failures"], art["verify_failures"]
    assert any("transparency log" in n for n in art["notes"])


def test_checkpoint_pack_fails_on_missing_or_bad_proof(engine, store, household, schedule, t0, tmp_path):
    import json

    data, z = _visit_pack(engine, store, household, t0, tmp_path)
    original = json.loads(z.read("bundle.json"))["original"]

    def rewrite(transform):
        import io
        import zipfile

        src = zipfile.ZipFile(io.BytesIO(data))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as out:
            for n in src.namelist():
                out.writestr(n, transform(n, src.read(n)))
        return buf.getvalue()

    # A receipt never committed to the log: drop its inclusion proof.
    ph = original["payload_hash"]
    stripped = json.loads(z.read("log_checkpoint.json"))
    stripped["proofs"].pop(ph)
    forged = rewrite(lambda n, b: json.dumps(stripped).encode() if n == "log_checkpoint.json" else b)

    from attest.app import _verify_pack

    ok, detail = _verify_pack(forged, engine.signer.public_key_b64)
    assert not ok and "inclusion proof" in detail

    # A tampered path cannot reach the signed tree head.
    tampered = json.loads(z.read("log_checkpoint.json"))
    pr = tampered["proofs"][ph]
    pr["path"] = ["00" * 32] + pr["path"]
    forged2 = rewrite(lambda n, b: json.dumps(tampered).encode() if n == "log_checkpoint.json" else b)
    ok, detail = _verify_pack(forged2, engine.signer.public_key_b64)
    assert not ok and "tree head" in detail

    # A checkpoint signed by a foreign key is not this deployment's log.
    from attest.ledger import Signer

    foreign = json.loads(z.read("log_checkpoint.json"))
    foreign["checkpoint"] = (
        Signer.ephemeral()
        .issue(
            visit_id="log:foreign",
            sequence=1,
            prev_hash=None,
            facts={
                k: v
                for k, v in foreign["checkpoint"]["payload"].items()
                if k not in {"schema", "sequence", "prev_hash", "receipt_id", "issued_at", "visit_id"}
            },
        )
        .model_dump(mode="json")
    )
    forged3 = rewrite(lambda n, b: json.dumps(foreign).encode() if n == "log_checkpoint.json" else b)
    ok, detail = _verify_pack(forged3, engine.signer.public_key_b64)
    assert not ok and "trusted issuer chain" in detail
