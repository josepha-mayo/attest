"""Signed key rotation — the chain's trust pivot end to end.

A ``key_rotation`` receipt signed by the retiring key endorses its successor:
verify_chain reads it as a pivot, packs carry it as an attestation, and every
verifier (app, embedded Python, JS) derives the trusted issuer set from the
pinned key plus the signed links — never from a key that merely shows up.
"""

import io
import json
import subprocess
import sys
import zipfile
from datetime import timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest import ledger
from attest.disputepack import build_case_pack, build_pack
from attest.keycustody import load_or_create_signer, persist_signer_key
from attest.ledger import Signer
from attest.models import ReviewInput
from attest.reviews import ReviewService, countersign_status, verify_bundle


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


def _rotate(engine, new_signer=None, reason=""):
    """The deployment rotation flow: retire under the current key, persist the
    successor (here: swap the in-memory signer), countersign the adoption."""
    old_key = engine.signer.public_key_b64
    new_signer = new_signer or Signer.ephemeral()
    rotation = engine.issue_key_rotation(new_signer.public_key_b64, reason)
    engine.signer = new_signer
    adoption = engine.issue_key_adoption(old_key, rotation)
    return old_key, new_signer, rotation, adoption


def test_chain_pivots_at_rotation(engine, store, household, schedule, t0):
    _closed_visit(engine, household, t0)
    old_key, _, _, _ = _rotate(engine, reason="annual")
    # a receipt issued under the NEW key after the pivot
    site = store.sites()[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    receipts = store.receipts()
    keys = {r.public_key for r in receipts}
    assert keys == {old_key, engine.signer.public_key_b64}
    ok, why = ledger.verify_chain(receipts)
    assert ok, why
    # pinning either the retired OR the current key validates the whole chain —
    # the rotation receipt links them in the pinned direction
    assert ledger.verify_chain(receipts, public_key=old_key)[0]
    assert ledger.verify_chain(receipts, public_key=engine.signer.public_key_b64)[0]


def test_chain_rejects_foreign_pinned_key(engine, store, household, schedule, t0):
    _closed_visit(engine, household, t0)
    _rotate(engine)
    receipts = store.receipts()
    foreign = Signer.ephemeral().public_key_b64
    ok, why = ledger.verify_chain(receipts, public_key=foreign)
    assert not ok
    assert "does not descend" in why


def test_retired_key_receipt_after_pivot_breaks_chain(engine, store, household, schedule, t0):
    """A receipt signed under the RETIRED key after the pivot is exactly the
    anomaly rotation exists to catch — the chain must not accept it."""
    _closed_visit(engine, household, t0)
    old_signer = engine.signer
    _rotate(engine)
    site = store.sites()[0]
    # forge: the retired key issues a new receipt as if rotation never happened
    prev = store.latest_receipt()
    forged = old_signer.issue(
        visit_id=f"coverage:{site.id}:forged",
        sequence=prev.sequence + 1,
        prev_hash=prev.payload_hash,
        facts={"record_type": "coverage_attestation", "forged": True},
    )
    ok, why = ledger.verify_chain(store.receipts() + [forged])
    assert not ok
    assert "different key" in why or "signature invalid" in why


def test_forged_rotation_endorsement_never_pivots(engine, store, household, schedule, t0):
    """A rotation receipt can only pivot if the RETIRING key signed it — an
    unrelated key claiming 'A endorsed me' has no pivot power."""
    _closed_visit(engine, household, t0)
    old_key = engine.signer.public_key_b64
    foreign = Signer.ephemeral()
    prev = store.latest_receipt()
    forged = foreign.issue(
        visit_id="key:forged",
        sequence=prev.sequence + 1,
        prev_hash=prev.payload_hash,
        facts={
            "record_type": "key_rotation",
            "previous_key": old_key,
            "new_key": foreign.public_key_b64,
        },
    )
    assert ledger._rotation_hop(store.receipts() + [forged], foreign.public_key_b64) is None
    assert ledger._rotation_hop(store.receipts() + [forged], old_key) is None


def test_review_bundle_spans_rotation(engine, store, household, schedule, t0):
    """A review appended after the rotation signs under the successor — the
    bundle verifies through the signed pivot, not despite it."""
    visit = _closed_visit(engine, household, t0)
    old_key, new_signer, rotation, _ = _rotate(engine)
    service = ReviewService(store, new_signer, engine.clock)
    service.coordinator_review(visit.id, ReviewInput(decision="confirm", statement="post-rotation"))
    bundle = service.bundle(visit.id)
    assert bundle.reviews[0].receipt.public_key == new_signer.public_key_b64
    rotations = [r for r in store.receipts() if r.visit_id.startswith("key:")]
    trusted = ledger.trusted_issuer_keys(
        new_signer.public_key_b64, rotations
    ) | ledger.descendant_issuer_keys(old_key, rotations)
    ok, why = verify_bundle(bundle, trusted_keys=trusted)
    assert ok, why


def test_pinned_single_key_rejects_mixed_bundle(engine, store, household, schedule, t0):
    visit = _closed_visit(engine, household, t0)
    old_key, new_signer, _, _ = _rotate(engine)
    service = ReviewService(store, new_signer, engine.clock)
    service.coordinator_review(visit.id, ReviewInput(decision="confirm", statement="post-rotation"))
    bundle = service.bundle(visit.id)
    ok, why = verify_bundle(bundle, public_key=old_key)
    assert not ok
    assert "different key" in why


@pytest.fixture
def rotated_pack(engine, store, household, schedule, t0, tmp_path):
    v1 = _closed_visit(engine, household, t0)
    old_key, new_signer, rotation, adoption = _rotate(engine)
    v2 = _closed_visit(engine, household, t0, offset_min=90)
    # a review on the pre-rotation visit appended post-rotation, under B
    service_b = ReviewService(store, new_signer, engine.clock)
    service_b.coordinator_review(v1.id, ReviewInput(decision="confirm", statement="post-rotation"))
    site = store.sites()[0]
    entries = [(v, service_b.bundle(v.id), countersign_status(service_b.bundle(v.id))) for v in (v1, v2)]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        entries,
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        issuer_key=new_signer.public_key_b64,
    )
    out = tmp_path / "case-rotated"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    return out, data, old_key, new_signer.public_key_b64


def _run_case(pack_dir, *args):
    return subprocess.run(
        [sys.executable, "verify_case.py", *args],
        cwd=pack_dir,
        capture_output=True,
        text=True,
    )


def test_case_pack_rotation_receipts_travel(rotated_pack):
    out, *_ = rotated_pack
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    types = {a["record_type"] for a in manifest["attestations"]}
    assert "key_rotation" in types
    assert "key_adoption" in types


def test_case_pack_verifies_with_retired_pin(rotated_pack):
    """Pinning the PRE-rotation key still verifies: the pack's signed rotation
    receipts link it forward to the manifest's issuer."""
    out, data, old_key, new_key = rotated_pack
    from attest.app import _verify_pack

    ok, why = _verify_pack(data, old_key)
    assert ok, why
    result = _run_case(out, "--key", old_key)
    assert result.returncode == 0, result.stdout + result.stderr


def test_case_pack_verifies_with_current_pin(rotated_pack):
    out, data, _, new_key = rotated_pack
    from attest.app import _verify_pack

    ok, why = _verify_pack(data, new_key)
    assert ok, why
    result = _run_case(out, "--key", new_key)
    assert result.returncode == 0, result.stdout + result.stderr


def test_case_pack_rejects_unrelated_pin(rotated_pack):
    """A key that merely appears in the pack — or nowhere — never bootstraps
    trust. Only the pinned key and its signed rotation chain count."""
    out, data, *_ = rotated_pack
    from attest.app import _verify_pack

    foreign = Signer.ephemeral().public_key_b64
    ok, why = _verify_pack(data, foreign)
    assert not ok
    assert "key_rotation" in why or "issuer" in why
    result = _run_case(out, "--key", foreign)
    assert result.returncode != 0


def test_case_pack_rejects_tampered_rotation(rotated_pack):
    """Retype the endorsement: a key_rotation whose new_key is edited no longer
    links the chain — packs must fail, not fall back to single-key luck."""
    out, *_ = rotated_pack
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    rot = next(a for a in manifest["attestations"] if a["record_type"] == "key_rotation")
    apath = out / "attestations" / f"{rot['receipt_id']}.json"
    att = json.loads(apath.read_text(encoding="utf-8"))
    att["payload"]["new_key"] = Signer.ephemeral().public_key_b64
    apath.write_text(json.dumps(att), encoding="utf-8")
    result = _run_case(out)
    assert result.returncode != 0


def test_dispute_pack_rotation_links(engine, store, household, schedule, t0, tmp_path):
    """A review appended after rotation signs under the successor; the dispute
    pack's key_rotations.json is the signed link the verifier walks."""
    visit = _closed_visit(engine, household, t0)
    old_key, new_signer, _, _ = _rotate(engine)
    service = ReviewService(store, new_signer, engine.clock)
    service.coordinator_review(visit.id, ReviewInput(decision="confirm", statement="post-rotation"))
    bundle = service.bundle(visit.id)
    data = build_pack(store, tmp_path / "media", bundle)
    z = zipfile.ZipFile(io.BytesIO(data))
    assert "key_rotations.json" in z.namelist()
    kr = json.loads(z.read("key_rotations.json"))
    assert kr["schema"] == "attest.key-rotations/1"
    assert any(r["payload"].get("record_type") == "key_rotation" for r in kr["rotations"])
    out = tmp_path / "pack-rotated"
    z.extractall(out)
    result = subprocess.run(
        [sys.executable, "verify_bundle.py", "bundle.json"],
        cwd=out,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    # drop the rotation links — the mixed-key bundle must now FAIL closed,
    # not quietly fall back to the original's key
    (out / "key_rotations.json").unlink()
    result = subprocess.run(
        [sys.executable, "verify_bundle.py", "bundle.json"],
        cwd=out,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "trusted issuer chain" in result.stderr


def _new_pem():
    """Fresh Ed25519 key material, returned as (signer, PEM bytes)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return Signer(sk), pem


def test_persist_signer_key_atomic_plaintext(tmp_path):
    key_path = tmp_path / "attest-ed25519.key"
    old = load_or_create_signer(key_path)
    new_signer, pem = _new_pem()
    persist_signer_key(key_path, pem)
    reloaded = load_or_create_signer(key_path)
    assert reloaded.public_key_b64 == new_signer.public_key_b64
    assert reloaded.public_key_b64 != old.public_key_b64


def test_persist_signer_key_under_kms(tmp_path):
    """The successor lands under the same custody posture — wrapped, never
    plaintext — and unwraps back to the new identity."""

    class FakeKms:
        def generate_data_key(self, KeyId, KeySpec, EncryptionContext):
            return {"Plaintext": b"\x22" * 32, "CiphertextBlob": b"blob:" + b"\x22" * 32}

        def decrypt(self, CiphertextBlob, EncryptionContext):
            return {"Plaintext": CiphertextBlob[5:], "KeyId": "k"}

    key_path = tmp_path / "attest-ed25519.key"
    old = load_or_create_signer(key_path, kms_key_id="k", kms_client=FakeKms())
    new_signer, pem = _new_pem()
    persist_signer_key(key_path, pem, kms_key_id="k", kms_client=FakeKms())
    wrapped = tmp_path / "attest-ed25519.key.kms.json"
    assert wrapped.exists()
    assert not key_path.exists()
    assert b"PRIVATE KEY" not in wrapped.read_bytes()
    reloaded = load_or_create_signer(key_path, kms_key_id="k", kms_client=FakeKms())
    assert reloaded.public_key_b64 == new_signer.public_key_b64
    assert reloaded.public_key_b64 != old.public_key_b64


def test_cli_rotate_key_end_to_end(tmp_path, monkeypatch):
    """`attest rotate-key` twice = a 3-key chain; the journal still verifies
    intact because the rotation receipts are the pivots."""
    from attest import cli
    from attest.config import Settings
    from attest.store import Store

    monkeypatch.setattr(
        cli,
        "settings",
        Settings(data_dir=tmp_path, admin_token="t" * 40, ring_webhook_key="k"),
    )
    Store(tmp_path / "attest.sqlite3").close()  # the store must exist
    cli.main(["rotate-key", "--reason", "annual"])
    cli.main(["rotate-key"])
    store = Store(tmp_path / "attest.sqlite3")
    receipts = store.receipts()
    assert len({r.public_key for r in receipts}) == 3
    ok, why = ledger.verify_chain(receipts)
    assert ok, why
    store.close()
    cli.main(["journal"])  # must not raise — the pivots keep history intact


def test_grafted_predecessor_never_enters_trust(engine, store, household, schedule, t0):
    """Endorsement is self-serve: an attacker key can sign "I retire into the
    deployment's issuer" — without the successor's key_adoption countersigning
    that exact rotation, the graft must not extend the trusted issuer set."""
    _closed_visit(engine, household, t0)
    issuer = engine.signer.public_key_b64
    attacker = Signer.ephemeral()
    graft = attacker.issue(
        visit_id=f"key:{attacker.public_key_b64[:12]}:{issuer[:12]}",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "key_rotation",
            "previous_key": attacker.public_key_b64,
            "new_key": issuer,
        },
    )
    pool = store.receipts() + [graft]
    assert ledger._rotation_hop(pool, issuer) is None
    assert ledger.trusted_issuer_keys(issuer, pool) == {issuer}


def test_forged_chain_cannot_pin_to_victim_key():
    """A wholly attacker-written chain ending in a 'mine -> victim' rotation
    must not satisfy a pin to the victim's key — the victim's own signature on
    a key_adoption is the only proof the handoff was consented to."""
    attacker = Signer.ephemeral()
    victim = Signer.ephemeral()
    r1 = attacker.issue(
        visit_id="attacker-visit",
        sequence=1,
        prev_hash=None,
        facts={"record_type": "visit_closed", "forged": True},
    )
    graft = attacker.issue(
        visit_id=f"key:{attacker.public_key_b64[:12]}:{victim.public_key_b64[:12]}",
        sequence=2,
        prev_hash=r1.payload_hash,
        facts={
            "record_type": "key_rotation",
            "previous_key": attacker.public_key_b64,
            "new_key": victim.public_key_b64,
        },
    )
    ok, why = ledger.verify_chain([r1, graft], public_key=victim.public_key_b64)
    assert not ok
    assert "does not descend" in why


def test_adoption_without_rotation_endorsement_is_no_hop(engine, store, household, schedule, t0):
    """Consent without endorsement is also no hop: an adoption signed by the
    issuer naming a rotation the 'predecessor' never signed cannot graft
    ancestry either direction."""
    _closed_visit(engine, household, t0)
    issuer = engine.signer.public_key_b64
    attacker = Signer.ephemeral()
    fake_rotation = attacker.issue(
        visit_id="key:never-signed",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "key_rotation",
            "previous_key": issuer,
            "new_key": attacker.public_key_b64,
        },
    )
    adoption = engine.signer.issue(
        visit_id=f"key:{issuer[:12]}:{attacker.public_key_b64[:12]}:adopted",
        sequence=2,
        prev_hash=None,
        facts={
            "record_type": "key_adoption",
            "previous_key": issuer,
            "rotation_receipt": {"id": fake_rotation.id, "hash": fake_rotation.payload_hash},
        },
    )
    pool = store.receipts() + [fake_rotation, adoption]
    # the 'rotation' was signed under the attacker key while CLAIMING the
    # issuer retired — r.public_key != previous_key, so no forward hop either
    assert ledger.descendant_issuer_keys(issuer, pool) == {issuer}
    assert ledger.trusted_issuer_keys(attacker.public_key_b64, pool) == {attacker.public_key_b64}
