"""Signed key revocation — the incident-response counterpart to rotation.

A ``key_revocation`` receipt signed under the chain TIP declares a prior
issuer's post-``suspect_after`` signatures untrustworthy. It never erases:
records still verify, verifiers annotate the suspect window. Only the tip
can revoke, so a compromised key can't smear its successor.
"""

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest import ledger
from attest.disputepack import build_case_pack
from attest.ledger import Signer
from attest.reviews import ReviewService, countersign_status


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
    old_key = engine.signer.public_key_b64
    new_signer = new_signer or Signer.ephemeral()
    rotation = engine.issue_key_rotation(new_signer.public_key_b64, reason)
    engine.signer = new_signer
    adoption = engine.issue_key_adoption(old_key, rotation)
    return old_key, new_signer, rotation, adoption


def test_revocation_marks_suspect_window(engine, store, household, schedule, t0):
    """Rotate away from a compromised key, then revoke it: its signatures
    inside the declared window report as suspect — while the chain still
    verifies intact."""
    v1 = _closed_visit(engine, household, t0)
    r1 = store.receipt_for_visit(v1.id)
    old_key, new_signer, rotation, _ = _rotate(engine)
    v2 = _closed_visit(engine, household, t0, offset_min=90)
    r2 = store.receipt_for_visit(v2.id)

    suspect_after = r1.issued_at - timedelta(minutes=1)  # compromise began before v1
    rev = engine.issue_key_revocation(old_key, suspect_after, "seed phrase leaked")

    assert rev.public_key == new_signer.public_key_b64  # signed under the TIP
    assert rev.payload["record_type"] == "key_revocation"
    assert rev.payload["revoked_key"] == old_key

    receipts = store.receipts()
    ok, why = ledger.verify_chain(receipts)
    assert ok, why  # revocation never breaks the chain

    revoked = ledger.revoked_issuer_keys(receipts)
    assert revoked == {old_key: suspect_after.isoformat()}
    suspect = ledger.suspect_receipts(receipts, revoked=revoked)
    # everything the compromised key signed inside the window — the visit
    # receipt AND its own rotation endorsement — reports suspect
    assert {r.id for r in suspect} == {r1.id, rotation.id}
    assert r2 not in suspect


def test_revocation_window_boundary_is_strict(engine, store, household, schedule, t0):
    """Signatures BEFORE the suspect window stay clean — revocation bounds
    the damage, it doesn't blanket-condemn the key."""
    v1 = _closed_visit(engine, household, t0)
    r1 = store.receipt_for_visit(v1.id)
    old_key, _, _, _ = _rotate(engine)
    engine.issue_key_revocation(old_key, r1.issued_at + timedelta(minutes=1))
    assert ledger.suspect_receipts(store.receipts()) == []


def test_revocation_idempotent_reissue(engine, store, household, schedule, t0):
    """Re-issuing the same revocation returns the existing receipt — the
    append-only ledger never writes a second one."""
    _closed_visit(engine, household, t0)
    old_key, _, _, _ = _rotate(engine)
    when = engine.clock.now()
    first = engine.issue_key_revocation(old_key, when)
    second = engine.issue_key_revocation(old_key, when, "different reason")
    assert first.id == second.id
    assert first.payload_hash == second.payload_hash


def test_a_compromised_key_cannot_smear_its_successor(engine, store, household, schedule, t0):
    """Only the tip revokes: a forged revocation signed by the RETIRED key
    (the classic "compromised key kills the healthy successor" move) is
    ignored by the trust overlay."""
    _closed_visit(engine, household, t0)
    old_signer = engine.signer
    _, new_signer, _, _ = _rotate(engine)

    forged = old_signer.issue(
        visit_id="key:forged-revocation",
        sequence=99,
        prev_hash=None,
        facts={
            "record_type": "key_revocation",
            "revoked_key": new_signer.public_key_b64,
            "suspect_after": datetime.now(tz=UTC).isoformat(),
        },
    )
    assert ledger.revoked_issuer_keys(store.receipts() + [forged]) == {}


def test_revocation_refuses_self_and_foreign_keys(engine, store, household, schedule, t0):
    _closed_visit(engine, household, t0)
    current = engine.signer.public_key_b64
    with pytest.raises(ValueError, match="cannot revoke itself"):
        engine.issue_key_revocation(current, engine.clock.now())
    with pytest.raises(ValueError, match="never signed"):
        engine.issue_key_revocation(Signer.ephemeral().public_key_b64, engine.clock.now())


def test_cli_revoke_key_end_to_end(tmp_path, monkeypatch):
    """`attest revoke-key` after `attest rotate-key`: the revocation receipt
    lands, the journal stays intact, and `attest explain` renders it."""
    from attest import cli
    from attest.config import Settings
    from attest.store import Store

    monkeypatch.setattr(
        cli,
        "settings",
        Settings(data_dir=tmp_path, admin_token="t" * 40, ring_webhook_key="k"),
    )
    Store(tmp_path / "attest.sqlite3").close()
    cli.main(["rotate-key"])
    store = Store(tmp_path / "attest.sqlite3")
    retired = next(
        r.payload["previous_key"] for r in store.receipts() if r.payload.get("record_type") == "key_rotation"
    )
    store.close()
    cli.main(["revoke-key", retired, "--reason", "laptop stolen"])
    store = Store(tmp_path / "attest.sqlite3")
    rev = next(r for r in store.receipts() if r.payload.get("record_type") == "key_revocation")
    assert rev.payload["revoked_key"] == retired
    ok, why = ledger.verify_chain(store.receipts())
    assert ok, why
    store.close()
    cli.main(["journal"])  # must not raise — the chain survives the annotation
    cli.main(["explain", rev.visit_id])  # renders the revocation in human terms


def test_cli_revoke_key_without_history_fails(tmp_path, monkeypatch, capsys):
    """`attest revoke-key` on a key that never signed this chain exits 1 —
    revocation only has meaning inside this deployment's lineage."""
    from attest import cli
    from attest.config import Settings
    from attest.store import Store

    monkeypatch.setattr(
        cli,
        "settings",
        Settings(data_dir=tmp_path, admin_token="t" * 40, ring_webhook_key="k"),
    )
    Store(tmp_path / "attest.sqlite3").close()
    cli.main(["rotate-key"])  # mint a real chain so a store+signer exists
    with pytest.raises(SystemExit) as exc:
        cli.main(["revoke-key", Signer.ephemeral().public_key_b64])
    assert "never signed" in str(exc.value.code)


def test_revocation_annotates_pack_verification(engine, store, household, schedule, t0, tmp_path):
    """A post-revocation case pack still verifies — and reports how many
    records carry the suspect-window annotation."""
    v1 = _closed_visit(engine, household, t0)
    old_key, new_signer, _, _ = _rotate(engine)
    suspect_after = store.receipt_for_visit(v1.id).issued_at - timedelta(minutes=1)
    engine.issue_key_revocation(old_key, suspect_after, "compromise")
    service = ReviewService(store, new_signer, engine.clock)
    site = store.sites()[0]
    entries = [(v1, service.bundle(v1.id), countersign_status(service.bundle(v1.id)))]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        entries,
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        issuer_key=new_signer.public_key_b64,
    )
    pack_dir = tmp_path / "pack"
    zipfile.ZipFile(io.BytesIO(data)).extractall(pack_dir)

    # the revocation rides with the pack's key:* attestations
    atts = [json.loads(p.read_text()) for p in (pack_dir / "attestations").glob("*.json")]
    assert any(a["payload"].get("record_type") == "key_revocation" for a in atts)

    from attest.app import _verify_case_pack

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        ok, detail = _verify_case_pack(z, new_signer.public_key_b64)
    assert ok, detail
    assert "suspect window" in detail
