import io
import json
import subprocess
import sys
import zipfile
from datetime import timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.disputepack import build_case_pack, build_pack
from attest.models import ReviewInput
from attest.reviews import ReviewService, countersign_status


@pytest.fixture
def pack(engine, store, household, schedule, t0, tmp_path):
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    service = ReviewService(store, engine.signer, engine.clock)
    service.coordinator_review(visit.id, ReviewInput(decision="confirm", statement="Looks right."))
    bundle = service.bundle(visit.id)
    data = build_pack(store, tmp_path / "media", bundle)
    out = tmp_path / "pack"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    return out


def _run(pack_dir, *args):
    return subprocess.run(
        [sys.executable, "verify_bundle.py", "bundle.json", *args],
        cwd=pack_dir,
        capture_output=True,
        text=True,
    )


def test_pack_verifies_offline_with_stdlib_only(pack):
    result = _run(pack)
    assert result.returncode == 0, result.stderr
    assert "2 receipt(s) verified" in result.stdout
    assert "media digests matched" in result.stdout


def test_pack_verifier_rejects_tampered_payload(pack):
    bundle_path = pack / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    bundle["original"]["payload"]["summary"] = "attendance confirmed"  # forged claim
    bundle_path.write_text(json.dumps(bundle))
    result = _run(pack)
    assert result.returncode != 0
    assert "payload hash mismatch" in result.stderr


def test_pack_verifier_rejects_key_swap(pack):
    bundle_path = pack / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    result = _run(pack, "--key", bundle["reviews"][0]["receipt"]["public_key"])
    assert result.returncode == 0
    # a foreign key must fail pinning even though the pack is self-consistent
    result = _run(pack, "--key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    assert result.returncode != 0
    assert "different key" in result.stderr


def test_pack_verifier_handles_nonascii_statement(engine, store, household, t0, tmp_path):
    """A signed statement containing non-ASCII text must verify offline — the
    verifier's read_text must pin UTF-8 or Windows' cp1252 default mojibakes the
    payload and the signature check fails on honest data."""
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    service = ReviewService(store, engine.signer, engine.clock)
    service.coordinator_review(
        visit.id,
        ReviewInput(decision="confirm", statement="Correct — María was there; noé problems."),
    )
    bundle = service.bundle(visit.id)
    data = build_pack(store, tmp_path / "media", bundle)
    out = tmp_path / "pack-utf8"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    result = _run(out)
    assert result.returncode == 0, result.stderr
    assert "receipt(s) verified" in result.stdout


def test_pack_verifier_rejects_broken_chain(pack):
    bundle_path = pack / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    bundle["reviews"][0]["revision"] = 7
    bundle_path.write_text(json.dumps(bundle))
    result = _run(pack)
    assert result.returncode != 0
    assert "chain" in result.stderr


@pytest.fixture
def case_pack(engine, store, household, schedule, t0, tmp_path):
    """Two closed visits for one site, packaged as a site-level case pack."""
    service = ReviewService(store, engine.signer, engine.clock)
    entries = []
    for offset in (0, 60):
        event = WebhookEvent.model_validate(
            webhooks.build_event(
                event_type="button_press",
                device_id=household[2].id,
                occurred_at=t0 + timedelta(minutes=offset),
            )
        )
        visit = engine.ingest(event).visit
        engine.close_for_review(visit.id)
        bundle = service.bundle(visit.id)
        entries.append((visit, bundle, countersign_status(bundle)))
    site = store.sites()[0]
    data = build_case_pack(store, tmp_path / "media", site, entries)
    out = tmp_path / "case"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    return out


def _run_case(pack_dir, *args):
    return subprocess.run(
        [sys.executable, "verify_case.py", *args],
        cwd=pack_dir,
        capture_output=True,
        text=True,
    )


def test_case_pack_verifies_offline_with_stdlib_only(case_pack):
    result = _run_case(case_pack)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("OK   ") == 2
    assert "2 visit records verified" in result.stdout


def test_case_pack_verifier_rejects_manifest_tamper(case_pack):
    manifest_path = case_pack / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["visits"][0]["payload_hash"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    result = _run_case(case_pack)
    assert result.returncode != 0
    assert "manifest hash disagrees" in result.stdout


def test_case_pack_redacted_media_verifies(engine, store, household, schedule, t0, tmp_path):
    """A redacted pack keeps signed digests but withholds bytes — the verifier
    reports them withheld instead of failing on missing files."""
    service = ReviewService(store, engine.signer, engine.clock)
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = service.bundle(visit.id)
    assert any(e.get("media_sha256") for e in bundle.original.payload["evidence"]), (
        "fixture should produce at least one media digest"
    )
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        redact_media=True,
    )
    out = tmp_path / "case-redacted"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    assert not (out / "visits" / visit.id / "media").exists()
    assert json.loads((out / "manifest.json").read_text())["media_redacted"] is True
    result = _run_case(out)
    assert result.returncode == 0, result.stderr
    assert "withheld" in result.stdout


def test_case_pack_verifier_rejects_bogus_redaction(engine, store, household, schedule, t0, tmp_path):
    """A redaction.json naming digests not in the signed evidence fails closed."""
    service = ReviewService(store, engine.signer, engine.clock)
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = service.bundle(visit.id)
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        redact_media=True,
    )
    out = tmp_path / "case-badredact"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    redact_path = out / "visits" / visit.id / "redaction.json"
    marker = json.loads(redact_path.read_text())
    marker["withheld_digests"] = ["f" * 64]
    redact_path.write_text(json.dumps(marker))
    result = _run_case(out)
    assert result.returncode != 0
    assert "not in the signed evidence" in result.stdout
