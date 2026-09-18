import io
import json
import re
import subprocess
import sys
import zipfile
from datetime import timedelta
from pathlib import Path

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
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["original"]["payload"]["summary"] = "attendance confirmed"  # forged claim
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    result = _run(pack)
    assert result.returncode != 0
    assert "payload hash mismatch" in result.stderr


def test_pack_verifier_rejects_key_swap(pack):
    bundle_path = pack / "bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
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
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["reviews"][0]["revision"] = 7
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    result = _run(pack)
    assert result.returncode != 0
    assert "sequence or previous hash mismatch" in result.stderr


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
    assert result.stdout.count("OK   ") == 3  # 2 visits + the manifest line
    assert "2 visit records verified" in result.stdout
    assert "manifest: unsigned manifest" in result.stdout


def test_case_pack_verifier_rejects_manifest_tamper(case_pack):
    manifest_path = case_pack / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["visits"][0]["payload_hash"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = _run_case(case_pack)
    assert result.returncode != 0
    assert "manifest hash disagrees" in result.stdout


@pytest.fixture
def case_pack_signed(engine, store, household, schedule, t0, tmp_path):
    """Same two-visit pack, but the manifest is signed at export time."""
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
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        entries,
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    out = tmp_path / "case-signed"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    return out


def test_signed_manifest_verifies_in_embedded_verifier(case_pack_signed):
    result = _run_case(case_pack_signed)
    assert result.returncode == 0, result.stderr
    assert "manifest: export signed: 2 record(s)" in result.stdout


def test_signed_manifest_rejects_dropped_record(case_pack_signed):
    """Removing a visit entry rewrites the manifest — the content hash inside
    the signed export receipt must catch it even though every bundle is intact."""
    manifest_path = case_pack_signed / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["visits"].pop()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = _run_case(case_pack_signed)
    assert result.returncode != 0
    assert "manifest content hash mismatch" in result.stdout


def test_signed_manifest_rejects_swapped_hash(case_pack_signed):
    """Keeping the manifest text identical but swapping a listed hash breaks the
    visit list ↔ signed-export equality even though the content digest is the
    attacker's too — recompute it to isolate the hash-map check."""
    import hashlib
    import json as _json

    manifest_path = case_pack_signed / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["visits"][0]["payload_hash"] = "0" * 64
    sig = manifest["signature_receipt"]
    core = {k: v for k, v in manifest.items() if k != "signature_receipt"}
    canonical = _json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sig["payload"]["manifest_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    manifest_path.write_text(_json.dumps(manifest), encoding="utf-8")
    result = _run_case(case_pack_signed)
    assert result.returncode != 0
    assert "payload hash mismatch" in result.stdout or "disagrees" in result.stdout


@pytest.fixture
def case_pack_attested(engine, store, household, schedule, t0, tmp_path):
    """Pack built after coverage + digest attestations — they must travel."""
    service = ReviewService(store, engine.signer, engine.clock)
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = service.bundle(visit.id)
    site = store.sites()[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    engine.issue_period_digest(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    out = tmp_path / "case-attested"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    return out


def test_site_attestations_travel_in_case_pack(case_pack_attested):
    manifest = json.loads((case_pack_attested / "manifest.json").read_text(encoding="utf-8"))
    listed = manifest["attestations"]
    assert {a["record_type"] for a in listed} == {"coverage_attestation", "period_digest"}
    # The export's own receipt cannot reference itself — not listed, not present.
    assert not any(a["visit_id"].startswith("export:") for a in listed)
    for a in listed:
        att = json.loads(
            (case_pack_attested / "attestations" / f"{a['receipt_id']}.json").read_text(encoding="utf-8")
        )
        assert att["payload_hash"] == a["payload_hash"]
        assert att["visit_id"] == a["visit_id"]
    result = _run_case(case_pack_attested)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "OK   attestation coverage_attestation" in result.stdout
    assert "OK   attestation period_digest" in result.stdout


def test_case_pack_verifier_rejects_missing_attestation(case_pack_attested):
    manifest = json.loads((case_pack_attested / "manifest.json").read_text(encoding="utf-8"))
    rid = manifest["attestations"][0]["receipt_id"]
    (case_pack_attested / "attestations" / f"{rid}.json").unlink()
    result = _run_case(case_pack_attested)
    assert result.returncode != 0
    assert "file is missing" in result.stdout


def test_case_pack_verifier_rejects_tampered_attestation(case_pack_attested):
    manifest = json.loads((case_pack_attested / "manifest.json").read_text(encoding="utf-8"))
    rid = manifest["attestations"][0]["receipt_id"]
    apath = case_pack_attested / "attestations" / f"{rid}.json"
    att = json.loads(apath.read_text(encoding="utf-8"))
    att["payload"]["device_id"] = "attacker-device"
    apath.write_text(json.dumps(att), encoding="utf-8")
    result = _run_case(case_pack_attested)
    assert result.returncode != 0
    assert "payload hash mismatch" in result.stdout


def test_case_pack_verifier_rejects_unlisted_attestation(case_pack_attested):
    """An attestation file dropped into the pack that the signed manifest does
    not list must fail closed — otherwise anyone could smuggle 'proof'."""
    import shutil

    manifest = json.loads((case_pack_attested / "manifest.json").read_text(encoding="utf-8"))
    rid = manifest["attestations"][0]["receipt_id"]
    shutil.copy(
        case_pack_attested / "attestations" / f"{rid}.json",
        case_pack_attested / "attestations" / "smuggled.json",
    )
    result = _run_case(case_pack_attested)
    assert result.returncode != 0
    assert "not in the signed manifest" in result.stdout


def test_case_pack_index_inlines_attestations(case_pack_attested):
    html = (case_pack_attested / "index.html").read_text(encoding="utf-8")
    tags = re.findall(r'class="attestation" data-rid="([^"]+)">([A-Za-z0-9+/=]+)', html)
    manifest = json.loads((case_pack_attested / "manifest.json").read_text(encoding="utf-8"))
    assert {t[0] for t in tags} == {a["receipt_id"] for a in manifest["attestations"]}
    import base64

    for rid, b64 in tags:
        att = json.loads(base64.b64decode(b64).decode())
        assert att["id"] == rid


def test_case_verifier_parity_rejects_forged_entry(case_pack):
    """Parity with reviews.verify_bundle: an entry whose id/visit_id doesn't
    match its receipt fails, not just on revision/prev_hash."""
    manifest = json.loads((case_pack / "manifest.json").read_text(encoding="utf-8"))
    vid = manifest["visits"][0]["visit_id"]
    bundle_path = case_pack / "visits" / vid / "bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    if not bundle["reviews"]:
        pytest.skip("fixture has no review entries")
    bundle["reviews"][0]["id"] = "rcpt_forged"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    result = _run_case(case_pack)
    assert result.returncode != 0
    assert "identity does not match" in result.stdout


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
    assert json.loads((out / "manifest.json").read_text(encoding="utf-8"))["media_redacted"] is True
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
    marker = json.loads(redact_path.read_text(encoding="utf-8"))
    marker["withheld_digests"] = ["f" * 64]
    redact_path.write_text(json.dumps(marker), encoding="utf-8")
    result = _run_case(out)
    assert result.returncode != 0
    assert "not in the signed evidence" in result.stdout


def _lambda_deploy(tmp_path):
    """Stage a Lambda deployment dir: pinned verifiers + handler module."""
    import importlib.util
    import shutil

    import attest.disputepack as disputepack

    deploy = tmp_path / "lambda-deploy"
    deploy.mkdir()
    disputepack.write_verifiers(deploy)
    handler_src = Path(__file__).parents[1] / "extras" / "lambda" / "verify_lambda.py"
    shutil.copy(handler_src, deploy / "verify_lambda.py")
    spec = importlib.util.spec_from_file_location("verify_lambda", deploy / "verify_lambda.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _invoke(mod, zip_bytes):
    import base64

    event = {"body": base64.b64encode(zip_bytes).decode(), "isBase64Encoded": True}
    return json.loads(mod.handler(event, None)["body"])


def test_lambda_handler_verifies_case_pack(engine, store, household, schedule, t0, tmp_path):
    """The AWS Lambda entry point runs the pinned verifier — pack's own script
    is never executed — and returns the same verdict as the offline path."""
    service = ReviewService(store, engine.signer, engine.clock)
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = service.bundle(visit.id)
    site = store.sites()[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    mod = _lambda_deploy(tmp_path)
    body = _invoke(mod, data)
    assert body["ok"] is True, body["output"]
    assert "attestation coverage_attestation" in body["output"]

    # The same pack with one tampered bundle must fail closed in Lambda too.
    zin = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            content = zin.read(name)
            if name.endswith("/bundle.json"):
                forged = json.loads(content)
                forged["original"]["payload"]["summary"] = "attendance confirmed"
                content = json.dumps(forged).encode()
            zout.writestr(name, content)
    body = _invoke(mod, buf.getvalue())
    assert body["ok"] is False
    assert "payload hash mismatch" in body["output"]


def test_lambda_handler_verifies_single_pack(engine, store, household, schedule, t0, tmp_path):
    service = ReviewService(store, engine.signer, engine.clock)
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = service.bundle(visit.id)
    data = build_pack(store, tmp_path / "media", bundle)
    mod = _lambda_deploy(tmp_path)
    body = _invoke(mod, data)
    assert body["ok"] is True, body["output"]
    assert "receipt(s) verified" in body["output"]

    body = _invoke(mod, b"not a zip at all")
    assert body["ok"] is False
    assert "not a zip" in body["error"]
