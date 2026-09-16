import io
import json
import subprocess
import sys
import zipfile

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.disputepack import build_pack
from attest.models import ReviewInput
from attest.reviews import ReviewService


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
    assert "original + 1 reviews verified" in result.stdout
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


def test_pack_verifier_rejects_broken_chain(pack):
    bundle_path = pack / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    bundle["reviews"][0]["revision"] = 7
    bundle_path.write_text(json.dumps(bundle))
    result = _run(pack)
    assert result.returncode != 0
    assert "chain" in result.stderr
