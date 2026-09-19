import io
import json
import zipfile
from datetime import timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.disputepack import build_case_pack
from attest.models import ReviewInput
from attest.packdiff import diff
from attest.reviews import ReviewService, countersign_status


def _visit(engine, household, t0, offset=0):
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0 + timedelta(minutes=offset),
        )
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    return visit


def _case(store, tmp_path, site, service, entries):
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(v, service.bundle(v.id), countersign_status(service.bundle(v.id))) for v in entries],
    )
    out = tmp_path / f"case-{len(list(tmp_path.glob('case-*.zip')))}.zip"
    out.write_bytes(data)
    return out


@pytest.fixture
def exports(engine, store, household, schedule, t0, tmp_path):
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    first = _case(store, tmp_path, site, service, [v1])
    v2 = _visit(engine, household, t0, offset=90)
    service.coordinator_review(v1.id, ReviewInput(decision="confirm", statement="Verified."))
    second = _case(store, tmp_path, site, service, [v1, v2])
    return first, second, v1.id, v2.id


def test_diff_reports_append_only_drift(exports):
    first, second, v1, v2 = exports
    lines, anomalies = diff(first, second)
    assert anomalies == 0, lines
    text = "\n".join(lines)
    assert f"+  {v2}: new visit" in text
    assert f"~  {v1}: +1 appended review receipt(s)" in text
    assert "clean" in text


def test_diff_flags_a_vanished_record(exports):
    first, second, v1, _ = exports
    # tamper: drop v1 from the newer pack's manifest
    zin = zipfile.ZipFile(second)
    manifest = json.loads(zin.read("manifest.json"))
    manifest["visits"] = [v for v in manifest["visits"] if v["visit_id"] != v1]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for name in zin.namelist():
            if name != "manifest.json":
                zout.writestr(name, zin.read(name))
        zout.writestr("manifest.json", json.dumps(manifest))
    forged = second.with_name("forged.zip")
    forged.write_bytes(buf.getvalue())
    lines, anomalies = diff(first, forged)
    assert anomalies >= 1
    assert any("absent now" in line for line in lines)


def test_diff_reports_new_attestation_and_flags_a_vanished_one(
    engine, store, household, schedule, t0, tmp_path
):
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    first = _case(store, tmp_path, site, service, [v1])
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    second = _case(store, tmp_path, site, service, [v1])

    lines, anomalies = diff(first, second)
    text = "\n".join(lines)
    assert anomalies == 0, lines
    assert "+  attestation coverage_attestation" in text

    # tamper: drop the attestation from a third pack's manifest — the previous
    # export listed it, so its absence is an anomaly, not drift.
    third = _case(store, tmp_path, site, service, [v1])
    zin = zipfile.ZipFile(third)
    manifest = json.loads(zin.read("manifest.json"))
    assert manifest["attestations"]  # the export carries it
    manifest["attestations"] = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for name in zin.namelist():
            if name != "manifest.json":
                zout.writestr(name, zin.read(name))
        zout.writestr("manifest.json", json.dumps(manifest))
    forged = third.with_name("forged-att.zip")
    forged.write_bytes(buf.getvalue())
    lines, anomalies = diff(second, forged)
    assert anomalies >= 1
    assert any("absent now" in line and "attestation" in line for line in lines)


def test_diff_flags_an_altered_signed_record(exports, tmp_path):
    first, second, v1, _ = exports
    # tamper: same visit id, different payload hash inside the newer pack
    zin = zipfile.ZipFile(second)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for name in zin.namelist():
            data = zin.read(name)
            if name == f"visits/{v1}/bundle.json":
                b = json.loads(data)
                b["original"]["payload_hash"] = "0" * 64
                data = json.dumps(b)
            zout.writestr(name, data)
    forged = second.with_name("forged2.zip")
    forged.write_bytes(buf.getvalue())
    lines, anomalies = diff(first, forged)
    assert anomalies >= 1
    assert any("cannot change" in line for line in lines)


def _repack(zin, out_path, mutate=None, drop=frozenset()):
    """Rewrite a case pack, optionally mutating manifest.json before re-zipping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for name in zin.namelist():
            if name in drop:
                continue
            data = zin.read(name)
            if name == "manifest.json" and mutate:
                data = json.dumps(mutate(json.loads(data)))
            zout.writestr(name, data)
    out_path.write_bytes(buf.getvalue())
    return out_path


def test_diff_flags_a_manifest_claim_lying_about_the_bundle(exports, tmp_path):
    """The manifest's listed payload_hash must match the bundle it ships —
    otherwise the unsigned summary can quietly contradict the signed record."""
    first, second, v1, _ = exports
    zin = zipfile.ZipFile(second)

    def lie(m):
        m["signature_receipt"] = None  # don't trip the content-hash check first
        for v in m["visits"]:
            if v["visit_id"] == v1:
                v["payload_hash"] = "f" * 64
        return m

    forged = _repack(zin, second.with_name("forged-claim.zip"), mutate=lie)
    lines, anomalies = diff(first, forged)
    assert anomalies >= 1
    assert any("manifest claims" in line for line in lines)


def test_diff_flags_a_duplicate_manifest_entry(exports, tmp_path):
    first, second, v1, _ = exports
    zin = zipfile.ZipFile(second)

    def dup(m):
        m["signature_receipt"] = None
        m["visits"] = m["visits"] + [dict(m["visits"][0])]
        return m

    forged = _repack(zin, second.with_name("forged-dup.zip"), mutate=dup)
    lines, anomalies = diff(first, forged)
    assert anomalies >= 1
    assert any("listed twice" in line for line in lines)


def test_diff_notes_an_unsigned_manifest(exports, tmp_path):
    first, second, _, _ = exports
    zin = zipfile.ZipFile(second)
    forged = _repack(
        zin,
        second.with_name("unsigned.zip"),
        mutate=lambda m: {**m, "signature_receipt": None},
    )
    lines, _ = diff(first, forged)
    assert any("unsigned manifest" in line for line in lines)


def test_diff_verify_pins_the_supplied_key(exports, tmp_path):
    """--key must not trust the pack's self-declared issuer — a wrong pin fails."""
    first, second, _, _ = exports
    lines, anomalies = diff(first, second, key="A" * 43 + "=")
    assert anomalies >= 1
    assert any("fails verification" in line for line in lines)
