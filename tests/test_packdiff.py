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


def test_diff_pins_to_an_issuer_document(engine, store, household, schedule, t0, tmp_path):
    """--issuer-url parity: exports spanning a rotation verify under the
    deployment's CURRENT issuer when the discovery doc's signed lifecycle
    receipts supply the lineage — and fail without them."""
    from attest import ledger
    from attest.ledger import Signer

    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    first = _case(store, tmp_path, site, service, [v1])

    old_key = engine.signer.public_key_b64
    new_signer = Signer.ephemeral()
    rotation = engine.issue_key_rotation(new_signer.public_key_b64, "")
    engine.signer = new_signer
    engine.issue_key_adoption(old_key, rotation)

    v2 = _visit(engine, household, t0, offset=90)
    second = _case(store, tmp_path, site, service, [v1, v2])

    doc = ledger.issuer_document(new_signer.public_key_b64, store.receipts())
    known = [ledger.Receipt.model_validate(r) for r in doc["key_receipts"]]

    # Pinned to the current issuer alone, the pre-rotation export fails — the
    # old key is outside the trust set without the lifecycle link.
    lines, anomalies = diff(first, second, key=doc["issuer_key"])
    assert anomalies >= 1
    assert any("fails verification" in line for line in lines)

    # With the issuer document's receipts the lineage bridges both directions.
    lines, anomalies = diff(first, second, key=doc["issuer_key"], extra_key_receipts=known)
    assert anomalies == 0, lines
    assert any("pinned issuer" in line for line in lines)


def test_diff_json_report_is_structured_and_consistent(exports, tmp_path, capsys):
    """--json output carries the same verdict as the text report — both are
    built from one event stream so they can never disagree."""
    import argparse
    import json as _json

    from attest import cli
    from attest.packdiff import diff_report

    first, second, v1, v2 = exports
    report = diff_report(first, second)
    assert report["clean"] is True and report["anomalies"] == 0
    assert report["old"]["verified"] and report["new"]["verified"]
    assert report["old"]["kind"] == report["new"]["kind"] == "case-pack"
    kinds = {e["severity"] for e in report["events"]}
    assert {"ok", "info", "drift"} <= kinds
    assert any(e.get("target") == v2 for e in report["events"])

    # A clean diff exits 0 and prints parseable JSON — the CI-gate contract.
    with pytest.raises(SystemExit) as se:
        cli._diff(argparse.Namespace(old=str(first), new=str(second), key=None, issuer_url=None, json=True))
    assert se.value.code == 0
    out = _json.loads(capsys.readouterr().out)
    assert out["clean"] is True

    # Reversed order: v2 was present before and absent now — a real anomaly.
    with pytest.raises(SystemExit) as se:
        cli._diff(argparse.Namespace(old=str(second), new=str(first), key=None, issuer_url=None, json=True))
    assert se.value.code == 1
    out = _json.loads(capsys.readouterr().out)
    assert out["clean"] is False and out["anomalies"] >= 1
    assert any(e["severity"] == "anomaly" and e.get("target") == v2 for e in out["events"])


def test_diff_json_with_issuer_url_keeps_stdout_parseable(exports, tmp_path, capsys):
    """--json + --issuer-url: the human pin note must ride on stderr — a CI
    gate piping stdout into a JSON parser gets the report, not prose."""
    import argparse
    import json as _json

    from attest import cli

    first, second, _v1, _v2 = exports
    issuer = _json.loads(zipfile.ZipFile(first).read("manifest.json"))["issuer_key"]
    doc = tmp_path / "issuer.json"
    doc.write_text(_json.dumps({"schema": "attest.issuer/1", "issuer_key": issuer, "key_receipts": []}))
    with pytest.raises(SystemExit) as se:
        cli._diff(
            argparse.Namespace(old=str(first), new=str(second), key=None, issuer_url=str(doc), json=True)
        )
    assert se.value.code == 0
    captured = capsys.readouterr()
    report = _json.loads(captured.out)  # any prose on stdout raises here
    assert report["clean"] is True
    assert report["pin"] == {
        "issuer_key": issuer,
        "issuer_url": str(doc),
        "lifecycle_receipts": 0,
    }
    assert "pinned to issuer key" in captured.err


def test_diff_rejects_forward_signed_member(tmp_path):
    """Parity guard: a case pack whose manifest declares K1 but lists a
    forward-linked K2 attestation must fail — membership is ancestors-of-
    declared on every surface; descendants only bridge the pin itself."""
    import json as _json

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from attest.ledger import Signer, issuer_document
    from attest.models import Receipt
    from attest.packdiff import load_artifact

    k1 = Signer(Ed25519PrivateKey.from_private_bytes(b"\x11" * 32))
    k2 = Signer(Ed25519PrivateKey.from_private_bytes(b"\x22" * 32))
    rot = k1.issue(
        visit_id="key:rot",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "key_rotation",
            "previous_key": k1.public_key_b64,
            "new_key": k2.public_key_b64,
        },
    )
    adopt = k2.issue(
        visit_id="key:adopt",
        sequence=2,
        prev_hash=rot.payload_hash,
        facts={
            "record_type": "key_adoption",
            "previous_key": k1.public_key_b64,
            "rotation_receipt": {"id": rot.id, "hash": rot.payload_hash},
        },
    )
    att = k2.issue(
        visit_id="site:att",
        sequence=3,
        prev_hash=adopt.payload_hash,
        facts={"record_type": "coverage_certificate"},
    )
    manifest = {
        "schema": "attest.case-pack/1",
        "issuer_key": k1.public_key_b64,
        "visits": [],
        "attestations": [
            {
                "receipt_id": att.id,
                "visit_id": att.visit_id,
                "payload_hash": att.payload_hash,
                "record_type": "coverage_certificate",
            }
        ],
    }
    pack = tmp_path / "crafted.zip"
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("manifest.json", _json.dumps(manifest))
        z.writestr(f"attestations/{att.id}.json", _json.dumps(att.model_dump(mode="json")))
    doc = issuer_document(k2.public_key_b64, [rot, adopt])
    known = [Receipt.model_validate(r) for r in doc["key_receipts"]]

    art = load_artifact(pack, key=doc["issuer_key"], extra_key_receipts=known)
    # The pin itself links (K2 IS the doc's issuer) — the failure is
    # membership: K2 is a descendant of the declared issuer, not an ancestor.
    assert not any("lifecycle link" in f for f in art["verify_failures"])
    assert any("outside the rotation chain" in f for f in art["verify_failures"])
