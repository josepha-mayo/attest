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


def test_diff_names_the_field_changed_under_an_intact_envelope(exports, tmp_path):
    """The classic forgery keeps the signed envelope — payload_hash field
    stays — and rewrites the payload bytes. The diff must name the moved
    field, not just report a changed hash."""
    first, second, v1, _ = exports
    zin = zipfile.ZipFile(second)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for name in zin.namelist():
            data = zin.read(name)
            if name == f"visits/{v1}/bundle.json":
                b = json.loads(data)
                b["original"]["payload"]["observed_span_minutes"] = 999.5
                data = json.dumps(b)
            zout.writestr(name, data)
    forged = second.with_name("forged3.zip")
    forged.write_bytes(buf.getvalue())
    lines, anomalies = diff(first, forged)
    assert anomalies >= 1
    named = [line for line in lines if "observed_span_minutes" in line]
    assert named, lines
    assert any("identical" in line and "envelope" in line for line in named)


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


def test_diff_html_report_matches_the_same_event_stream(exports, tmp_path, capsys):
    """--html renders the same events the text report prints — one
    verification pass, two renderings. The page stamps ANOMALIES on a
    tampered pack and names the moved field; a clean pair stamps honest."""
    import argparse

    from attest import cli
    from attest.packdiff import diff_report

    first, second, v1, v2 = exports
    out = tmp_path / "diff.html"

    # Clean pair: exit 0, page stamps no-difference drift honestly.
    cli._diff(
        argparse.Namespace(
            old=str(first),
            new=str(second),
            key=None,
            issuer_url=None,
            json=False,
            html=str(out),
        )
    )
    page = out.read_text(encoding="utf-8")
    assert "APPEND-ONLY DRIFT" in page  # v2 is a new visit in the second pack
    assert "ANOMALIES" not in page
    assert v1 in page and v2 in page
    assert "attest diff" in page  # the re-derive note rides the footer

    # Tampered pack: the page names the field, text+page share one stream,
    # and the anomaly still drives exit 1 for CI.
    zin = zipfile.ZipFile(second)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for name in zin.namelist():
            data = zin.read(name)
            if name == f"visits/{v1}/bundle.json":
                b = json.loads(data)
                b["original"]["payload"]["observed_span_minutes"] = 999.5
                data = json.dumps(b)
            zout.writestr(name, data)
    forged = second.with_name("forged-html.zip")
    forged.write_bytes(buf.getvalue())

    with pytest.raises(SystemExit) as se:
        cli._diff(
            argparse.Namespace(
                old=str(first),
                new=str(forged),
                key=None,
                issuer_url=None,
                json=False,
                html=str(out),
            )
        )
    assert se.value.code == 1
    page = out.read_text(encoding="utf-8")
    assert "ANOMALIES DETECTED" in page
    assert "observed_span_minutes" in page
    # Text output and the HTML name the same event stream — `line` fields.
    report = diff_report(first, forged)
    assert all("line" in e for e in report["events"])
    captured = capsys.readouterr()
    assert "observed_span_minutes" in captured.out


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


def _case_with_log(engine, store, tmp_path, site, service, entries):
    """_case with the transparency member attached — each call issues a
    fresh signed checkpoint, so consecutive exports carry adjacent heads."""
    from attest.disputepack import log_member

    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(v, service.bundle(v.id), countersign_status(service.bundle(v.id))) for v in entries],
        log_fn=lambda rs, pack_members=None: log_member(engine, rs, pack_members=pack_members),
    )
    out = tmp_path / f"case-{len(list(tmp_path.glob('case-*.zip')))}.zip"
    out.write_bytes(data)
    return out


def _rewrite_member(pack, member, new_bytes, tmp_path):
    """Return a copy of `pack` with one zip member's bytes swapped."""
    import zipfile as _zf

    out = tmp_path / f"rewritten-{len(list(tmp_path.glob('rewritten-*.zip')))}.zip"
    with _zf.ZipFile(pack) as zin, _zf.ZipFile(out, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            zout.writestr(info.filename, new_bytes if info.filename == member else data)
    return out


def _head(pack):
    import zipfile as _zf

    with _zf.ZipFile(pack) as z:
        doc = json.loads(z.read("log_checkpoint.json"))
    return doc["checkpoint"]["payload"]["tree_size"], doc


def test_diff_bridges_adjacent_log_heads(engine, store, household, schedule, t0, tmp_path):
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    first = _case_with_log(engine, store, tmp_path, site, service, [v1])
    v2 = _visit(engine, household, t0, offset=90)
    second = _case_with_log(engine, store, tmp_path, site, service, [v1, v2])

    s1, _ = _head(first)
    s2, _ = _head(second)
    assert s2 > s1

    lines, anomalies = diff(first, second)
    text = "\n".join(lines)
    assert anomalies == 0, text
    assert f"the size-{s2} head provably extends the size-{s1} head" in text, text

    # Reversed direction is NOT symmetric: the newer export pinning an
    # earlier head is the rollback signature (an old signed head replayed)
    # or simply an older export — reported as drift, never a clean append.
    lines, anomalies = diff(second, first)
    text = "\n".join(lines)
    assert f"EARLIER signed head (size {s1} < {s2})" in text, text


def _forge_same_size(pack, engine, store, tmp_path):
    """Rebuild a pack's log_checkpoint.json as a self-consistent FORKED
    history at the same tree size: the pack's proven receipts sit inside a
    fabricated leaf arrangement whose root differs from the honest head —
    every inclusion proof still verifies under a validly-issuer-signed
    checkpoint. This is exactly what a deployment serving per-victim
    histories would hand out."""
    import zipfile as _zf

    from attest.transparency import inclusion_path
    from attest.transparency import root as _troot

    with _zf.ZipFile(pack) as z:
        doc = json.loads(z.read("log_checkpoint.json"))
    size = int(doc["checkpoint"]["payload"]["tree_size"])
    leaves = [bytes.fromhex(h) for h in sorted(doc["proofs"])]
    assert len(leaves) <= size
    leaves += [b"\xf0" * 32] * (size - len(leaves))
    if _troot(leaves).hex() == doc["checkpoint"]["payload"]["root_sha256"]:
        leaves = leaves[::-1]  # same leaves, alternative order → different root
    assert _troot(leaves).hex() != doc["checkpoint"]["payload"]["root_sha256"]
    doc["proofs"] = {
        h: {
            "leaf_index": leaves.index(bytes.fromhex(h)),
            "path": [p.hex() for p in inclusion_path(leaves, leaves.index(bytes.fromhex(h)))],
        }
        for h in sorted(doc["proofs"])
    }
    prev = store.latest_receipt()
    doc["checkpoint"] = engine.signer.issue(
        visit_id=f"log-fork:{size}",
        sequence=prev.sequence + 1,
        prev_hash=prev.payload_hash,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": size,
            "root_sha256": _troot(leaves).hex(),
            "journal_head": store.journal_head(),
        },
    ).model_dump(mode="json")
    return _rewrite_member(pack, "log_checkpoint.json", json.dumps(doc).encode(), tmp_path)


def test_diff_flags_a_same_size_different_root_log_fork(engine, store, household, schedule, t0, tmp_path):
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    v2 = _visit(engine, household, t0, offset=90)
    second = _case_with_log(engine, store, tmp_path, site, service, [v1, v2])
    # An unchanged leaf set re-checkpoints to the identical head — a pack
    # taken "at the same time" is a byte-identical signed view.
    twin = _case_with_log(engine, store, tmp_path, site, service, [v1, v2])
    size, _ = _head(second)
    size2, _ = _head(twin)
    assert size == size2

    forked = _forge_same_size(second, engine, store, tmp_path)
    lines, anomalies = diff(forked, twin)
    text = "\n".join(lines)
    assert anomalies >= 1, text
    assert f"size-{size} log heads with DIFFERENT roots" in text
    assert "provable fork" in text


def test_diff_reports_same_head_and_unbridged_gap(engine, store, household, schedule, t0, tmp_path):
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    first = _case_with_log(engine, store, tmp_path, site, service, [v1])

    # A pack diffed against itself: identical signed heads.
    lines, anomalies = diff(first, first)
    text = "\n".join(lines)
    assert anomalies == 0, text
    assert "both exports commit to the same signed log head" in text

    # A checkpoint issued between the exports breaks ADJACENCY — the newer
    # head's own bridge names THAT head, not the first pack's — but the
    # second export's embedded signed chain covers the gap hop-by-hop, so
    # the reconcile still proves append-only, offline. The intermediate
    # checkpoint must cover a GROWN tree (unchanged heads are idempotent),
    # and the tree must grow again after it so the export's checkpoint is
    # a distinct, non-adjacent head.
    v2 = _visit(engine, household, t0, offset=90)
    engine.issue_log_checkpoint()
    v3 = _visit(engine, household, t0, offset=180)
    third = _case_with_log(engine, store, tmp_path, site, service, [v1, v2, v3])
    lines, anomalies = diff(first, third)
    text = "\n".join(lines)
    assert anomalies == 0, text
    assert "signed checkpoint hop(s) verified" in text, text


def test_diff_reports_unbridged_gap_when_chain_cannot_reach(engine, store, household, schedule, t0, tmp_path):
    """A pack whose embedded chain does not reach the older head stays
    honestly undecidable — strip the newer pack's `chain` member and the
    reconcile falls back to 'no bridge', never a guess."""
    import zipfile as _zf

    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    first = _case_with_log(engine, store, tmp_path, site, service, [v1])
    v2 = _visit(engine, household, t0, offset=90)
    engine.issue_log_checkpoint()
    v3 = _visit(engine, household, t0, offset=180)
    third = _case_with_log(engine, store, tmp_path, site, service, [v1, v2, v3])

    with _zf.ZipFile(third) as z:
        doc = json.loads(z.read("log_checkpoint.json"))
    assert doc.get("chain"), "export should embed prior signed heads"
    del doc["chain"]
    stripped = _rewrite_member(third, "log_checkpoint.json", json.dumps(doc).encode(), tmp_path)

    lines, anomalies = diff(first, stripped)
    text = "\n".join(lines)
    assert anomalies == 0, text
    assert "no bridge or chain" in text or "no embedded bridge" in text, text


def test_diff_chain_collision_is_a_provable_fork(engine, store, household, schedule, t0, tmp_path):
    """A chain member occupying the OLDER pack's head size under a different
    signed root is two issuer-signed heads at one tree size — the walk must
    report a provable fork, not quietly pass over it."""
    import zipfile as _zf

    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    first = _case_with_log(engine, store, tmp_path, site, service, [v1])
    s1, _ = _head(first)

    v2 = _visit(engine, household, t0, offset=90)
    second = _case_with_log(engine, store, tmp_path, site, service, [v1, v2])

    # Forge a signed checkpoint receipt AT the older head's size under a
    # different root — the issuer's real key signs it, so it passes the
    # pack's own chain validation and reaches the reconcile.
    from attest.transparency import root as _troot

    prev = store.latest_receipt()
    forged = engine.signer.issue(
        visit_id=f"log-fork:{s1}",
        sequence=prev.sequence + 1,
        prev_hash=prev.payload_hash,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": s1,
            "root_sha256": _troot([b"\xab" * 32]).hex(),
            "journal_head": store.journal_head(),
        },
    ).model_dump(mode="json")

    with _zf.ZipFile(second) as z:
        doc = json.loads(z.read("log_checkpoint.json"))
    chain = doc.get("chain") or []
    # Replace the honest member at s1 (the walk's target) so the pack still
    # verifies — the fork lives inside the signed evidence itself.
    doc["chain"] = [forged] + [m for m in chain if m["payload"].get("tree_size") != s1]
    forked = _rewrite_member(second, "log_checkpoint.json", json.dumps(doc).encode(), tmp_path)

    lines, anomalies = diff(first, forked)
    text = "\n".join(lines)
    assert anomalies >= 1, text
    assert "provable fork" in text and "two issuer-signed heads at one tree size" in text, text


def test_check_log_rejects_foreign_and_dup_size_chain_members(
    engine, store, household, schedule, t0, tmp_path
):
    """Chain members are validated like embedded evidence receipts minus the
    leaf proof — a foreign signer's member, or two signed roots at one tree
    size inside one document, fail the pack closed."""
    import zipfile as _zf

    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    _case_with_log(engine, store, tmp_path, site, service, [v1])
    v2 = _visit(engine, household, t0, offset=90)
    pack = _case_with_log(engine, store, tmp_path, site, service, [v1, v2])

    from attest.packdiff import check_log_pin

    with _zf.ZipFile(pack) as z:
        doc = json.loads(z.read("log_checkpoint.json"))
        member_ids = []
        for n in z.namelist():
            if n.startswith("attestations/"):
                att = json.loads(z.read(n))
                member_ids.append((att["id"], att["payload_hash"], att["public_key"]))
    assert doc.get("chain"), "export should embed prior signed heads"
    trusted = {doc["checkpoint"]["public_key"]}

    def run(d):
        raw = json.dumps(d).encode()
        return check_log_pin(
            lambda n: raw if n == "log_checkpoint.json" else None,
            member_ids,
            trusted,
            check_members=False,
        )

    res, err = run(doc)
    assert err is None and res is not None, err

    bad = json.loads(json.dumps(doc))
    bad["chain"][0]["public_key"] = "AA" * 32
    res2, err2 = run(bad)
    assert res2 is None and "outside the issuer lineage" in err2

    # The second root at one size must be VALIDLY signed — a mutated copy
    # dies at the signature check long before the dedup rule reads it.
    dup = json.loads(json.dumps(doc))
    s0 = dup["chain"][0]["payload"]["tree_size"]
    prev = store.latest_receipt()
    forged = engine.signer.issue(
        visit_id=f"log-fork:{s0}",
        sequence=prev.sequence + 1,
        prev_hash=prev.payload_hash,
        facts={
            "record_type": "log_checkpoint",
            "tree_size": s0,
            "root_sha256": "ab" * 32,
            "journal_head": store.journal_head(),
        },
    ).model_dump(mode="json")
    dup["chain"].append(forged)
    res3, err3 = run(dup)
    assert res3 is None and "two signed heads" in err3, err3


def test_pack_members_rejects_undeclared_member(engine, store, household, schedule, t0, tmp_path):
    """The member list binds both directions: a file riding the zip that the
    signed export never declared is smuggled — inert or not, it is not what
    the deployment signed."""
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    pack = _case_with_log(engine, store, tmp_path, site, service, [v1])

    from attest.packdiff import check_log_pin

    with zipfile.ZipFile(pack) as z:
        doc = json.loads(z.read("log_checkpoint.json"))
        names = set(z.namelist())
        member_ids = []
        for n in names:
            if n.startswith("attestations/"):
                att = json.loads(z.read(n))
                member_ids.append((att["id"], att["payload_hash"], att["public_key"]))
    trusted = {doc["checkpoint"]["public_key"]}
    raw = json.dumps(doc).encode()

    def reader(n):
        if n == "log_checkpoint.json":
            return raw
        return b"x" if n in names else None

    res, err = check_log_pin(reader, member_ids, trusted, actual_members=list(names))
    assert err is None and res is not None, err

    res, err = check_log_pin(
        reader,
        member_ids,
        trusted,
        actual_members=list(names) + ["attestations/smuggled.json"],
    )
    assert res is None and "never declared" in err, err


def test_diff_notes_when_only_one_export_carries_a_checkpoint(
    engine, store, household, schedule, t0, tmp_path
):
    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    with_log = _case_with_log(engine, store, tmp_path, site, service, [v1])
    without = _case(store, tmp_path, site, service, [v1])

    lines, anomalies = diff(without, with_log)
    text = "\n".join(lines)
    assert "only the new export carries a transparency checkpoint" in text


def test_diff_chain_quoted_bridge_first_still_walks(engine, store, household, schedule, t0, tmp_path):
    """Parity fix: a member whose signed `extends.first` is spelled as a
    digit STRING coerces on every surface (verify_extends/_extOk accept it),
    so the multi-hop walk must follow it too — a strict isinstance gate
    would dead-end Python where the browser still walks. The signed member
    is real: the issuer's key signs the quoted spelling itself."""
    import zipfile as _zf

    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    first = _case_with_log(engine, store, tmp_path, site, service, [v1])
    v2 = _visit(engine, household, t0, offset=90)
    engine.issue_log_checkpoint()
    v3 = _visit(engine, household, t0, offset=180)
    third = _case_with_log(engine, store, tmp_path, site, service, [v1, v2, v3])

    with _zf.ZipFile(third) as z:
        doc = json.loads(z.read("log_checkpoint.json"))
    # The walk only visits the member the HEAD's bridge names — respell the
    # `extends.first` of exactly that member (the mid-walk hop) as a string
    # and have the issuer sign the respelled payload.
    head_ext = doc["checkpoint"]["payload"].get("extends") or {}
    hop_size = head_ext.get("first")
    target = next((m for m in doc["chain"] if m["payload"].get("tree_size") == hop_size), None)
    assert target is not None, "expected the head's bridge target to ride in the chain"
    payload = {
        k: v
        for k, v in json.loads(json.dumps(target["payload"])).items()
        if k not in ("schema", "sequence", "prev_hash", "receipt_id", "issued_at", "visit_id")
    }
    payload["extends"]["first"] = str(payload["extends"]["first"])
    prev = store.latest_receipt()
    respelled = engine.signer.issue(
        visit_id=f"log-quoted:{payload['tree_size']}",
        sequence=prev.sequence + 1,
        prev_hash=prev.payload_hash,
        facts=payload,
    ).model_dump(mode="json")
    doc["chain"] = [m for m in doc["chain"] if m["payload"].get("tree_size") != payload["tree_size"]] + [
        respelled
    ]
    quoted = _rewrite_member(third, "log_checkpoint.json", json.dumps(doc).encode(), tmp_path)

    lines, anomalies = diff(first, quoted)
    text = "\n".join(lines)
    assert anomalies == 0, text
    assert "signed checkpoint hop(s) verified" in text, text


def test_check_log_rejects_nonhex_and_accepts_case_variant_roots(
    engine, store, household, schedule, t0, tmp_path
):
    """Parity fixes: a member root must decode to 32 bytes — a 64-char
    NON-HEX spelling passed the old len()==64 gate and diverged (Python
    walked past it as undecidable, the browser convicted a fork). And two
    members at one size whose roots differ only in hex CASE are the same
    bytes — same head, not a collision."""
    import zipfile as _zf

    service = ReviewService(store, engine.signer, engine.clock)
    site = store.sites()[0]
    v1 = _visit(engine, household, t0)
    engine.issue_log_checkpoint()  # a PRIOR checkpoint must exist for `chain`
    v2 = _visit(engine, household, t0, offset=90)
    pack = _case_with_log(engine, store, tmp_path, site, service, [v1, v2])

    from attest.packdiff import check_log_pin

    with _zf.ZipFile(pack) as z:
        doc = json.loads(z.read("log_checkpoint.json"))
        member_ids = []
        for n in z.namelist():
            if n.startswith("attestations/"):
                att = json.loads(z.read(n))
                member_ids.append((att["id"], att["payload_hash"], att["public_key"]))
    assert doc.get("chain"), "export should embed prior signed heads"
    trusted = {doc["checkpoint"]["public_key"]}

    def run(d):
        raw = json.dumps(d).encode()
        return check_log_pin(
            lambda n: raw if n == "log_checkpoint.json" else None,
            member_ids,
            trusted,
            check_members=False,
        )

    def signed_member(facts):
        prev = store.latest_receipt()
        return engine.signer.issue(
            visit_id=f"log-variant:{facts['tree_size']}:{len(facts['root_sha256'])}",
            sequence=prev.sequence + 1,
            prev_hash=prev.payload_hash,
            facts=facts,
        ).model_dump(mode="json")

    # 64 chars but not hex — the strictest spelling (the browser's regex)
    # wins everywhere now: fail closed at intake.
    base = doc["chain"][0]["payload"]
    badhex = dict(doc)
    badhex["chain"] = [
        signed_member(
            {
                "record_type": "log_checkpoint",
                "tree_size": base["tree_size"],
                "root_sha256": "zz" * 32,
                "journal_head": store.journal_head(),
            }
        )
    ]
    res, err = run(badhex)
    assert res is None and "malformed or non-prior head" in err, err

    # Same bytes, upper-case spelling — one head, not two.
    upper = dict(doc)
    member = signed_member(
        {
            "record_type": "log_checkpoint",
            "tree_size": base["tree_size"],
            "root_sha256": base["root_sha256"].upper(),
            "journal_head": store.journal_head(),
        }
    )
    upper["chain"] = [m for m in doc["chain"]] + [member]
    res2, err2 = run(upper)
    assert err2 is None and res2 is not None, err2
