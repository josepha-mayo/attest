import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.models import VisitState, utcnow
from attest.poller import HistoryPoller


def event(cam, at, kind="motion_detected", account="ava1.ring.account.SANDBOX"):
    return WebhookEvent.model_validate(
        webhooks.build_event(
            event_type=kind,
            device_id=cam.id,
            occurred_at=at,
            sub_type="human" if kind == "motion_detected" else None,
            account_id=account,
        )
    )


def test_failed_ingest_can_retry_without_partial_visit(engine, store, household, schedule, t0, monkeypatch):
    cam = household[2]
    ev = event(cam, t0)
    original = store.put_evidence
    with monkeypatch.context() as patch:
        patch.setattr(store, "put_evidence", lambda _: (_ for _ in ()).throw(RuntimeError("disk failure")))
        with pytest.raises(RuntimeError):
            engine.ingest(ev)
    assert store.visits() == []
    assert engine.ingest(ev).transitions == ["opened"]
    assert len(store.visits()) == 1
    assert original is not None


def test_concurrent_arrivals_create_one_active_visit(engine, store, household, schedule, t0):
    cam = household[2]
    events = [event(cam, t0 + timedelta(seconds=i)) for i in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(engine.ingest, events))
    assert len(store.visits()) == 1


def test_account_mismatch_cannot_attach_to_site(engine, store, household, schedule, t0):
    result = engine.ingest(event(household[2], t0, account="different-account"))
    assert result.ignored_reason == "account mismatch"
    assert store.visits() == []


def test_schedule_is_not_identity(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    assert visit.worker_id is None
    assert visit.schedule_id == schedule.id


def test_sensor_pattern_does_not_prove_departure_or_work(engine, store, household, schedule, t0):
    _, _, cam, sensor = household
    engine.ingest(event(cam, t0))
    engine.ingest(event(sensor, t0 + timedelta(minutes=12), "contact_sensor_faulted"))
    engine.ingest(event(sensor, t0 + timedelta(minutes=12, seconds=5), "contact_sensor_cleared"))
    visit = engine.ingest(event(cam, t0 + timedelta(minutes=12, seconds=10))).visit
    assert visit.state == VisitState.CLOSED
    assert visit.departed_at is None
    assert visit.duration_minutes is None
    receipt = store.receipt_for_visit(visit.id)
    assert receipt.payload["assessment"]["identity_verified"] is False
    assert receipt.payload["assessment"]["time_worked_minutes"] is None
    assert "Maria Chen arrived" not in visit.summary
    assert "stayed" not in visit.summary


def test_missing_observations_do_not_certify_no_show(engine, store, household, schedule, t0):
    (visit,) = engine.sweep(t0 + timedelta(hours=3))
    assert visit.state.value == "no_observation"
    assert visit.duration_minutes is None
    receipt = store.receipt_for_visit(visit.id)
    assert receipt.payload["first_observed_at"] is None
    assert receipt.payload["assessment"]["attendance"] == "unknown"


def test_single_cue_event_can_be_archived_without_inventing_departure(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    visit.last_seen_at = utcnow() - timedelta(minutes=25)
    store.put_visit(visit)
    (closed,) = engine.sweep()
    assert closed.departed_at is None
    assert closed.duration_minutes is None


def test_clock_conflict_is_flagged_not_clean(engine, store, household, schedule, t0):
    _, _, cam, sensor = household
    engine.ingest(event(cam, t0))
    engine.check_in(engine.issue_checkin(store.active_visit(household[0].id).id), at=utcnow())
    engine.ingest(event(sensor, t0 + timedelta(minutes=90), "contact_sensor_faulted"))
    engine.ingest(event(sensor, t0 + timedelta(minutes=90, seconds=5), "contact_sensor_cleared"))
    visit = engine.ingest(event(cam, t0 + timedelta(minutes=90, seconds=10))).visit
    assert "clock_conflict" in {f.code for f in visit.flags}
    assert "No discrepancies" not in visit.summary


def test_poller_orders_across_event_types(engine, store, household, schedule, ring_client, ring_control, t0):
    cam = household[2]
    for kind, seconds in [("button_press", 0), ("motion_detected", 10)]:
        ring_control.post(
            "/_sandbox/events",
            json={
                "device_id": cam.id,
                "type": kind,
                "sub_type": "human" if seconds else None,
                "at": (t0 + timedelta(seconds=seconds)).isoformat(),
                "deliver": False,
            },
        ).raise_for_status()
    HistoryPoller(engine, store, ring_client, lookback=timedelta(days=2)).poll_once()
    visit = store.active_visit(household[0].id)
    assert visit.arrived_at == t0


def test_receipt_insert_never_overwrites_existing_receipt(engine, store, household, schedule, t0):
    (visit,) = engine.sweep(t0 + timedelta(hours=3))
    receipt = store.receipt_for_visit(visit.id)
    replacement = receipt.model_copy(update={"payload": {"forged": True}})
    with pytest.raises(sqlite3.IntegrityError):
        store.put_receipt(replacement)
    assert store.receipt(receipt.id).payload == receipt.payload


def test_checkin_grant_is_hashed_scoped_expiring_and_single_use(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    token = engine.issue_checkin(visit.id)
    grant = store.checkin_grant(hashlib.sha256(token.encode()).hexdigest())
    assert grant.id == visit.id and token not in grant.model_dump_json()
    replacement = engine.issue_checkin(visit.id)
    assert engine.check_in(token) is None
    assert engine.check_in(replacement) is not None
    assert engine.check_in(replacement) is None


def test_expired_grant_is_rejected(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    token = engine.issue_checkin(visit.id)
    grant = store.checkin_grant(hashlib.sha256(token.encode()).hexdigest())
    grant.expires_at = utcnow() - timedelta(seconds=1)
    store.put_checkin_grant(grant)
    assert engine.check_in(token) is None


def test_duplicate_checkin_is_atomic(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    token = engine.issue_checkin(visit.id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(engine.check_in, [token, token]))
    assert sum(v is not None for v in results) == 1


def test_bedrock_fallback_provenance_is_explicit(engine, store, household, schedule, t0):
    from attest.summarize import BedrockSummarizer

    summarizer = BedrockSummarizer("test-model", "us-east-1")
    summarizer._client_factory = lambda: (_ for _ in ()).throw(RuntimeError("unavailable"))
    engine.summarizer = summarizer
    visit = engine.ingest(event(household[2], t0)).visit
    visit.last_seen_at = utcnow() - timedelta(minutes=25)
    store.put_visit(visit)
    (closed,) = engine.sweep()
    provenance = store.receipt_for_visit(closed.id).payload["summary_provenance"]
    assert provenance["source"] == "template"
    assert provenance["fallback_reason"] == "RuntimeError"
    assert provenance["model"] is None


def test_source_switch_requires_reconciliation(engine, store, household, schedule, t0):
    ev = event(household[2], t0)
    engine.ingest(ev)
    result = engine.ingest(event(household[2], t0), source="history")
    assert result.ignored_reason == "ingestion source changed; reconciliation required"
    assert len(store.visits()) == 1


def test_late_events_are_retained_without_rewriting_signed_records(engine, store, household, schedule, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    visit.last_seen_at = utcnow() - timedelta(minutes=25)
    store.put_visit(visit)
    engine.sweep()
    before = store.receipts()[0].model_dump_json()
    outcome = engine.ingest(event(household[2], t0 - timedelta(seconds=1)))
    assert outcome.ignored_reason == "late event retained for review"
    assert len(store.late_events()) == 1
    assert store.receipts()[0].model_dump_json() == before
    assert len(store.visits()) == 1


def test_media_read_stays_within_root_and_relative_save_roundtrips(tmp_path, monkeypatch):
    from attest.media import MediaStore

    monkeypatch.chdir(tmp_path)
    media = MediaStore(__import__("pathlib").Path("media"))
    sha, path = media.save("vis_test", "arrival", b"test", "image/png")
    assert media.verify(path, sha)
    assert media.read(tmp_path / "outside.txt") is None
    with pytest.raises(ValueError):
        media.save("../escape", "arrival", b"test", "image/png")


def test_cli_verify_accepts_zip_packs(tmp_path):
    """`attest verify pack.zip` runs the same pack checks as the /verify page —
    no manual unzip, no pointing at embedded scripts. A corrupt zip fails
    cleanly rather than tracebacking."""
    import subprocess
    import sys

    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK" + b"0" * 20)
    rc = subprocess.run(
        [sys.executable, "-m", "attest.cli", "verify", str(bad)],
        capture_output=True,
        text=True,
    )
    assert rc.returncode != 0
    assert "Traceback" not in rc.stderr
    out = rc.stdout + rc.stderr
    assert "not a valid zip" in out or "could not read" in out


def test_cli_verify_real_pack(tmp_path, engine, store, household, schedule, t0):
    """End-to-end: export a case pack and `attest verify` it by path."""
    import subprocess
    import sys
    import zipfile
    from io import BytesIO

    from attest.disputepack import build_case_pack
    from attest.reviews import ReviewService, countersign_status

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    pack = tmp_path / "case.zip"
    pack.write_bytes(data)
    assert "manifest.json" in zipfile.ZipFile(BytesIO(data)).namelist()
    rc = subprocess.run(
        [sys.executable, "-m", "attest.cli", "verify", str(pack)],
        capture_output=True,
        text=True,
    )
    assert rc.returncode == 0, rc.stderr + rc.stdout
    assert "case pack verified" in rc.stdout


def test_verify_attest_signs_the_verdict_into_the_journal(tmp_path, engine, store, household, schedule, t0):
    """`attest verify pack.zip --attest` — the mediator's audit act is itself
    evidence: a `pack_verification` receipt binds sha256(pack bytes), the
    verdict, and the verifier's content identity under the AUDITING
    deployment's issuer key. FAIL verdicts sign too — a forged pack attested
    as forged is evidence. Idempotent per (pack, verifier identity)."""
    import subprocess
    import sys

    from attest.disputepack import build_case_pack, tamper_twin
    from attest.reviews import ReviewService, countersign_status
    from attest.store import Store

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    pack = tmp_path / "case.zip"
    pack.write_bytes(data)

    audit = tmp_path / "auditor"
    audit.mkdir()
    Store(audit / "attest.sqlite3").close()  # initialized store the CLI can open
    import os

    env = {**os.environ, "ATTEST_DATA_DIR": str(audit)}

    def run(*argv):
        return subprocess.run(
            [sys.executable, "-m", "attest.cli", *argv],
            capture_output=True,
            text=True,
            env=env,
        )

    rc = run("verify", "--attest", str(pack))
    assert rc.returncode == 0, rc.stderr + rc.stdout
    assert "Attestation rcpt_" in rc.stdout

    audit_store = Store(audit / "attest.sqlite3")
    att = [r for r in audit_store.receipts() if r.payload.get("record_type") == "pack_verification"]
    assert len(att) == 1
    facts = att[0].payload
    assert facts["verdict"] == "ok"
    assert facts["pack_sha256"] == hashlib.sha256(data).hexdigest()
    assert facts["pack_bytes"] == len(data)
    assert facts["verifier"]["name"] == "attest-cli"
    assert len(facts["verifier"]["verifier_sha256"]) == 64
    assert att[0].visit_id.startswith("pack-verify:")

    # A doctored twin attests as forged — exit 1, but the FAIL receipt lands.
    forged = tmp_path / "forged.zip"
    forged_bytes, _attack = tamper_twin(data)
    forged.write_bytes(forged_bytes)
    rc = run("verify", "--attest", str(forged))
    assert rc.returncode == 1, rc.stderr + rc.stdout
    audit_store = Store(audit / "attest.sqlite3")
    att = [r for r in audit_store.receipts() if r.payload.get("record_type") == "pack_verification"]
    assert len(att) == 2
    fail_att = next(r for r in att if r.payload["verdict"] == "fail")
    assert fail_att.payload["pack_sha256"] == hashlib.sha256(forged_bytes).hexdigest()
    assert fail_att.payload["pack_bytes"] == len(forged_bytes)
    assert fail_att.payload["detail"]

    # Re-attesting the same bytes under the same verifier is idempotent —
    # the audit trail records the act once, not once per run.
    rc = run("verify", "--attest", str(pack))
    assert rc.returncode == 0
    audit_store = Store(audit / "attest.sqlite3")
    att = [r for r in audit_store.receipts() if r.payload.get("record_type") == "pack_verification"]
    assert len(att) == 2

    # --attest on a non-pack input rejects loudly instead of silently skipping.
    bare = tmp_path / "receipts.json"
    bare.write_text("[]")
    rc = run("verify", "--attest", str(bare))
    assert rc.returncode != 0
    assert "--attest" in (rc.stdout + rc.stderr)

    # The verdict's trust context keys the attestation — the same bytes
    # re-verified under a different pin and reaching the OPPOSITE verdict
    # must mint a new receipt, never reuse the "ok" one.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from attest.ledger import Signer

    foreign = Signer(Ed25519PrivateKey.from_private_bytes(b"\xee" * 32)).public_key_b64
    rc = run("verify", "--attest", "--key", foreign, str(pack))
    assert rc.returncode == 1, rc.stderr + rc.stdout
    audit_store = Store(audit / "attest.sqlite3")
    att = [r for r in audit_store.receipts() if r.payload.get("record_type") == "pack_verification"]
    verdicts = {(r.payload["pack_sha256"], r.payload["verdict"]) for r in att}
    assert (hashlib.sha256(data).hexdigest(), "fail") in verdicts
    fail_att = next(
        r
        for r in att
        if r.payload["verdict"] == "fail" and r.payload["pack_sha256"] == hashlib.sha256(data).hexdigest()
    )
    assert fail_att.payload["context"]["issuer_pin"] == foreign

    # --json stays machine-pure with --attest — the attestation note rides
    # stderr so a CI gate parses stdout alone.
    import json as _json

    rc = run("verify", "--json", "--attest", str(forged))
    assert rc.returncode == 1
    verdict = _json.loads(rc.stdout)
    assert verdict["ok"] is False
    assert "Attestation rcpt_" in rc.stderr


def test_diff_attest_signs_the_comparison(tmp_path, engine, store, household, schedule, t0):
    """`attest diff --attest` — the mediator's reconciliation is evidence: a
    `pack_comparison` receipt binds BOTH pack digests, the machine verdict
    (log_heads + anomaly count), and a hash of the event stream. An anomalous
    comparison attests as anomalous — a caught forgery is the deliverable."""
    import os
    import subprocess
    import sys

    from attest.disputepack import build_case_pack, tamper_twin
    from attest.reviews import ReviewService, countersign_status
    from attest.store import Store

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    pack = tmp_path / "case.zip"
    pack.write_bytes(data)
    forged_bytes, _ = tamper_twin(data)
    forged = tmp_path / "forged.zip"
    forged.write_bytes(forged_bytes)

    audit = tmp_path / "auditor"
    audit.mkdir()
    Store(audit / "attest.sqlite3").close()
    env = {**os.environ, "ATTEST_DATA_DIR": str(audit)}

    def run(*argv):
        return subprocess.run(
            [sys.executable, "-m", "attest.cli", *argv],
            capture_output=True,
            text=True,
            env=env,
        )

    # A clean comparison attests — the anomalous one is the deliverable.
    rc = run("diff", str(pack), str(forged), "--attest")
    assert rc.returncode == 1  # anomalies → exit 1
    assert "Attestation rcpt_" in rc.stderr

    audit_store = Store(audit / "attest.sqlite3")
    att = [r for r in audit_store.receipts() if r.payload.get("record_type") == "pack_comparison"]
    assert len(att) == 1
    facts = att[0].payload
    assert facts["pack_a_sha256"] == hashlib.sha256(data).hexdigest()
    assert facts["pack_b_sha256"] == hashlib.sha256(forged_bytes).hexdigest()
    assert facts["clean"] is False
    assert facts["anomalies"] >= 1
    assert len(facts["events_sha256"]) == 64
    assert "does not prove the comparison is right" in facts["boundary"]
    assert att[0].visit_id.startswith("pack-diff:")

    # Idempotent — reconciling the same pair again reuses the receipt.
    rc = run("diff", str(pack), str(forged), "--attest")
    audit_store = Store(audit / "attest.sqlite3")
    att = [r for r in audit_store.receipts() if r.payload.get("record_type") == "pack_comparison"]
    assert len(att) == 1

    # --json keeps stdout pure — the attestation note rides stderr.
    rc = run("diff", "--json", str(pack), str(forged), "--attest")
    import json as _json

    verdict = _json.loads(rc.stdout)  # stdout parses: the note can't corrupt it
    assert verdict["anomalies"] >= 1

    # A comparison under a different issuer pin is a different claim — the
    # trust context keys the pseudo-id, so the first receipt isn't reused.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from attest.ledger import Signer

    foreign = Signer(Ed25519PrivateKey.from_private_bytes(b"\xee" * 32)).public_key_b64
    rc = run("diff", str(pack), str(forged), "--key", foreign, "--attest")
    audit_store = Store(audit / "attest.sqlite3")
    att = [r for r in audit_store.receipts() if r.payload.get("record_type") == "pack_comparison"]
    assert len(att) == 2
    pinned = next(r for r in att if r.payload["context"].get("issuer_pin") == foreign)
    assert pinned.payload["verifier"]["checker"] == "attest.packdiff.diff_report"


def test_verify_attest_needs_an_initialized_store(tmp_path):
    """--attest with no ATTEST_DATA_DIR store fails fast — before the pack is
    even opened — rather than silently verifying without attesting."""
    import os
    import subprocess
    import sys

    pack = tmp_path / "case.zip"
    pack.write_bytes(b"PK\x03\x04" + b"0" * 20)
    empty = tmp_path / "no-store"
    empty.mkdir()
    env = {**os.environ, "ATTEST_DATA_DIR": str(empty)}
    rc = subprocess.run(
        [sys.executable, "-m", "attest.cli", "verify", "--attest", str(pack)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert rc.returncode != 0
    assert "--attest needs a store" in (rc.stdout + rc.stderr)


def test_issue_pack_verification_fields(engine):
    """The attestation receipt carries the boundary discipline every signed
    claim does: it attests the verifier RAN and returned this verdict, not
    that the verdict is right or that anything physical is true."""
    receipt = engine.issue_pack_verification(
        "ab" * 32,
        1234,
        "ok",
        "case pack verified — 4 receipts intact",
        {"name": "attest-cli", "version": "0.1.0", "verifier_sha256": "cd" * 32},
    )
    p = receipt.payload
    assert p["record_type"] == "pack_verification"
    assert p["pack_sha256"] == "ab" * 32
    assert p["verdict"] == "ok"
    assert "does not prove the verdict is right" in p["boundary"]
    assert receipt.visit_id.startswith("pack-verify:")
    # Same pack + same verifier → the same attestation, not a duplicate leaf.
    again = engine.issue_pack_verification(
        "ab" * 32,
        1234,
        "ok",
        "case pack verified — 4 receipts intact",
        {"name": "attest-cli", "version": "0.1.0", "verifier_sha256": "cd" * 32},
    )
    assert again.id == receipt.id
    # A different verifier identity must NOT collapse into the first
    # attestation — verdicts from different rules are different claims.
    other = engine.issue_pack_verification(
        "ab" * 32,
        1234,
        "fail",
        "payload hash mismatch",
        {"name": "verify_case.py", "version": "", "verifier_sha256": "ef" * 32},
    )
    assert other.id != receipt.id


def test_attestation_pseudo_ids_key_every_asserted_claim(engine):
    """Two runs over the same bytes reaching different claims must never share
    a receipt — the pseudo-id keys verdict, detail, and trust context, or an
    "ok" could be cited for a run that actually failed."""
    v = {"name": "attest-cli", "version": "0.1.0", "verifier_sha256": "cd" * 32}
    ok = engine.issue_pack_verification("ab" * 32, 1, "ok", "verified", v)
    fail = engine.issue_pack_verification("ab" * 32, 1, "fail", "mismatch", v)
    assert fail.id != ok.id
    # Same verdict but a different trust context — also a distinct claim.
    pinned = engine.issue_pack_verification("ab" * 32, 1, "ok", "verified", v, context={"issuer_pin": "AA=="})
    assert pinned.id != ok.id
    again = engine.issue_pack_verification("ab" * 32, 1, "ok", "verified", v, context={"issuer_pin": "AA=="})
    assert again.id == pinned.id
    # Comparisons key the same way — a changed verdict never reuses a
    # "clean" receipt.
    c1 = engine.issue_pack_comparison("aa" * 32, "bb" * 32, 1, 1, "extends", True, 0, "e" * 64, "grew", v)
    c2 = engine.issue_pack_comparison("aa" * 32, "bb" * 32, 1, 1, "same", False, 2, "f" * 64, "moved", v)
    assert c2.id != c1.id
    c3 = engine.issue_pack_comparison(
        "aa" * 32,
        "bb" * 32,
        1,
        1,
        "extends",
        True,
        0,
        "e" * 64,
        "grew",
        v,
        context={"issuer_pin": "AA=="},
    )
    assert c3.id != c1.id


def test_cli_verify_json_emits_a_gatable_verdict(tmp_path, engine, store, household, schedule, t0):
    """`attest verify pack.zip --json` is the CI gate: stdout carries exactly
    one object — {ok, kind, detail, pinned} — and a tampered pack is exit 1
    with {"ok": false}."""
    import json
    import subprocess
    import sys
    import zipfile
    from io import BytesIO

    from attest.disputepack import build_case_pack, log_member
    from attest.reviews import ReviewService, countersign_status

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
        log_fn=lambda rs: log_member(engine, rs),
    )
    pack = tmp_path / "case.zip"
    pack.write_bytes(data)
    rc = subprocess.run(
        [sys.executable, "-m", "attest.cli", "verify", "--json", str(pack)],
        capture_output=True,
        text=True,
    )
    assert rc.returncode == 0, rc.stderr + rc.stdout
    verdict = json.loads(rc.stdout)
    assert verdict["ok"] is True
    assert verdict["kind"] == "case-pack"
    assert "verifier tool(s) pinned" in verdict["detail"]
    # The signed head rides the verdict as data — a CI can gate on the log
    # growing between exports, not just on the pack being intact.
    assert verdict["log"]["tree_size"] >= 1
    assert verdict["log"]["proven"] >= 1
    # A forged always-green verifier inside the pack is the CI's whole point.
    with zipfile.ZipFile(BytesIO(data)) as z:
        items = [(n, z.read(n)) for n in z.namelist()]
    forged = BytesIO()
    with zipfile.ZipFile(forged, "w") as z:
        for n, b in items:
            z.writestr(n, b"<html>always green</html>" if n == "verify.html" else b)
    bad = tmp_path / "forged.zip"
    bad.write_bytes(forged.getvalue())
    rc = subprocess.run(
        [sys.executable, "-m", "attest.cli", "verify", "--json", str(bad)],
        capture_output=True,
        text=True,
    )
    assert rc.returncode == 1, rc.stderr + rc.stdout
    verdict = json.loads(rc.stdout)
    assert verdict["ok"] is False
    assert "issuer-signed pin" in verdict["detail"]


def test_cli_explain_narrates_a_record(tmp_path, monkeypatch, ring_world, ring_client, settings, t0):
    """`attest explain` renders source-by-source corroboration, the signed
    anchor, the review chain, and the derived stance for one record."""
    import argparse
    from datetime import timedelta

    from ring_sandbox.world import DeviceKind

    from attest import cli
    from attest.engine import VisitEngine
    from attest.ledger import Signer
    from attest.media import MediaStore
    from attest.models import Role, Schedule, Site, Worker
    from attest.store import Store
    from attest.summarize import TemplateSummarizer

    store = Store(tmp_path / "attest.sqlite3")
    cam = next(d for d in ring_world.devices.values() if d.kind == DeviceKind.DOORBELL)
    site = store.put_site(
        Site(name="Alvarez residence", ring_account_id=ring_world.account_id, door_camera_id=cam.id)
    )
    worker = store.put_worker(Worker(name="Maria Chen", role=Role.HOME_HEALTH_AIDE, checkin_token="t"))
    store.put_schedule(
        Schedule(
            site_id=site.id,
            worker_id=worker.id,
            window_start=t0,
            window_end=t0 + timedelta(hours=1),
            expected_minutes=60,
        )
    )
    engine = VisitEngine(
        store,
        ring_client,
        Signer.ephemeral(),
        MediaStore(tmp_path / "media"),
        TemplateSummarizer("UTC"),
        settings,
    )
    visit = engine.ingest(event(cam, t0 + timedelta(minutes=2))).visit
    engine.close_for_review(visit.id)
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))

    monkeypatch.setattr(cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(cli.settings, "kms_key_id", None)

    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._explain(argparse.Namespace(visit=visit.id))
    out = buf.getvalue()
    assert visit.id in out
    assert "Source-by-source" in out
    assert "Pipeline coverage" in out
    assert "Signed receipt" in out and "Review chain: OK" in out
    assert "Derived stance" in out
    assert "Site attestations" in out
    assert "coverage_attestation" in out and "spans this visit's window" in out

    # attestations explain too — by pseudo visit_id or receipt id
    w0, w1 = (t0 - timedelta(hours=1)).isoformat(), (t0 + timedelta(hours=2)).isoformat()
    pseudo = f"coverage:{site.id}:{w0}:{w1}"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._explain(argparse.Namespace(visit=pseudo))
    att = buf.getvalue()
    assert "coverage_attestation" in att
    assert "signature: OK" in att and "silence is not absence" in att

    # a signed verification_report explains its per-check results too
    vreceipt = engine.issue_verification_report(
        {
            "generated_at": t0.isoformat(),
            "base_url": "https://api.prod.ring.dev.example",
            "checks": [
                {"check": "users/me", "status": "pass", "detail": "account reachable"},
                {"check": "WHEP live view", "status": "fail", "detail": "500"},
            ],
            "summary": {"pass": 1, "fail": 1, "warn": 0, "skip": 0},
        }
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cli._explain(argparse.Namespace(visit=vreceipt.id))
    vout = buf.getvalue()
    assert "verification_report" in vout and "official-API sweep" in vout
    assert "users/me: account reachable" in vout and "only PASS is verified" in vout

    with pytest.raises(SystemExit):
        with contextlib.redirect_stdout(buf):
            cli._explain(argparse.Namespace(visit="vis_nope"))
