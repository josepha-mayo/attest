import json
from datetime import timedelta

from attest.coverage import coverage_report
from attest.models import CoverageEvent, CoverageEventKind, PollObservation, Schedule


def _obs(store, device, polled_at, since, ok=True, events=0):
    o = PollObservation(
        site_id="site",
        device_id=device,
        polled_at=polled_at,
        since=since,
        ok=ok,
        events_returned=events,
        error=None if ok else "HTTP 500",
    )
    store.put_poll_observation(o)
    return o


def _cov(store, site_id, device, at, kind, detail=None):
    ev = CoverageEvent(site_id=site_id, device_id=device, at=at, kind=kind, detail=detail or {})
    store.put_coverage_event(ev)
    return ev


def test_no_polls_means_no_claim(store, t0):
    report = coverage_report(store, "cam1", t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=2))
    assert report["state"] == "no_polls" and report["fraction"] == 0.0


def test_full_silent_coverage_is_observed_not_absent(store, t0):
    _obs(store, "cam1", t0 + timedelta(minutes=30), t0 - timedelta(minutes=10))
    _obs(store, "cam1", t0 + timedelta(hours=2), t0)
    report = coverage_report(store, "cam1", t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=3))
    assert report["state"] == "observed" and report["fraction"] == 1.0
    assert report["polls"] == 2 and report["events"] == 0 and not report["gaps"]
    assert "not what physically happened" in report["claim"]


def test_failed_poll_leaves_an_honest_gap(store, t0):
    _obs(store, "cam1", t0 + timedelta(minutes=10), t0 - timedelta(minutes=5))
    _obs(store, "cam1", t0 + timedelta(minutes=40), t0 + timedelta(minutes=20), ok=False)
    _obs(store, "cam1", t0 + timedelta(hours=1), t0 + timedelta(minutes=50))
    report = coverage_report(store, "cam1", t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=2))
    assert report["state"] == "partial" and report["failed_polls"] == 1
    assert len(report["gaps"]) == 1
    assert report["fraction"] < 0.5


def test_all_failed_polls_is_blind(store, t0):
    _obs(store, "cam1", t0 + timedelta(minutes=30), t0, ok=False)
    report = coverage_report(store, "cam1", t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=2))
    assert report["state"] == "blind" and report["polls"] == 0


def test_retroactive_poll_covers_earlier_window(store, t0):
    # A poll after the window still covers it — history is retrospective
    _obs(store, "cam1", t0 + timedelta(hours=5), t0 - timedelta(minutes=30), events=1)
    report = coverage_report(store, "cam1", t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=6))
    assert report["state"] == "observed_with_events" and report["fraction"] == 1.0


def test_other_devices_polls_do_not_count(store, t0):
    _obs(store, "other-cam", t0 + timedelta(hours=2), t0)
    report = coverage_report(store, "cam1", t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=3))
    assert report["state"] == "no_polls"


def test_lifecycle_interruption_explains_a_gap(store, household, t0):
    """A poll gap overlapping a signed-channel interruption reads explained —
    silence with a recorded cause on file, still never proof of absence."""
    site, _worker, cam, _sensor = household
    _obs(store, cam.id, t0 + timedelta(minutes=20), t0 - timedelta(minutes=10))
    _obs(store, cam.id, t0 + timedelta(hours=2), t0 + timedelta(minutes=50))
    _cov(store, site.id, cam.id, t0 + timedelta(minutes=25), CoverageEventKind.DEVICE_OFFLINE)
    _cov(store, site.id, cam.id, t0 + timedelta(minutes=45), CoverageEventKind.DEVICE_ONLINE)

    report = coverage_report(
        store, cam.id, t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=3), site_id=site.id
    )
    assert report["state"] == "partial" and len(report["gaps"]) == 1
    gap = report["gaps"][0]
    assert gap["explained"] is True
    assert gap["explained_by"][0]["kind"] == "device_offline"
    assert gap["explained_by"][0]["restored_by"] == "device_online"
    assert [i["kind"] for i in report["interruptions"]] == ["device_offline", "device_online"]


def test_unclosed_interruption_explains_silence_through_window_end(store, household, t0):
    """A camera that never comes back online leaves an open-ended explanation —
    the gap stays explained to the window edge, without claiming a restore."""
    site, _worker, cam, _sensor = household
    _obs(store, cam.id, t0 + timedelta(minutes=20), t0 - timedelta(minutes=10))
    _cov(store, site.id, cam.id, t0 + timedelta(minutes=25), CoverageEventKind.DEVICE_OFFLINE)

    report = coverage_report(
        store, cam.id, t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=3), site_id=site.id
    )
    gap = report["gaps"][0]
    assert gap["explained"] is True and gap["explained_by"][0]["restored_by"] is None


def test_other_channels_lifecycle_does_not_explain(store, household, t0):
    """Explanations are channel-scoped: the door sensor going dark says nothing
    about why the camera's history went unpolled — the event is still listed
    as site context, just never as the gap's cause."""
    site, _worker, cam, sensor = household
    _obs(store, cam.id, t0 + timedelta(minutes=20), t0 - timedelta(minutes=10))
    _obs(store, cam.id, t0 + timedelta(hours=2), t0 + timedelta(minutes=50))
    _cov(store, site.id, sensor.id, t0 + timedelta(minutes=25), CoverageEventKind.DEVICE_OFFLINE)

    report = coverage_report(
        store, cam.id, t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=3), site_id=site.id
    )
    assert "explained" not in report["gaps"][0]
    assert [i["kind"] for i in report["interruptions"]] == ["device_offline"]


def test_account_scoped_event_explains_every_device(store, household, t0):
    """An unlink/subscription event names the account, not a device — it can
    explain silence on any channel of the site."""
    site, _worker, cam, _sensor = household
    _obs(store, cam.id, t0 + timedelta(minutes=20), t0 - timedelta(minutes=10))
    _obs(store, cam.id, t0 + timedelta(hours=2), t0 + timedelta(minutes=50))
    _cov(store, site.id, None, t0 + timedelta(minutes=25), CoverageEventKind.APP_INTEGRATION_REMOVED)

    report = coverage_report(
        store, cam.id, t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=3), site_id=site.id
    )
    assert report["gaps"][0]["explained"] is True
    assert report["gaps"][0]["explained_by"][0]["device_id"] is None


def test_report_without_site_id_omits_lifecycle(store, household, t0):
    """Without site context the report stays poll-only — lifecycle rows exist
    but are not folded in, and gaps carry no explanation."""
    site, _worker, cam, _sensor = household
    _obs(store, cam.id, t0 + timedelta(minutes=20), t0 - timedelta(minutes=10))
    _cov(store, site.id, cam.id, t0 + timedelta(minutes=25), CoverageEventKind.DEVICE_OFFLINE)

    report = coverage_report(store, cam.id, t0, t0 + timedelta(hours=1), now=t0 + timedelta(hours=3))
    assert "interruptions" not in report
    assert "explained" not in report["gaps"][0]


def test_receipt_coverage_carries_signed_interruptions(engine, store, household, schedule, t0):
    """The lifecycle rows land inside the signed payload — purging the raw
    coverage_events table can't take the explanation with it."""
    from attest.ledger import verify_receipt

    site, _worker, cam, _sensor = household
    engine.ingest(_cam_ev(cam.id, "motion_detected", t0 + timedelta(minutes=2), "human"))
    engine.ingest(_cam_ev(cam.id, "device_offline", t0 + timedelta(minutes=30)))
    engine.ingest(_cam_ev(cam.id, "device_online", t0 + timedelta(minutes=45)))
    engine.ingest(_cam_ev(cam.id, "motion_detected", t0 + timedelta(minutes=50), "human"))

    visit = store.active_visit(site.id)
    engine.close_for_review(visit.id)
    receipt = store.receipt_for_visit(visit.id)
    cov = receipt.payload["history_poll_coverage"]
    assert [i["kind"] for i in cov["interruptions"]] == ["device_offline", "device_online"]
    # Departure was never observed, so the signed window extends to the
    # schedule's end — "could we have seen them leave?" not just "the last event".
    assert cov["window"]["end"] == (t0 + timedelta(hours=1)).isoformat()
    assert verify_receipt(receipt, public_key=engine.signer.public_key_b64)[0]


def _cam_ev(device_id, etype, at, sub=None):
    from ring_sandbox import WebhookEvent, webhooks

    return WebhookEvent.model_validate(
        webhooks.build_event(event_type=etype, device_id=device_id, occurred_at=at, sub_type=sub)
    )


def test_receipt_carries_signed_coverage(engine, store, household, schedule, t0):
    """A no-observation closure attests coverage, not absence."""
    device = household[2].id
    _obs(store, device, t0 + timedelta(minutes=30), t0 - timedelta(minutes=30))
    _obs(store, device, t0 + timedelta(hours=2), t0)

    changed = engine.sweep(t0 + timedelta(hours=2))
    visit = next(v for v in changed if v.schedule_id == schedule.id)
    receipt = store.receipt_for_visit(visit.id)
    cov = receipt.payload["history_poll_coverage"]
    assert cov["state"] == "observed" and cov["fraction"] == 1.0
    assert cov["polls"] == 2 and cov["events"] == 0

    # the coverage claim is inside the signed payload
    from attest.ledger import verify_receipt

    assert verify_receipt(receipt, public_key=engine.signer.public_key_b64)[0]


def test_coverage_attestation_is_signed_chained_and_idempotent(engine, store, household, t0):
    """`attest coverage` issues a standalone signed receipt: chain-linked,
    journal-head pinned, and a re-issue for the same range returns the same receipt."""
    from attest.ledger import verify_receipt

    site = household[0]
    device = household[2].id
    _obs(store, device, t0 + timedelta(minutes=30), t0 - timedelta(minutes=30))
    _obs(store, device, t0 + timedelta(hours=2), t0)

    head_at_issue = store.journal_head()
    receipt = engine.issue_coverage_attestation(site, t0, t0 + timedelta(hours=1))
    assert receipt.payload["record_type"] == "coverage_attestation"
    assert receipt.payload["coverage"]["state"] == "observed"
    # the pin captures the journal tip at issuance — before this receipt's own
    # journal writes — and is covered by the signature
    assert receipt.payload["journal_head"] == head_at_issue
    assert verify_receipt(receipt, public_key=engine.signer.public_key_b64)[0]

    again = engine.issue_coverage_attestation(site, t0, t0 + timedelta(hours=1))
    assert again.id == receipt.id  # idempotent per range


def test_coverage_attestation_links_into_receipt_chain(engine, store, household, t0):
    from attest.ledger import verify_chain

    site = household[0]
    r1 = engine.issue_coverage_attestation(site, t0, t0 + timedelta(hours=1))
    r2 = engine.issue_coverage_attestation(site, t0 + timedelta(hours=1), t0 + timedelta(hours=2))
    assert r2.prev_hash == r1.payload_hash and r2.sequence == r1.sequence + 1
    ok, reason = verify_chain(store.receipts(), public_key=engine.signer.public_key_b64)
    assert ok, reason


def test_anchor_receipt_roundtrips_through_verify(store, t0):
    """The `attest anchor` artifact is a bare signed receipt — `attest verify`
    detects it via the payload+signature branch and checks the signature."""
    from attest.ledger import Signer, verify_receipt
    from attest.models import Receipt

    signer = Signer.ephemeral()
    anchor = signer.issue(
        visit_id="anchor",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "anchor",
            "journal_head": store.journal_head(),
            "journal_entries": 0,
            "receipt_head": None,
            "receipt_count": 0,
            "boundary": "Anchors that a record state existed at issuance.",
        },
    )
    data = json.loads(anchor.model_dump_json())
    assert "payload" in data and "signature" in data  # the _verify detection branch
    parsed = Receipt.model_validate(data)
    ok, reason = verify_receipt(parsed, public_key=signer.public_key_b64)
    assert ok, reason
    # a foreign key must not verify an anchor
    ok2, _ = verify_receipt(parsed, public_key=Signer.ephemeral().public_key_b64)
    assert not ok2


def test_timeline_strip_positions_window_bands_and_marks(store, household, t0):
    """The visit-page strip places the scheduled window, watched/gap bands,
    and each observation/check-in as percentage positions."""
    from attest.timeline import timeline_strip

    site, worker, cam, _sensor = household
    sch = Schedule(
        site_id=site.id,
        worker_id=worker.id,
        window_start=t0,
        window_end=t0 + timedelta(hours=1),
        expected_minutes=60,
        service="x",
    )

    class _E:
        pass

    evs = []
    for kind, off in [("arrival_motion", 10), ("snapshot", 22), ("departure_motion", 50)]:
        e = _E()
        e.at = t0 + timedelta(minutes=off)
        e.kind = kind
        evs.append(e)
    cov = {
        "covered": [{"start": t0.isoformat(), "end": (t0 + timedelta(minutes=40)).isoformat()}],
        "gaps": [
            {"start": (t0 + timedelta(minutes=40)).isoformat(), "end": (t0 + timedelta(hours=1)).isoformat()}
        ],
    }
    strip = timeline_strip(
        schedule=sch,
        evidence=evs,
        checked_in_at=t0 + timedelta(minutes=12),
        coverage=cov,
    )
    assert strip["window"]["w"] > 50
    assert [b["watched"] for b in strip["bands"]] == [True, False]
    assert len(strip["marks"]) == 4  # 3 events + check-in
    assert all(0 <= m["x"] <= 100 for m in strip["marks"])
    assert timeline_strip(schedule=None, evidence=[], checked_in_at=None, coverage=None) is None


def test_day_strips_share_a_midnight_to_midnight_axis(store, household, t0):
    """The site week view: one strip per local day on a fixed 24h axis, newest
    first — schedules, evidence, check-ins, and coverage land on their own day."""
    from datetime import UTC

    from attest.timeline import day_strips

    site, worker, cam, _sensor = household
    mid2 = t0.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    mid1 = mid2 - timedelta(days=1)
    day1, day2 = mid1, mid2

    class _E:
        pass

    class _V:
        def __init__(self, vid, ci=None):
            self.id, self.checked_in_at = vid, ci

    sch1 = Schedule(
        site_id=site.id,
        worker_id=worker.id,
        window_start=day1,
        window_end=day1 + timedelta(hours=2),
        expected_minutes=90,
        service="x",
    )
    sch2 = Schedule(
        site_id=site.id,
        worker_id=worker.id,
        window_start=day2,
        window_end=day2 + timedelta(hours=2),
        expected_minutes=90,
        service="x",
    )
    e1, e2 = _E(), _E()
    e1.at, e1.kind = day1 + timedelta(minutes=30), "arrival_motion"
    e2.at, e2.kind = day2 + timedelta(hours=3), "departure_motion"
    v1, v2 = _V("v1", ci=day1 + timedelta(minutes=35)), _V("v2")
    cov = {
        "v2": {
            "covered": [{"start": day2.isoformat(), "end": (day2 + timedelta(hours=1)).isoformat()}],
            "gaps": [],
        }
    }
    strips = day_strips(
        visits=[v1, v2],
        evidence_by_visit={"v1": [e1], "v2": [e2]},
        schedules=[sch1, sch2],
        coverage_by_visit=cov,
        tz=UTC,
    )
    assert len(strips) == 2
    newest, oldest = strips
    assert newest["label"] == day2.strftime("%a %b %d")
    # fixed 24h axis: bounds exactly midnight→midnight
    assert newest["strip"]["start"] == day2.replace(hour=0, minute=0, second=0).isoformat()
    assert (
        newest["strip"]["end"] == (day2 + timedelta(days=1)).replace(hour=0, minute=0, second=0).isoformat()
    )
    # day2's mark: 3h in => ~12.5% across
    mark = next(m for m in newest["strip"]["marks"] if m["kind"] == "departure_motion")
    assert 11 < mark["x"] < 14
    # day1 carries the check-in mark
    assert any(m["kind"] == "checkin" for m in oldest["strip"]["marks"])
    # coverage band only on day2
    assert newest["strip"]["bands"] and not oldest["strip"]["bands"]
    # every rendered element inside the axis
    for s in strips:
        assert all(0 <= m["x"] <= 100 for m in s["strip"]["marks"])
        assert all(0 <= b["x"] and b["x"] + b["w"] <= 100.5 for b in s["strip"]["bands"])


def test_publish_anchor_uploads_with_sha_metadata(tmp_path, monkeypatch):
    """--publish s3://bucket/key uploads the anchor bytes and stamps the file's
    sha256 + payload hash into object metadata — the checkpoint's integrity is
    checkable against the object's own metadata."""
    import sys
    import types

    from attest.cli import _publish_anchor

    calls = {}

    class _S3:
        def put_object(self, **kw):
            calls.update(kw)

    fake = types.ModuleType("boto3")
    fake.client = lambda svc, region_name=None: _S3()
    monkeypatch.setitem(sys.modules, "boto3", fake)

    f = tmp_path / "anchor.json"
    f.write_bytes(b'{"signed": "anchor"}')
    _publish_anchor("s3://bkt/path/anchor.json", f, "ph" * 10 + "0" * 14, "us-east-1")

    import hashlib

    assert calls["Bucket"] == "bkt" and calls["Key"] == "path/anchor.json"
    assert calls["Body"] == f.read_bytes()
    assert calls["Metadata"]["sha256"] == hashlib.sha256(f.read_bytes()).hexdigest()
    assert calls["Metadata"]["attest-record-type"] == "anchor"
