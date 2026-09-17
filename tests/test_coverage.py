import json
from datetime import timedelta

from attest.coverage import coverage_report
from attest.models import PollObservation, Schedule


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
