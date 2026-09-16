from datetime import timedelta

from attest.coverage import coverage_report
from attest.models import PollObservation


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
