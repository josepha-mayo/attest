"""Period digest: a signed, chain-linked summary of the *records* written
for an interval — counts of records, never claims about physical presence."""

from datetime import timedelta

import httpx
import pytest

from attest.app import create_app
from attest.ledger import Signer, verify_chain, verify_receipt


@pytest.fixture
def api(settings, store, ring_client, household, schedule):
    app = create_app(settings, store=store, ring=ring_client, signer=Signer.ephemeral(), sweep_interval_s=0)

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            import asyncio

            async def go():
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://t"
                ) as ac:
                    r = await ac.request(
                        request.method,
                        request.url,
                        headers=request.headers,
                        content=request.content,
                    )
                    await r.aread()
                    return httpx.Response(
                        r.status_code, headers=r.headers, content=r.content, request=request
                    )

            return asyncio.run(go())

    with httpx.Client(transport=T(), base_url="http://t", follow_redirects=False) as c:
        c.auth = ("admin", settings.admin_token.get_secret_value())
        c.attest_state = app.state
        yield c
    app.state.inbox.close()


def test_period_digest_counts_records_signs_and_chains(engine, store, household, schedule, t0):
    site = household[0]
    engine.sweep(t0 + timedelta(hours=2))  # schedule lapses to no_observation

    start, end = t0 - timedelta(hours=1), t0 + timedelta(hours=4)
    head_at_issue = store.journal_head()
    receipt = engine.issue_period_digest(site, start, end)
    payload = receipt.payload
    assert payload["record_type"] == "period_digest"
    counts = payload["counts"]
    assert counts["visits_no_observation"] == 1
    assert counts["visits_observed"] == counts["visits_unmatched"] == 0
    assert counts["worker_statements"] == 0
    # the digest pins exactly which receipts it summarizes
    visit = store.visit_for_schedule(schedule.id)
    assert payload["summarized_receipts"] == {visit.id: store.receipt_for_visit(visit.id).payload_hash}
    assert payload["journal_head"] == head_at_issue
    assert "never about physical presence" in payload["boundary"]
    assert verify_receipt(receipt, public_key=engine.signer.public_key_b64)[0]
    ok, why = verify_chain(store.receipts(), public_key=engine.signer.public_key_b64)
    assert ok, why


def test_period_digest_measures_the_dispute_loop_closing(engine, store, household, schedule, t0):
    """Resolved records and median time-to-resolution are ledger metrics —
    the digest shows the review loop actually closing, not just counting."""
    from ring_sandbox import WebhookEvent, webhooks

    from attest.models import ResolutionInput, ReviewInput
    from attest.reviews import ReviewService

    site = household[0]
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    service = ReviewService(store, engine.signer, engine.clock)
    token = service.issue_worker_link(visit.id)
    service.worker_review(token, ReviewInput(decision="dispute", statement="I was early."))
    service.resolve(visit.id, ResolutionInput(outcome="account_accepted", statement="Camera confirms."))

    receipt = engine.issue_period_digest(site, t0 - timedelta(hours=1), t0 + timedelta(hours=4))
    counts = receipt.payload["counts"]
    assert counts["worker_disputes"] == 1
    assert counts["coordinator_resolutions"] == 1
    assert counts["records_resolved"] == 1
    assert counts["median_resolution_minutes"] is not None
    assert counts["median_resolution_minutes"] >= 0


def test_period_digest_is_idempotent_per_range(engine, store, household, schedule, t0):
    site = household[0]
    engine.sweep(t0 + timedelta(hours=2))
    start, end = t0 - timedelta(hours=1), t0 + timedelta(hours=4)
    first = engine.issue_period_digest(site, start, end)
    second = engine.issue_period_digest(site, start, end)
    assert first.id == second.id


def test_period_digest_endpoint_covers_shown_records(api):
    store = api.attest_state.store
    api.attest_state.engine.sweep()  # lapse the fixture schedule into a record
    site = store.sites()[0]
    response = api.post(f"/api/sites/{site.id}/digest")
    assert response.status_code == 200, response.text
    receipt = response.json()
    assert receipt["payload"]["record_type"] == "period_digest"
    assert receipt["payload"]["site"]["id"] == site.id
    # re-issue is idempotent — same records, same digest
    assert api.post(f"/api/sites/{site.id}/digest").json()["id"] == receipt["id"]
