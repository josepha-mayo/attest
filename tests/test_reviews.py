import hashlib
from datetime import timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.models import ReviewInput, utcnow
from attest.reviews import ReviewService, verify_bundle


@pytest.fixture
def review_case(engine, store, household, schedule, t0):
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    return ReviewService(store, engine.signer, engine.clock), visit.id


def test_reviews_append_without_changing_original_observations(review_case, store, t0):
    service, visit_id = review_case
    original = store.receipt_for_visit(visit_id).model_dump_json()
    visit_before = store.visit(visit_id).model_dump_json()
    service.coordinator_review(visit_id, ReviewInput(decision="inconclusive", statement="Ask the worker."))
    token = service.issue_worker_link(visit_id)
    worker_review = service.worker_review(
        token,
        ReviewInput(
            decision="correction",
            statement="I remained inside after the camera stopped recording.",
            reported_start=t0,
            reported_end=t0 + timedelta(minutes=90),
        ),
    )
    assert worker_review.receipt.payload["actor"]["role"] == "worker"
    assert worker_review.receipt.payload["review"]["decision"] == "correction"
    assert store.receipt_for_visit(visit_id).model_dump_json() == original
    assert store.visit(visit_id).model_dump_json() == visit_before
    assert len(store.receipts()) == 1
    bundle = service.bundle(visit_id)
    assert len(bundle.reviews) == 2
    assert verify_bundle(bundle, public_key=service.signer.public_key_b64)[0]
    assert bundle.reviews[0].receipt.prev_hash == bundle.original.payload_hash
    assert bundle.reviews[1].receipt.prev_hash == bundle.reviews[0].receipt.payload_hash


def test_worker_review_link_is_single_use_and_expiring(review_case, store):
    service, visit_id = review_case
    token = service.issue_worker_link(visit_id)
    service.worker_review(token, ReviewInput(decision="dispute", statement="This was not my visit."))
    with pytest.raises(ValueError):
        service.worker_review(token, ReviewInput(decision="confirm", statement="Duplicate submission."))
    token = service.issue_worker_link(visit_id)
    grant = store.review_grant(hashlib.sha256(token.encode()).hexdigest())
    assert token not in grant.model_dump_json()
    grant.expires_at = utcnow() - timedelta(seconds=1)
    store.put_review_grant(grant)
    with pytest.raises(ValueError):
        service.worker_review(token, ReviewInput(decision="confirm", statement="Expired."))


def test_tampered_or_reordered_reviews_fail_verification(review_case):
    service, visit_id = review_case
    service.coordinator_review(
        visit_id, ReviewInput(decision="confirm", statement="Reviewed as a statement.")
    )
    service.coordinator_review(
        visit_id, ReviewInput(decision="correction", statement="Correcting my prior note.")
    )
    bundle = service.bundle(visit_id)
    tampered = bundle.model_copy(deep=True)
    tampered.reviews[0].receipt.payload["review"]["statement"] = "Forged statement"
    assert not verify_bundle(tampered, public_key=service.signer.public_key_b64)[0]
    bundle.reviews.reverse()
    assert not verify_bundle(bundle, public_key=service.signer.public_key_b64)[0]


def test_input_cannot_supply_identity_and_windows_are_validated(t0):
    with pytest.raises(ValueError):
        ReviewInput(decision="confirm", statement="x", actor={"role": "worker"})
    with pytest.raises(ValueError):
        ReviewInput(decision="correction", statement="x", reported_start=t0)
    with pytest.raises(ValueError):
        ReviewInput(
            decision="correction", statement="x", reported_start=t0, reported_end=t0 - timedelta(seconds=1)
        )


def test_review_failure_does_not_consume_grant(review_case, store, monkeypatch):
    service, visit_id = review_case
    token = service.issue_worker_link(visit_id)
    with monkeypatch.context() as patch:
        patch.setattr(store, "put_review", lambda _: (_ for _ in ()).throw(RuntimeError("disk failure")))
        with pytest.raises(RuntimeError):
            service.worker_review(token, ReviewInput(decision="dispute", statement="Try again."))
    assert service.worker_target(token) is not None
    assert service.worker_review(token, ReviewInput(decision="dispute", statement="Saved."))
