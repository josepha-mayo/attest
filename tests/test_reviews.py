import hashlib
from datetime import timedelta

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.errors import DomainError
from attest.models import HouseholdStatementInput, ReviewInput, utcnow
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


def test_countersign_tracks_worker_stance_and_link_state(review_case, store):
    service, visit_id = review_case
    assert service.countersign(visit_id)["state"] == "unrequested"

    token = service.issue_worker_link(visit_id)
    assert service.countersign(visit_id)["state"] == "awaiting"

    service.worker_review(token, ReviewInput(decision="confirm", statement="Matches what happened."))
    status = service.countersign(visit_id)
    assert status["state"] == "acknowledged"
    assert status["worker"] and status["revision"] == 1

    # A later worker dispute supersedes the acknowledgment (new link, new revision)
    token = service.issue_worker_link(visit_id)
    service.worker_review(token, ReviewInput(decision="dispute", statement="Times are wrong."))
    assert service.countersign(visit_id)["state"] == "contested"

    # Coordinator reviews never count as the worker's stance
    service.coordinator_review(visit_id, ReviewInput(decision="confirm", statement="Coordinator note."))
    assert service.countersign(visit_id)["state"] == "contested"

    # Derived state is pure: recomputes identically from an exported bundle
    from attest.reviews import countersign_status

    exported = service.bundle(visit_id)
    assert countersign_status(exported)["state"] == "contested"


def test_resolution_is_the_terminal_signed_conclusion(review_case):
    """A worker dispute has no terminal state without a resolution — the
    coordinator's signed conclusion layers after the stance, leaves the
    worker's words in the chain, and re-opens on any newer statement."""
    from attest.models import ResolutionInput
    from attest.reviews import countersign_status, verify_bundle

    service, visit_id = review_case
    token = service.issue_worker_link(visit_id)
    service.worker_review(token, ReviewInput(decision="dispute", statement="Times are wrong."))
    assert service.countersign(visit_id)["state"] == "contested"

    entry = service.resolve(
        visit_id,
        ResolutionInput(outcome="record_upheld", statement="Coverage was continuous; the record stands."),
    )
    assert entry.receipt.payload["review"]["kind"] == "resolution"
    assert entry.receipt.payload["actor"]["role"] == "coordinator"
    assert entry.receipt.payload["record_type"] == "review"

    status = service.countersign(visit_id)
    assert status["state"] == "resolved"
    assert status["decision"] == "dispute"  # worker stance preserved, not erased
    assert status["resolution"]["outcome"] == "record_upheld"
    assert status["resolution"]["revision"] == entry.revision
    assert "coordinator upheld the record" in status["detail"]

    # The exported bundle recomputes identically, and the resolution verifies.
    exported = service.bundle(visit_id)
    assert countersign_status(exported)["state"] == "resolved"
    ok, _ = verify_bundle(exported, public_key=service.signer.public_key_b64)
    assert ok


def test_new_worker_statement_after_resolution_reopens(review_case):
    from attest.models import ResolutionInput

    service, visit_id = review_case
    token = service.issue_worker_link(visit_id)
    service.worker_review(token, ReviewInput(decision="dispute", statement="Not me."))
    service.resolve(visit_id, ResolutionInput(outcome="record_upheld", statement="Record stands."))
    assert service.countersign(visit_id)["state"] == "resolved"

    token = service.issue_worker_link(visit_id)
    service.worker_review(token, ReviewInput(decision="correction", statement="Window moved an hour."))
    assert service.countersign(visit_id)["state"] == "corrected"


def test_identical_resolution_resubmission_is_idempotent(review_case):
    """A double-submit (retry, refreshed form) must not chain a byte-identical
    duplicate — the same entry comes back. A *different* outcome or statement
    is a changed mind and appends normally."""
    from attest.models import ResolutionInput

    service, visit_id = review_case
    first = service.resolve(visit_id, ResolutionInput(outcome="record_upheld", statement="Record stands."))
    again = service.resolve(visit_id, ResolutionInput(outcome="record_upheld", statement="Record stands."))
    assert again.id == first.id
    assert len(service.bundle(visit_id).reviews) == 1

    changed = service.resolve(visit_id, ResolutionInput(outcome="inconclusive", statement="Reconsidered."))
    assert changed.id != first.id
    assert len(service.bundle(visit_id).reviews) == 2


def test_resolution_without_worker_statement(review_case):
    from attest.models import ResolutionInput

    service, visit_id = review_case
    service.resolve(
        visit_id,
        ResolutionInput(outcome="inconclusive", statement="No account received; ambiguity recorded."),
    )
    status = service.countersign(visit_id)
    assert status["state"] == "resolved"
    assert "No worker statement" in status["detail"]


def test_countersign_marks_expired_unused_links(review_case, store):
    service, visit_id = review_case
    token = service.issue_worker_link(visit_id)
    grant = store.review_grant(hashlib.sha256(token.encode()).hexdigest())
    grant.expires_at = utcnow() - timedelta(seconds=1)
    store.put_review_grant(grant)
    assert service.countersign(visit_id)["state"] == "unacknowledged"


def test_review_failure_does_not_consume_grant(review_case, store, monkeypatch):
    service, visit_id = review_case
    token = service.issue_worker_link(visit_id)
    with monkeypatch.context() as patch:
        patch.setattr(store, "put_review", lambda _: (_ for _ in ()).throw(RuntimeError("disk failure")))
        with pytest.raises(RuntimeError):
            service.worker_review(token, ReviewInput(decision="dispute", statement="Try again."))
    assert service.worker_target(token) is not None
    assert service.worker_review(token, ReviewInput(decision="dispute", statement="Saved."))


def test_resolution_reason_code_is_signed_and_classifies_not_asserts(review_case):
    """The coded reason rides inside the signed review payload — an EVV-style
    exception code that classifies the coordinator's explanation. The basis
    qualifier keeps it honest: the code is a stated cause, never a verified one."""
    from attest.models import ResolutionInput

    service, visit_id = review_case
    token = service.issue_worker_link(visit_id)
    service.worker_review(token, ReviewInput(decision="dispute", statement="Door was jammed, I waited."))

    entry = service.resolve(
        visit_id,
        ResolutionInput(
            outcome="inconclusive",
            statement="Plausible account, no confirming observation.",
            reason_code="no_electronic_confirmation",
        ),
    )
    review = entry.receipt.payload["review"]
    assert review["reason_code"] == "no_electronic_confirmation"
    assert review["reason_label"] == "No device confirmation exists — unexplained gap"
    assert review["reason_basis"] == "coordinator_stated_explanation_not_verified_cause"
    # the honesty invariants are untouched by the code
    assert entry.receipt.payload["independently_verified_attendance"] is False
    assert entry.receipt.payload["original_assessment_unchanged"] is True

    exported = service.bundle(visit_id)
    ok, _ = __import__("attest.reviews", fromlist=["verify_bundle"]).verify_bundle(
        exported, public_key=service.signer.public_key_b64
    )
    assert ok


def test_resolution_reason_code_validates_against_taxonomy(review_case):
    """Free-text codes would defeat the point — only taxonomy members pass."""
    import pytest

    from attest.models import ResolutionInput

    with pytest.raises(Exception, match="unknown reason code"):
        ResolutionInput(outcome="record_upheld", statement="x", reason_code="worker_seemed_nice")
    # blank posts (empty <select>) normalize to None, not a validation error
    assert ResolutionInput(outcome="record_upheld", statement="x", reason_code="").reason_code is None


def test_reason_code_participates_in_resolution_idempotency(review_case):
    """Same outcome+statement but a different coded reason is a changed mind —
    it must append, not dedupe against the earlier resolution."""
    from attest.models import ResolutionInput

    service, visit_id = review_case
    first = service.resolve(
        visit_id,
        ResolutionInput(outcome="inconclusive", statement="Unclear.", reason_code="device_fault"),
    )
    same = service.resolve(
        visit_id,
        ResolutionInput(outcome="inconclusive", statement="Unclear.", reason_code="device_fault"),
    )
    assert same.id == first.id
    recoded = service.resolve(
        visit_id,
        ResolutionInput(outcome="inconclusive", statement="Unclear.", reason_code="subscription_lapse"),
    )
    assert recoded.id != first.id
    assert len(service.bundle(visit_id).reviews) == 2


def test_taxonomy_suggestions_cover_every_visit_flag():
    """Every flag the engine can emit maps to at least one suggested reason —
    a coordinator should never face an unclassified flag."""
    from attest.taxonomy import REASON_CODES, suggest

    for flag in [
        "clock_conflict",
        "departure_unconfirmed",
        "early",
        "idle_close",
        "late",
        "media_unavailable",
        "no_checkin",
        "no_observation",
        "observation_gap",
        "observed_interval_short",
        "unscheduled",
    ]:
        codes = suggest([flag])
        assert codes, flag
        assert all(c in REASON_CODES for c in codes)
        assert len(codes) == len(REASON_CODES)  # suggestions then the rest
    # deduped — overlapping suggestions collapse
    assert len(suggest(["no_observation", "observation_gap"])) == len(REASON_CODES)


def test_link_failures_carry_stable_domain_codes(review_case):
    """Handlers route on DomainError.code, never the message wording — the
    codes are the contract localized pages and dead-link decisions key on."""
    service, visit_id = review_case
    with pytest.raises(DomainError) as worker_exc:
        service.worker_review("bogus-token", ReviewInput(decision="confirm", statement="x"))
    assert worker_exc.value.code == "invalid_review_link"
    with pytest.raises(DomainError) as family_exc:
        service.household_statement(
            "bogus-token",
            HouseholdStatementInput(perception="unsure", statement="Not sure."),
        )
    assert family_exc.value.code == "invalid_family_link"
    # a used worker link fails with the same code as a bogus one — an
    # attacker cannot probe link state from the error surface
    token = service.issue_worker_link(visit_id)
    service.worker_review(token, ReviewInput(decision="confirm", statement="Noted."))
    with pytest.raises(DomainError) as reused_exc:
        service.worker_review(token, ReviewInput(decision="confirm", statement="Again."))
    assert reused_exc.value.code == "invalid_review_link"


def test_worker_statement_reason_code_is_self_reported(review_case):
    """A worker's coded reason signs in with a self-reported basis — the same
    taxonomy, a different claim class than a coordinator's resolution code."""
    service, visit_id = review_case
    token = service.issue_worker_link(visit_id)
    entry = service.worker_review(
        token,
        ReviewInput(
            decision="dispute",
            statement="The app wouldn't open the check-in screen.",
            reason_code="mobile_or_network_issue",
        ),
    )
    review = entry.receipt.payload["review"]
    assert review["reason_code"] == "mobile_or_network_issue"
    assert review["reason_basis"] == "worker_stated_explanation_not_verified_cause"
    assert verify_bundle(service.bundle(visit_id), public_key=service.signer.public_key_b64)[0]
