import json
import sys

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.models import Flag, ResolutionInput, ReviewInput, Visit, VisitState
from attest.reviews import ReviewService
from attest.triage import attention_items, deterministic_brief, make_tools, run_triage


@pytest.fixture
def case(engine, store, household, schedule, t0):
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    return store, ReviewService(store, engine.signer, engine.clock), visit


def test_attention_items_flags_disputes(case):
    store, reviews, visit = case
    reviews.coordinator_review(visit.id, ReviewInput(decision="inconclusive", statement="Check."))
    items = attention_items(store, reviews)
    assert [i["visit"].id for i in items] == [visit.id]
    assert items[0]["level"] == "warn"


def test_deterministic_brief_clean_store(store, engine):
    reviews = ReviewService(store, engine.signer, engine.clock)
    assert "Nothing needs attention" in deterministic_brief(store, reviews)


def test_deterministic_brief_reports_contested(case):
    store, reviews, visit = case
    token = reviews.issue_worker_link(visit.id)
    reviews.worker_review(token, ReviewInput(decision="dispute", statement="That was not my visit."))
    brief = deterministic_brief(store, reviews)
    assert visit.id in brief
    assert "disputes" in brief


def test_routine_flags_alone_do_not_queue(store, engine, household, t0):
    """departure_unconfirmed rides on every closed record as a boundary
    statement — it must not, by itself, pull the record into Needs review."""
    site = household[0]
    visit = Visit(
        site_id=site.id,
        state=VisitState.CLOSED,
        arrived_at=t0,
        last_activity_at=t0,
        flags=[
            Flag(
                code="departure_unconfirmed",
                severity="warn",
                message="Record closed for review; direction, identity, and "
                "continuous presence are not established",
            )
        ],
    )
    store.put_visit(visit)
    reviews = ReviewService(store, engine.signer, engine.clock)
    assert attention_items(store, reviews) == []


def test_resolved_record_leaves_the_queue(case):
    """A signed coordinator conclusion is terminal until a newer worker
    statement — resolved records must not stay in Needs review."""
    store, reviews, visit = case
    token = reviews.issue_worker_link(visit.id)
    reviews.worker_review(token, ReviewInput(decision="dispute", statement="Not my visit."))
    assert any(i["visit"].id == visit.id for i in attention_items(store, reviews))
    reviews.resolve(visit.id, ResolutionInput(outcome="record_upheld", statement="Record stands."))
    assert all(i["visit"].id != visit.id for i in attention_items(store, reviews))


def test_run_triage_runner_injection_labels_source(case):
    store, reviews, _ = case
    result = run_triage(store, reviews, model_id="m", region="r", runner=lambda p: "agent says hi")
    assert result.source == "strands-agent"
    assert result.brief == "agent says hi"
    assert result.model == "m"


def test_run_triage_falls_back_without_strands(case, monkeypatch):
    store, reviews, _ = case
    monkeypatch.setitem(sys.modules, "strands", None)
    result = run_triage(store, reviews, model_id="m", region="r")
    assert result.source == "deterministic"
    assert result.fallback_reason


def test_tools_read_the_ledger(case):
    store, reviews, visit = case
    tools = {fn.__name__: fn for fn in make_tools(store, reviews)}
    sites = json.loads(tools["list_sites"]())
    assert sites[0]["name"] == "Alvarez residence"
    records = json.loads(tools["site_records"](sites[0]["id"]))
    assert records[0]["id"] == visit.id
    detail = json.loads(tools["record_detail"](visit.id))
    assert detail["evidence"]
    health = json.loads(tools["integrity"]())
    assert health["chain_ok"] is True


def test_record_detail_unknown_visit(case):
    store, reviews, _ = case
    tools = {fn.__name__: fn for fn in make_tools(store, reviews)}
    assert "error" in json.loads(tools["record_detail"]("vis_nope"))
