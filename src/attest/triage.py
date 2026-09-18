"""Coordinator triage — a Strands agent that reads the ledger through real
tools and writes the week's "needs attention" brief.

This is the AWS Builder *agentic* surface: not a text-generation call but an
orchestrated agent deciding which records to inspect. When Strands or Bedrock
is unavailable the same facts render deterministically — and the brief labels
which source produced it, exactly like the summarizer labels its source.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

_SYSTEM = """You are a triage assistant for Attest, a tamper-evident record system
for scheduled home-service visits. Use the tools to inspect the record set,
then write a short "needs attention" brief for the coordinator.

Rules:
- Report record states and evidence, never claims of presence or absence.
- "no_observation" means nothing was observed — NOT that the worker was absent.
- "unmatched" means an observation arrived outside every scheduled window.
- Worker stances (contested/corrected/inconclusive/awaiting) always need review.
- End with a one-line count summary: N records, K need attention."""


def attention_items(store, reviews, *, limit: int = 50) -> list[dict]:
    """The same attention computation the dashboard renders — the deterministic
    baseline the agent brief is compared against."""
    items = []
    visits = store.visits(limit=limit)
    for v in visits:
        cs = reviews.countersign(v.id) if v.receipt_id else None
        if cs and cs["state"] == "contested":
            items.append({"visit": v, "why": "worker disputes this record", "level": "bad"})
        elif cs and cs["state"] in ("corrected", "inconclusive"):
            items.append({"visit": v, "why": cs["detail"], "level": "warn"})
        elif v.state.value == "unmatched":
            items.append({"visit": v, "why": "observation matched no schedule", "level": "warn"})
        elif v.flags:
            items.append(
                {"visit": v, "why": f"{len(v.flags)} review note(s): {v.flags[0].code}", "level": "warn"}
            )
        elif cs and cs["state"] == "awaiting":
            items.append({"visit": v, "why": "worker statement pending", "level": "muted"})
    return items


def deterministic_brief(store, reviews) -> str:
    """The zero-dependency brief — what `attest triage` prints when the agent
    path is unavailable."""
    items = attention_items(store, reviews)
    if not items:
        return "Nothing needs attention — every record in view is signed and uncontested."
    lines = [f"- {i['visit'].id} ({i['visit'].state.value}): {i['why']}" for i in items]
    return f"{len(items)} record(s) need attention:\n" + "\n".join(lines)


def make_tools(store, reviews):
    """Strands @tool functions bound to this store — the agent's read window
    into the ledger. Returns plain functions (works with or without strands)."""

    def list_sites() -> str:
        """List every registered site: id, name, bound devices."""
        out = [
            {"id": s.id, "name": s.name, "camera": s.door_camera_id, "sensor": s.door_sensor_id}
            for s in store.sites()
        ]
        return json.dumps(out)

    def site_records(site_id: str, limit: int = 25) -> str:
        """List a site's visit records: id, state, window, worker, evidence count."""
        rows = []
        for v in store.visits(site_id=site_id, limit=limit):
            cs = reviews.countersign(v.id) if v.receipt_id else None
            rows.append(
                {
                    "id": v.id,
                    "state": v.state.value,
                    "arrived": v.arrived_at.isoformat() if v.arrived_at else None,
                    "worker": v.worker_id,
                    "evidence": len(store.evidence_for(v.id)),
                    "receipt": bool(v.receipt_id),
                    "stance": cs["state"] if cs else None,
                    "flags": [f.code for f in v.flags],
                }
            )
        return json.dumps(rows)

    def record_detail(visit_id: str) -> str:
        """Full detail for one record: evidence kinds, coverage, stance, flags."""
        v = store.visit(visit_id)
        if v is None:
            return json.dumps({"error": "unknown visit"})
        receipt = store.receipt_for_visit(visit_id)
        cs = reviews.countersign(visit_id) if receipt else None
        cov = (receipt.payload.get("history_poll_coverage") or {}) if receipt else {}
        return json.dumps(
            {
                "id": v.id,
                "state": v.state.value,
                "evidence": [
                    {"kind": e.kind.value, "at": e.at.isoformat()} for e in store.evidence_for(visit_id)
                ],
                "coverage_fraction": cov.get("fraction"),
                "coverage_gaps": len(cov.get("gaps", [])),
                "stance": cs,
                "flags": [{"code": f.code, "message": f.message} for f in v.flags],
            }
        )

    def integrity() -> str:
        """Integrity health: receipt-chain verdict and mutation-journal verdict."""
        from . import ledger

        ok, why = ledger.verify_chain(store.receipts())
        j = store.verify_journal()
        return json.dumps({"chain_ok": ok, "chain": why, "journal": j})

    return [list_sites, site_records, record_detail, integrity]


@dataclass
class TriageResult:
    brief: str
    source: str  # "strands-agent" | "deterministic"
    model: str | None
    fallback_reason: str | None


def run_triage(
    store,
    reviews,
    *,
    model_id: str,
    region: str,
    prompt: str = "What needs the coordinator's attention this week, and why?",
    runner=None,
) -> TriageResult:
    """Run the agent if strands+Bedrock are reachable; otherwise render the
    deterministic brief. ``runner`` injects a fake agent for tests."""
    if runner is not None:
        text = runner(prompt)
        return TriageResult(text, "strands-agent", model_id, None)
    try:
        from strands import Agent, tool
        from strands.models import BedrockModel

        agent = Agent(
            model=BedrockModel(model_id=model_id, region_name=region),
            system_prompt=_SYSTEM,
            tools=[tool(fn) for fn in make_tools(store, reviews)],
        )
        result = agent(prompt)
        text = str(result)
        if not text.strip():
            raise ValueError("empty agent output")
        return TriageResult(text, "strands-agent", model_id, None)
    except Exception as exc:  # noqa: BLE001 — honest fallback, never block triage
        reason = type(exc).__name__
        log.warning("agent triage unavailable (%s); deterministic brief", reason)
        return TriageResult(deterministic_brief(store, reviews), "deterministic", None, reason)
