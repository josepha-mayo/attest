"""Plain-language visit summaries.

``TemplateSummarizer`` is deterministic and dependency-free. ``BedrockSummarizer`` sends the
visit facts plus the arrival/departure snapshots to an Amazon Bedrock model through the
Converse API and asks for a short, factual account. The prompt forbids identifying people;
the product is about *whether a visit happened as scheduled*, not *who* someone is.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Protocol
from zoneinfo import ZoneInfo

from .media import MediaStore
from .models import Evidence, EvidenceKind, Schedule, Site, Visit

log = logging.getLogger("attest.summarize")


class Summarizer(Protocol):
    name: str

    def summarize(
        self,
        visit: Visit,
        site: Site,
        schedule: Schedule | None,
        worker_name: str | None,
        evidence: list[Evidence],
        media: MediaStore,
    ) -> str: ...


def _fmt(dt: datetime, tz: str) -> str:
    return dt.astimezone(ZoneInfo(tz)).strftime("%I:%M %p").lstrip("0")


def facts_for_prompt(
    visit: Visit,
    site: Site,
    schedule: Schedule | None,
    worker_name: str | None,
    evidence: list[Evidence],
    tz: str,
) -> dict:
    return {
        "site": site.name,
        "worker": worker_name or "unknown (no check-in)",
        "scheduled_window": (
            f"{_fmt(schedule.window_start, tz)}-{_fmt(schedule.window_end, tz)}" if schedule else None
        ),
        "expected_minutes": schedule.expected_minutes if schedule else None,
        "service": schedule.service if schedule else None,
        "arrived_at": _fmt(visit.arrived_at, tz),
        "checked_in_at": _fmt(visit.checked_in_at, tz) if visit.checked_in_at else None,
        "departed_at": _fmt(visit.departed_at, tz) if visit.departed_at else None,
        "duration_minutes": round(visit.duration_minutes) if visit.duration_minutes is not None else None,
        "flags": [f.message for f in visit.flags],
        "timeline": [
            f"{_fmt(e.at, tz)} {e.kind.value}" + (f" ({e.ring_sub_type})" if e.ring_sub_type else "")
            for e in evidence
            if e.kind != EvidenceKind.SNAPSHOT
        ],
    }


class TemplateSummarizer:
    name = "template"

    def __init__(self, tz: str = "UTC"):
        self.tz = tz

    def summarize(self, visit, site, schedule, worker_name, evidence, media) -> str:  # noqa: D102
        f = facts_for_prompt(visit, site, schedule, worker_name, evidence, self.tz)
        who = f["worker"] if worker_name else "An unidentified visitor"
        parts = [f"{who} arrived at {site.name} at {f['arrived_at']}"]
        if f["checked_in_at"]:
            parts[-1] += f" and confirmed presence at {f['checked_in_at']}"
        parts[-1] += "."
        if f["departed_at"]:
            parts.append(
                f"Departure was detected at {f['departed_at']}, "
                f"a stay of about {f['duration_minutes']} minutes"
                + (f" against {f['expected_minutes']} expected." if f["expected_minutes"] else ".")
            )
        if f["flags"]:
            parts.append("Notes: " + "; ".join(f["flags"]) + ".")
        else:
            parts.append("No discrepancies were detected.")
        return " ".join(parts)


_SYSTEM = (
    "You write neutral visit records for home-service work (home health aides, cleaners, dog walkers) "
    "from door-camera evidence. Write 2-4 plain sentences for a family member or agency coordinator. "
    "State arrival, check-in, departure and duration versus what was expected, and call out any flags. "
    "Describe only what is visible in snapshots at the level of 'a person carrying a bag'. "
    "Never guess identity, age, race, gender, or emotional state. Never speculate beyond the evidence. "
    "Do not use markdown."
)


class BedrockSummarizer:
    name = "bedrock"

    def __init__(self, model_id: str, region: str, tz: str = "UTC", fallback: Summarizer | None = None):
        import boto3  # optional dependency

        self.client = boto3.client("bedrock-runtime", region_name=region)
        self.model_id = model_id
        self.tz = tz
        self.fallback = fallback or TemplateSummarizer(tz)

    def summarize(self, visit, site, schedule, worker_name, evidence, media) -> str:  # noqa: D102
        facts = facts_for_prompt(visit, site, schedule, worker_name, evidence, self.tz)
        content: list[dict] = [{"text": "Visit facts (JSON):\n" + json.dumps(facts, indent=2)}]
        for e in evidence:
            if e.kind == EvidenceKind.SNAPSHOT and e.media_path:
                data = media.read(e.media_path)
                if not data or not media.verify(e.media_path, e.media_sha256 or ""):
                    continue
                fmt = "png" if data.startswith(b"\x89PNG") else "jpeg"
                content.append({"text": f"Door camera snapshot at {e.note}:"})
                content.append({"image": {"format": fmt, "source": {"bytes": data}}})
        content.append({"text": "Write the visit record."})
        try:
            resp = self.client.converse(
                modelId=self.model_id,
                system=[{"text": _SYSTEM}],
                messages=[{"role": "user", "content": content}],
                inferenceConfig={"maxTokens": 300, "temperature": 0.2},
            )
            text = "".join(b.get("text", "") for b in resp["output"]["message"]["content"]).strip()
            return text or self.fallback.summarize(visit, site, schedule, worker_name, evidence, media)
        except Exception as exc:  # noqa: BLE001 - never block receipt issuance on the LLM
            log.warning("bedrock summarize failed (%s); using template", exc)
            return self.fallback.summarize(visit, site, schedule, worker_name, evidence, media)


def build(kind: str, *, tz: str, model_id: str, region: str) -> Summarizer:
    if kind == "bedrock":
        return BedrockSummarizer(model_id, region, tz)
    return TemplateSummarizer(tz)
