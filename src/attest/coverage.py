"""Observation coverage: how much of a window the ingest pipeline was actually watching.

"Nobody came" is never attestable from events alone — but "our pipeline checked Ring
Event History K times, covering P% of the window, and Ring returned zero events" is.
Each successful poll covers the interval [since, polled_at] it queried; failed polls
and service downtime leave honest gaps that the report surfaces rather than hides.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from .store import Store

CoverageState = Literal["observed", "observed_with_events", "partial", "blind", "no_polls"]


def _clip(a: datetime, b: datetime, lo: datetime, hi: datetime) -> tuple[datetime, datetime] | None:
    s, e = max(a, lo), min(b, hi)
    return (s, e) if s < e else None


def coverage_report(store: Store, device_id: str, start: datetime, end: datetime, *, now: datetime) -> dict:
    """Compute how much of [start, end] successful Event History polls covered.

    A poll at T querying history since S covers [S, T]; later polls can retroactively
    cover earlier gaps. ``now`` bounds the report (polls after it are ignored).
    """
    end = min(end, now)
    if end <= start:
        return {"state": "no_window", "fraction": 0.0, "gaps": [], "polls": 0, "events": 0}

    covering = [
        o for o in store.poll_observations(device_id, start, now) if _clip(o.since, o.polled_at, start, end)
    ]
    spans = sorted(s for o in covering if o.ok and (s := _clip(o.since, o.polled_at, start, end)))
    covered: list[tuple[datetime, datetime]] = []
    for span in spans:
        if covered and span[0] <= covered[-1][1]:
            covered[-1] = (covered[-1][0], max(covered[-1][1], span[1]))
        else:
            covered.append(span)

    covered_seconds = sum((e - s).total_seconds() for s, e in covered)
    total = (end - start).total_seconds()
    fraction = min(1.0, covered_seconds / total)

    gaps: list[dict] = []
    cursor = start
    for s, e in covered:
        if s > cursor:
            gaps.append({"start": cursor.isoformat(), "end": s.isoformat()})
        cursor = max(cursor, e)
    if cursor < end:
        gaps.append({"start": cursor.isoformat(), "end": end.isoformat()})

    events = sum(o.events_returned for o in covering if o.ok)
    polls = len([o for o in covering if o.ok])
    if not covering:
        state: CoverageState = "no_polls"
    elif not polls:
        state = "blind"
    elif events:
        state = "observed_with_events"
    elif fraction >= 0.999:
        state = "observed"
    else:
        state = "partial"

    return {
        "state": state,
        "fraction": round(fraction, 4),
        "covered": [{"start": s.isoformat(), "end": e.isoformat()} for s, e in covered],
        "gaps": gaps,
        "polls": polls,
        "failed_polls": len([o for o in covering if not o.ok]),
        "events": events,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "claim": (
            "Attest polled Ring Event History during this window; it attests what the "
            "pipeline observed, not what physically happened"
        ),
    }
