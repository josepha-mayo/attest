"""Observation coverage: how much of a window the ingest pipeline was actually watching.

"Nobody came" is never attestable from events alone — but "our pipeline checked Ring
Event History K times, covering P% of the window, and Ring returned zero events" is.
Each successful poll covers the interval [since, polled_at] it queried; failed polls
and service downtime leave honest gaps that the report surfaces rather than hides.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from .models import CoverageEvent
from .store import Store

CoverageState = Literal["observed", "observed_with_events", "partial", "blind", "no_polls"]


def _clip(a: datetime, b: datetime, lo: datetime, hi: datetime) -> tuple[datetime, datetime] | None:
    s, e = max(a, lo), min(b, hi)
    return (s, e) if s < e else None


def _explained_spans(events: list[CoverageEvent], end: datetime) -> list[dict]:
    """Pair interrupting lifecycle events with their restoring event per channel
    (device id; account-scoped events share the ``None`` channel). An unclosed
    interruption explains silence through the window end."""
    open_intervals: dict[str | None, tuple[datetime, CoverageEvent]] = {}
    spans: list[dict] = []
    for ev in events:
        key = ev.device_id
        if ev.interrupts:
            open_intervals.setdefault(key, (ev.at, ev))
        elif key in open_intervals:
            opened_at, opened = open_intervals.pop(key)
            spans.append(
                {
                    "start": opened_at,
                    "end": ev.at,
                    "kind": opened.kind.value,
                    "device_id": opened.device_id,
                    "restored_by": ev.kind.value,
                }
            )
    for opened_at, opened in open_intervals.values():
        spans.append(
            {
                "start": opened_at,
                "end": end,
                "kind": opened.kind.value,
                "device_id": opened.device_id,
                "restored_by": None,
            }
        )
    return spans


def coverage_report(
    store: Store,
    device_id: str,
    start: datetime,
    end: datetime,
    *,
    now: datetime,
    site_id: str | None = None,
) -> dict:
    """Compute how much of [start, end] successful Event History polls covered.

    A poll at T querying history since S covers [S, T]; later polls can retroactively
    cover earlier gaps. ``now`` bounds the report (polls after it are ignored).
    With ``site_id``, Ring lifecycle events recorded for the site annotate the
    report: coverage gaps that overlap a signed-source interruption (camera
    offline, subscription ended, account unlinked) are marked ``explained`` —
    silence with a recorded cause, still never proof of absence.
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

    lifecycle: list[CoverageEvent] = []
    explained: list[dict] = []
    if site_id is not None:
        lifecycle = [ev for ev in store.coverage_events(site_id, until=end) if ev.at <= end]
        explained = _explained_spans(lifecycle, end)

    gaps: list[dict] = []
    cursor = start
    for s, e in covered:
        if s > cursor:
            gaps.append({"start": cursor.isoformat(), "end": s.isoformat()})
        cursor = max(cursor, e)
    if cursor < end:
        gaps.append({"start": cursor.isoformat(), "end": end.isoformat()})

    for gap in gaps:
        gs = datetime.fromisoformat(gap["start"])
        ge = datetime.fromisoformat(gap["end"])
        # Only this device's channel — or an account-scoped interruption —
        # explains this device's silence; a sensor going dark says nothing
        # about the camera's gap.
        why = [
            s for s in explained if s["start"] < ge and s["end"] > gs and s["device_id"] in (None, device_id)
        ]
        if why:
            gap["explained"] = True
            gap["explained_by"] = [
                {
                    "kind": s["kind"],
                    "device_id": s["device_id"],
                    "start": s["start"].isoformat(),
                    "end": s["end"].isoformat(),
                    "restored_by": s["restored_by"],
                }
                for s in why
            ]

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

    report = {
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
    if site_id is not None:
        report["interruptions"] = [
            {
                "kind": ev.kind.value,
                "at": ev.at.isoformat(),
                "device_id": ev.device_id,
                "interrupts": ev.interrupts,
                "detail": ev.detail,
            }
            for ev in lifecycle
            if ev.at >= start
        ]
    return report
