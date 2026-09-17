"""Positions for the visit-page timeline strip — pure function, no I/O.

The template renders an SVG band: the scheduled window, which sub-intervals
Event History polling actually watched (from the signed coverage attestation),
each observation/check-in as a tick, and axis labels. Percentages are computed
here so the template stays declarative and the math stays testable.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

_KIND_LABEL = {
    "arrival_motion": "motion",
    "doorbell": "doorbell",
    "door_opened": "door opened",
    "door_closed": "door closed",
    "activity": "activity",
    "departure_motion": "departure cue",
    "on_demand": "on-demand media",
    "snapshot": "snapshot",
    "checkin": "worker check-in",
    "late": "late-arriving event",
}


def _iso(s: Any) -> datetime:
    return s if isinstance(s, datetime) else datetime.fromisoformat(str(s))


def timeline_strip(
    *,
    schedule: Any | None,
    evidence: list[Any],
    checked_in_at: datetime | None,
    coverage: dict | None,
    late_events: list[Any] | None = None,
) -> dict | None:
    """Return positioned elements (percent coords) for the strip, or None when
    there is nothing worth drawing (no window and no observations)."""
    points: list[datetime] = []
    win_start = _iso(schedule.window_start) if schedule else None
    win_end = _iso(schedule.window_end) if schedule else None
    for e in evidence:
        points.append(_iso(e.at))
    if checked_in_at:
        points.append(_iso(checked_in_at))
    for iv in (coverage or {}).get("covered", []):
        points.extend((_iso(iv["start"]), _iso(iv["end"])))
    for e in late_events or []:
        at = getattr(e, "occurred_at", None) or getattr(e, "at", None)
        if at:
            points.append(_iso(at))
    if win_start:
        points.extend((win_start, win_end))
    if not points:
        return None

    lo = min(points)
    hi = max(points)
    if hi - lo < timedelta(minutes=10):  # pad degenerate windows
        mid = lo + (hi - lo) / 2
        lo, hi = mid - timedelta(minutes=5), mid + timedelta(minutes=5)
    pad = (hi - lo) * 0.04
    lo, hi = lo - pad, hi + pad
    span = (hi - lo).total_seconds()

    def x(dt: datetime) -> float:
        return round((dt - lo).total_seconds() / span * 100, 2)

    def band(a: datetime, b: datetime) -> dict:
        xa, xb = x(a), x(b)
        return {"x": xa, "w": max(0.4, round(xb - xa, 2))}

    bands = []
    if coverage:
        covered = [(_iso(i["start"]), _iso(i["end"])) for i in coverage.get("covered", [])]
        gaps = [(_iso(i["start"]), _iso(i["end"])) for i in coverage.get("gaps", [])]
        bands = [{"watched": True, **band(a, b)} for a, b in covered] + [
            {"watched": False, **band(a, b)} for a, b in gaps
        ]

    marks = []
    for e in evidence:
        kind = getattr(e, "kind", "activity")
        kind = getattr(kind, "value", kind)
        marks.append(
            {
                "x": x(_iso(e.at)),
                "kind": kind,
                "label": _KIND_LABEL.get(kind, kind.replace("_", " ")),
                "title": f"{_KIND_LABEL.get(kind, kind)} — {_iso(e.at).isoformat()}",
            }
        )
    if checked_in_at:
        marks.append(
            {
                "x": x(_iso(checked_in_at)),
                "kind": "checkin",
                "label": _KIND_LABEL["checkin"],
                "title": f"worker check-in — {checked_in_at.isoformat()}",
            }
        )
    for e in late_events or []:
        at = getattr(e, "occurred_at", None) or getattr(e, "at", None)
        if at:
            marks.append(
                {
                    "x": x(_iso(at)),
                    "kind": "late",
                    "label": _KIND_LABEL["late"],
                    "title": f"late-arriving event — {_iso(at).isoformat()}",
                }
            )

    # 4–5 readable axis ticks
    ticks = []
    step = span / 4
    for i in range(5):
        dt = lo + timedelta(seconds=step * i)
        ticks.append({"x": x(dt), "label": dt.strftime("%I:%M%p").lstrip("0").lower()})

    return {
        "window": band(win_start, win_end) if win_start else None,
        "bands": bands,
        "marks": marks,
        "ticks": ticks,
        "start": lo.isoformat(),
        "end": hi.isoformat(),
        "has_coverage": bool(coverage),
    }
