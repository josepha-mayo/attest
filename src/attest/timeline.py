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


def _get(obj: Any, name: str) -> Any:
    """Attribute-or-key access — evidence arrives as models on the visit page
    and as signed-payload dicts on the worker review page."""
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def timeline_strip(
    *,
    schedule: Any | None,
    evidence: list[Any],
    checked_in_at: datetime | None,
    coverage: dict | None,
    late_events: list[Any] | None = None,
    bounds: tuple[datetime, datetime] | None = None,
) -> dict | None:
    """Return positioned elements (percent coords) for the strip, or None when
    there is nothing worth drawing (no window and no observations). ``bounds``
    pins the axis (e.g. midnight→midnight for a day row in a week strip);
    without it the axis auto-fits the data."""
    points: list[datetime] = []
    win_start = _iso(_get(schedule, "window_start")) if schedule else None
    win_end = _iso(_get(schedule, "window_end")) if schedule else None
    for e in evidence:
        points.append(_iso(_get(e, "at")))
    if checked_in_at:
        points.append(_iso(checked_in_at))
    for iv in (coverage or {}).get("covered", []):
        points.extend((_iso(iv["start"]), _iso(iv["end"])))
    for e in late_events or []:
        at = _get(e, "occurred_at") or _get(e, "at")
        if at:
            points.append(_iso(at))
    if win_start:
        points.extend((win_start, win_end))
    if not points:
        return None

    if bounds:
        lo, hi = bounds
    else:
        lo = min(points)
        hi = max(points)
        if hi - lo < timedelta(minutes=10):  # pad degenerate windows
            mid = lo + (hi - lo) / 2
            lo, hi = mid - timedelta(minutes=5), mid + timedelta(minutes=5)
        pad = (hi - lo) * 0.04
        lo, hi = lo - pad, hi + pad
    span = (hi - lo).total_seconds()

    def x(dt: datetime) -> float:
        return round(min(max((dt - lo).total_seconds() / span, 0.0), 1.0) * 100, 2)

    def band(a: datetime, b: datetime) -> dict | None:
        a, b = max(a, lo), min(b, hi)
        if b <= a:
            return None
        xa, xb = x(a), x(b)
        return {"x": xa, "w": max(0.4, round(xb - xa, 2))}

    bands = []
    if coverage:
        covered = [(_iso(i["start"]), _iso(i["end"])) for i in coverage.get("covered", [])]
        gaps = [(_iso(i["start"]), _iso(i["end"])) for i in coverage.get("gaps", [])]
        bands = [{"watched": True, **b} for a, b_ in covered if (b := band(a, b_))] + [
            {"watched": False, **b} for a, b_ in gaps if (b := band(a, b_))
        ]

    marks = []
    for e in evidence:
        at = _iso(_get(e, "at"))
        if bounds and not lo <= at <= hi:
            continue
        kind = _get(e, "kind") or "activity"
        kind = getattr(kind, "value", kind)
        marks.append(
            {
                "x": x(at),
                "kind": kind,
                "label": _KIND_LABEL.get(kind, kind.replace("_", " ")),
                "title": f"{_KIND_LABEL.get(kind, kind)} — {at.isoformat()}",
            }
        )
    if checked_in_at and (not bounds or lo <= checked_in_at <= hi):
        marks.append(
            {
                "x": x(checked_in_at),
                "kind": "checkin",
                "label": _KIND_LABEL["checkin"],
                "title": f"worker check-in — {checked_in_at.isoformat()}",
            }
        )
    for e in late_events or []:
        at = _get(e, "occurred_at") or _get(e, "at")
        if at and (not bounds or lo <= _iso(at) <= hi):
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


def day_strips(
    *,
    visits: list[Any],
    evidence_by_visit: dict[str, list[Any]],
    schedules: list[Any],
    coverage_by_visit: dict[str, dict],
    tz: Any,
    max_days: int = 10,
) -> list[dict]:
    """One strip per local day covering every record — shared 00:00–24:00 axis,
    newest first. Each row shows the scheduled window(s), poll coverage bands,
    and observation marks so a week of service reads at a glance."""
    items: list[tuple[datetime, datetime, str, Any]] = []  # (start, end, kind, obj)
    for sch in schedules:
        ws, we = _iso(_get(sch, "window_start")), _iso(_get(sch, "window_end"))
        if ws and we:
            items.append((ws, we, "schedule", sch))
    for v in visits:
        vid = _get(v, "id")
        for e in evidence_by_visit.get(vid, []):
            at = _iso(_get(e, "at"))
            items.append((at, at, "evidence", e))
        ci = _get(v, "checked_in_at")
        if ci:
            items.append((_iso(ci), _iso(ci), "checkin", v))
        cov = coverage_by_visit.get(vid) or {}
        for key, watched in (("covered", True), ("gaps", False)):
            for iv in cov.get(key, []):
                items.append((_iso(iv["start"]), _iso(iv["end"]), "coverage", (iv, watched)))
    if not items:
        return []

    def days_between(a: datetime, b: datetime) -> list[datetime]:
        """Local midnights from a's day through b's day."""
        first = a.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
        last = b.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
        out = []
        d = first
        while d <= last:
            out.append(d)
            d += timedelta(days=1)
        return out

    touched = sorted({d for a, b, _k, _o in items for d in days_between(a, b)}, reverse=True)
    strips = []
    for day in touched[:max_days]:
        lo, hi = day, day + timedelta(days=1)
        sched_today = [
            {"window_start": max(ws, lo), "window_end": min(we, hi)}
            for ws, we, kind, _o in items
            if kind == "schedule" and ws < hi and we > lo
        ]
        ev_today = [o for a, _b, kind, o in items if kind == "evidence" and lo <= a < hi]
        cov_today: dict[str, list[dict]] = {"covered": [], "gaps": []}
        for a, b, kind, o in items:
            if kind == "coverage":
                iv, watched = o
                if a < hi and b > lo:
                    cov_today["covered" if watched else "gaps"].append(
                        {"start": max(a, lo).isoformat(), "end": min(b, hi).isoformat()}
                    )
        checkins = [a for a, _b, kind, _o in items if kind == "checkin" and lo <= a < hi]
        strip = timeline_strip(
            schedule=sched_today[0] if sched_today else None,
            evidence=ev_today,
            checked_in_at=checkins[0] if checkins else None,
            coverage=cov_today if cov_today["covered"] or cov_today["gaps"] else None,
            bounds=(lo, hi),
        )
        # extra schedules/check-ins beyond the first fold into marks via evidence anyway;
        # second windows are rare — draw the first only for readability.
        if strip:
            strips.append({"label": day.strftime("%a %b %d"), "strip": strip})
    return strips
