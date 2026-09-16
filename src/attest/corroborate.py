"""Source-by-source corroboration for a visit record.

Every row states what a source reported — or explicitly did not — and what that
observation establishes. Agreement and disagreement between sources are shown
side by side; silence is labelled, never treated as evidence of absence.
"""

from __future__ import annotations

from .models import Evidence, Receipt, Schedule, Site, Visit


def corroboration(
    visit: Visit,
    site: Site,
    schedule: Schedule | None,
    evidence: list[Evidence],
    receipt: Receipt | None,
) -> list[dict]:
    camera = [e for e in evidence if e.source_device_id == site.door_camera_id]
    sensor = [e for e in evidence if site.door_sensor_id and e.source_device_id == site.door_sensor_id]
    snapshots = [e for e in evidence if e.kind.value == "snapshot" and e.media_sha256]
    history = (receipt.payload.get("ring_history") or []) if receipt else []
    coverage = (receipt.payload.get("history_poll_coverage") or {}) if receipt else {}

    def times(events):
        return f"{events[0].at:%H:%M}–{events[-1].at:%H:%M} UTC" if events else ""

    rows = [
        {
            "source": "Scheduled expectation",
            "status": f"{schedule.window_start:%H:%M}–{schedule.window_end:%H:%M}"
            if schedule
            else "unscheduled",
            "detail": (f"{schedule.expected_minutes} min · {schedule.service}" if schedule else ""),
            "establishes": "What was planned — never what happened",
        },
        {
            "source": f"Camera/doorbell {site.door_camera_id[-6:] if site.door_camera_id else ''}",
            "status": f"{len(camera)} event{'s' if len(camera) != 1 else ''} {times(camera)}"
            if camera
            else "silent",
            "detail": " + ".join(sorted({e.kind.value.replace("_", " ") for e in camera})),
            "establishes": "Device-observed activity timestamps only",
        },
        {
            "source": f"Contact sensor {site.door_sensor_id[-6:] if site.door_sensor_id else ''}",
            "status": "not bound"
            if not site.door_sensor_id
            else (
                f"{len(sensor)} event{'s' if len(sensor) != 1 else ''} {times(sensor)}"
                if sensor
                else "silent"
            ),
            "detail": " + ".join(sorted({e.kind.value.replace("_", " ") for e in sensor})),
            "establishes": "Open/close transitions at the door",
        },
        {
            "source": "Worker self-report",
            "status": f"check-in {visit.checked_in_at:%H:%M}" if visit.checked_in_at else "none received",
            "detail": "via single-use link" if visit.checked_in_at else "",
            "establishes": "The worker's account — a claim, not verification",
        },
        {
            "source": "Media on record",
            "status": f"{len(snapshots)} snapshot{'s' if len(snapshots) != 1 else ''}",
            "detail": "sha256 digests signed in receipt" if snapshots else "",
            "establishes": "Bytes received at fetch time, hashed at ingest",
        },
        {
            "source": "Ring Event History",
            "status": (
                f"{len(history)} corroborating entr{'ies' if len(history) != 1 else 'y'}"
                if history
                else ("unavailable" if receipt else "pending")
            ),
            "detail": "",
            "establishes": "Ring-side record independent of delivery path",
        },
        {
            "source": "Pipeline coverage",
            "status": (
                {
                    "observed": "fully watched",
                    "observed_with_events": "watched — events seen",
                    "partial": "partially watched",
                    "blind": "blind — polls failed",
                    "no_polls": "not polled",
                }.get(coverage.get("state"), "not polled")
                if coverage
                else "not polled"
            ),
            "detail": (
                f"{round((coverage.get('fraction') or 0) * 100)}% of window · "
                f"{coverage.get('polls', 0)} polls"
                if coverage
                else ""
            ),
            "establishes": "How much silence is meaningful vs. unwatched",
        },
    ]

    # Agreement callouts: where sources visibly diverge, say so explicitly.
    if visit.checked_in_at and camera:
        delta = (visit.checked_in_at - camera[0].at).total_seconds() / 60
        if abs(delta) >= 10:
            direction = "check-in later" if delta > 0 else "check-in earlier"
            rows.append(
                {
                    "source": "Source divergence",
                    "status": f"{abs(delta):.0f} min apart",
                    "detail": f"first device observation vs. worker check-in ({direction})",
                    "establishes": "Discrepancy to review — neither source is authoritative",
                }
            )
    return rows
