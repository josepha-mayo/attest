"""Agency-grade exports: schedule calendar feeds and visit registers.

These are *views* — convenience surfaces for people and tools that live
outside Attest (calendar apps, spreadsheets, billing reconciliation). They
carry no signature and claim nothing: an ICS event is a scheduled
expectation, a CSV row is an observation summary. The signed record chain
remains the only attestation surface.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

from .models import Schedule, Site, Visit, Worker


def _dt(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# --------------------------------------------------------------------- ICS


def _ics_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace(";", "\\;")
        .replace(",", "\\,")
        .replace("\n", "\\n")
        .replace("\r", "")
    )


def _ics_fold(line: str) -> str:
    """RFC 5545 §3.1 — fold content lines past 75 octets with CRLF + space."""
    out = []
    while len(line.encode()) > 75:
        # fold on a UTF-8 char boundary no later than octet 75
        cut = 75
        while len(line[:cut].encode()) > 75:
            cut -= 1
        out.append(line[:cut])
        line = " " + line[cut:]
    out.append(line)
    return "\r\n".join(out)


def schedule_ics(site: Site, schedules: list[Schedule], workers: dict[str, Worker]) -> str:
    """RFC 5545 calendar feed of a site's visit windows — subscribable in any
    calendar app. Events describe *expectations*; they never claim attendance."""
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//attest//schedule//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{_ics_escape(f'Attest — {site.name} visit windows')}",
        _ics_fold(
            "X-WR-CALDESC:"
            + _ics_escape(
                "Scheduled visit windows only — calendar entries are expectations, "
                "not observation evidence and never attendance claims."
            )
        ),
    ]
    for sch in sorted(schedules, key=lambda s: _dt(s.window_start) or datetime.min.replace(tzinfo=UTC)):
        worker = workers.get(sch.worker_id)
        summary = sch.service or "Scheduled visit"
        if worker:
            summary += f" — {worker.name}"
        desc = (
            f"Scheduled window: {sch.expected_minutes} min expected."
            " This entry is the plan, not evidence — the signed visit record is"
            " the only attestation surface."
        )
        stamp = _dt(sch.created_at) or datetime.now(UTC)
        lines += [
            "BEGIN:VEVENT",
            f"UID:{_ics_escape(sch.id)}@attest",
            f"DTSTAMP:{stamp.strftime('%Y%m%dT%H%M%SZ')}",
            f"DTSTART:{_dt(sch.window_start).strftime('%Y%m%dT%H%M%SZ')}",
            f"DTEND:{_dt(sch.window_end).strftime('%Y%m%dT%H%M%SZ')}",
            _ics_fold(f"SUMMARY:{_ics_escape(summary)}"),
            _ics_fold(f"DESCRIPTION:{_ics_escape(desc)}"),
            f"STATUS:{'CANCELLED' if sch.status == 'cancelled' else 'CONFIRMED'}",
            "TRANSP:OPAQUE",
            "END:VEVENT",
        ]
    lines.append("END:VCALENDAR")
    return "\r\n".join(lines) + "\r\n"


# --------------------------------------------------------------------- CSV

_CSV_HEADER = [
    "visit_id",
    "state",
    "scheduled_window_start_utc",
    "scheduled_window_end_utc",
    "expected_minutes",
    "worker_self_reported",
    "first_observed_utc",
    "last_observed_utc",
    "observed_span_minutes",
    "worker_checkin_utc",
    "checkin_lag_minutes",
    "receipt_id",
    "receipt_sha256",
    "review_state",
    "resolution_outcome",
    "resolution_reason_code",
    "resolution_reason_label",
    "worker_stated_reason_code",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    """Spreadsheet-formula guard: a leading = +- @ tab CR in a text cell is
    executable in Excel/Sheets — prefix with a quote, never drop content."""
    if isinstance(value, str) and value[:1] in _FORMULA_PREFIXES:
        return "'" + value
    return value


def _iso(dt: datetime | None) -> str:
    d = _dt(dt)
    return d.isoformat().replace("+00:00", "Z") if d else ""


def visits_csv(
    site: Site,
    visits: list[Visit],
    schedules: dict[str, Schedule],
    workers: dict[str, Worker],
    review_states: dict[str, str],
    receipt_hashes: dict[str, str],
    resolutions: dict[str, dict | None],
    worker_reasons: dict[str, str] | None = None,
) -> str:
    """One row per visit — a register for billing reconciliation or a mediator's
    spreadsheet. Column names stay honest: 'observed', never 'arrived/departed';
    'worker_self_reported', never 'worker' as fact. Resolution columns carry the
    coordinator's stated disposition + coded reason — an explanation, not a
    verified cause."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(_CSV_HEADER)
    for v in sorted(visits, key=lambda x: _dt(x.arrived_at) or datetime.min.replace(tzinfo=UTC)):
        sch = schedules.get(v.schedule_id or "")
        worker = workers.get(v.worker_id or "")
        lag = None
        if v.checkin_received_at and v.arrived_at:
            lag = round((v.checkin_received_at - v.arrived_at).total_seconds() / 60, 1)
        w.writerow(
            [
                _csv_safe(v.id),
                v.state,
                _iso(sch.window_start if sch else None),
                _iso(sch.window_end if sch else None),
                sch.expected_minutes if sch else "",
                _csv_safe(worker.name if worker else (v.worker_id or "")),
                _iso(v.arrived_at if v.has_observations else None),
                _iso(v.last_activity_at if v.has_observations else None),
                round(v.observed_span_minutes, 1) if v.observed_span_minutes is not None else "",
                _iso(v.checkin_received_at),
                lag if lag is not None else "",
                _csv_safe(v.receipt_id or ""),
                _csv_safe(receipt_hashes.get(v.id, "")),
                review_states.get(v.id, ""),
                (res := resolutions.get(v.id) or {}).get("outcome", ""),
                res.get("reason_code", ""),
                _csv_safe(res.get("reason_label", "")),
                (worker_reasons or {}).get(v.id, ""),
            ]
        )
    return buf.getvalue()
