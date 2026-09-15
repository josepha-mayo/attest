"""Non-destructive data-lifecycle reporting.

Nothing in this module deletes. ``build_report`` describes what exists, how old
it is, and which records a retention policy would touch. Removing retained data
remains a separate, explicit, reviewed action — this report is the input to that
review, not the action itself.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import VisitState, utcnow
from .store import Store

_CAP = 200  # max items listed per candidate bucket; totals stay exact
_TERMINAL_DELIVERY = ("done", "rejected", "failed")


@dataclass(frozen=True)
class RetentionPolicy:
    visits_days: int = 180
    media_days: int = 180
    deliveries_days: int = 30
    grants_days: int = 7
    seen_days: int = 30
    late_events_days: int = 90


def build_report(
    store: Store,
    inbox: Any | None,
    media_root: Path,
    *,
    now: datetime | None = None,
    policy: RetentionPolicy | None = None,
) -> dict:
    now = now or utcnow()
    policy = policy or RetentionPolicy()

    totals = store.stats()
    totals["deliveries"] = inbox.counts() if inbox is not None else {}
    media_files = _media_files(media_root)
    totals["media"] = {"files": len(media_files), "bytes": sum(f["bytes"] for f in media_files)}

    grants = []
    used = expired = 0
    for kind, grant in [("checkin", g) for g in store.checkin_grants()] + [
        ("review", g) for g in store.review_grants()
    ]:
        is_used = grant.used_at is not None
        is_expired = grant.expires_at < now - timedelta(days=policy.grants_days)
        used += is_used
        expired += is_expired
        if is_used or is_expired:
            grants.append(
                {
                    "kind": kind,
                    "id": grant.id,
                    "expires_at": grant.expires_at.isoformat(),
                    "used": is_used,
                }
            )
    totals["grants"] = {"used": used, "expired": expired}

    visit_cutoff = now - timedelta(days=policy.visits_days)
    closed = store.visits(
        states=(VisitState.CLOSED, VisitState.NO_OBSERVATION, VisitState.NO_SHOW), limit=100_000
    )
    old_visits = [
        v
        for v in closed
        if (v.closed_at or v.last_activity_at) and (v.closed_at or v.last_activity_at) < visit_cutoff
    ]

    media_cutoff = now - timedelta(days=policy.media_days)
    closed_states = (VisitState.CLOSED, VisitState.NO_OBSERVATION, VisitState.NO_SHOW)
    media_candidates = []
    for f in media_files:
        visit_id = Path(f["path"]).parts[0] if Path(f["path"]).parts else ""
        visit = store.visit(visit_id)
        if visit is None:
            media_candidates.append({**f, "reason": "no matching visit record"})
        elif visit.state in closed_states and (visit.closed_at or visit.last_activity_at) < media_cutoff:
            media_candidates.append({**f, "reason": "visit past media retention"})

    seen_total, seen_ids = store.stale_seen(now - timedelta(days=policy.seen_days), limit=_CAP)

    late = []
    for row in store.late_event_rows():
        at = _late_event_at(row["body"])
        if at is None or at < now - timedelta(days=policy.late_events_days):
            late.append({"id": row["id"], "site_id": row["site_id"], "at": at and at.isoformat()})

    deliveries = []
    if inbox is not None:
        cutoff = (now - timedelta(days=policy.deliveries_days)).timestamp()
        for e in inbox.entries():
            if e["status"] in _TERMINAL_DELIVERY and e["received_at"] < cutoff:
                deliveries.append(
                    {
                        "id": e["id"],
                        "status": e["status"],
                        "attempts": e["attempts"],
                        "error_code": e["error_code"],
                        "received_at": datetime.fromtimestamp(e["received_at"], tz=now.tzinfo).isoformat(),
                    }
                )

    def bucket(items: list) -> dict:
        return {"total": len(items), "items": items[:_CAP]}

    return {
        "generated_at": now.isoformat(),
        "mode": "preview",
        "policy": asdict(policy),
        "totals": totals,
        "candidates": {
            "closed_visits": bucket(
                [
                    {
                        "id": v.id,
                        "state": str(v.state),
                        "site_id": v.site_id,
                        "closed_at": (v.closed_at or v.last_activity_at).isoformat(),
                    }
                    for v in old_visits
                ]
            ),
            "media_files": {
                "total": len(media_candidates),
                "bytes": sum(f["bytes"] for f in media_candidates),
                "items": media_candidates[:_CAP],
            },
            "deliveries": bucket(deliveries),
            "grants": bucket(grants),
            "seen_requests": {"total": seen_total, "items": seen_ids},
            "late_events": bucket(late),
        },
        "note": "Preview only: nothing was deleted or modified. "
        "Removing records requires a separate explicit, reviewed action.",
    }


def _media_files(media_root: Path) -> list[dict]:
    root = Path(media_root)
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out.append({"path": str(p.relative_to(root)), "bytes": p.stat().st_size})
    return out


def _late_event_at(body: dict) -> datetime | None:
    try:
        ms = body["data"]["attributes"]["timestamp"]
        return datetime.fromtimestamp(ms / 1000, tz=UTC)
    except (KeyError, TypeError, ValueError, OSError):
        return None
