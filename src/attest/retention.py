"""Data-lifecycle reporting and explicitly confirmed retention.

``build_report`` is non-destructive: it describes what exists, how old it is,
and which records a retention policy would touch. ``apply`` deletes only the
non-chain categories (terminal deliveries, expired/used grants, stale dedupe
keys, old late events, media files past retention, and old poll observations —
the signed coverage claims in receipts survive their raw poll log) — and only when the
caller supplies the ``apply_token`` from a matching preview, so deletion always
targets exactly the set an operator just reviewed. Closed visits, evidence,
receipts, and reviews are chain-linked records; removing them requires a future
export-and-archive step and is deliberately not implemented here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import VisitState, utcnow
from .store import Store

_CAP = 200  # max items listed per candidate bucket; totals stay exact
_CLOSED = (VisitState.CLOSED, VisitState.NO_OBSERVATION, VisitState.NO_SHOW)
_TERMINAL_DELIVERY = ("done", "rejected", "failed")


@dataclass(frozen=True)
class RetentionPolicy:
    visits_days: int = 180
    media_days: int = 180
    deliveries_days: int = 30
    grants_days: int = 7
    seen_days: int = 30
    late_events_days: int = 90
    poll_observations_days: int = 90
    coverage_events_days: int = 90


def build_report(
    store: Store,
    inbox: Any | None,
    media_root: Path,
    *,
    now: datetime | None = None,
    policy: RetentionPolicy | None = None,
) -> dict:
    """Preview what the policy would touch. Never modifies data."""
    now = now or utcnow()
    policy = policy or RetentionPolicy()

    totals = store.stats()
    totals["deliveries"] = inbox.counts() if inbox is not None else {}
    media_files = _media_files(media_root)
    totals["media"] = {"files": len(media_files), "bytes": sum(f["bytes"] for f in media_files)}

    cands = _candidates(store, inbox, media_root, now, policy)
    totals["grants"] = cands.pop("grant_stats")

    return {
        "generated_at": now.isoformat(),
        "mode": "preview",
        "policy": asdict(policy),
        "totals": totals,
        "candidates": {
            "closed_visits": _bucket(cands["closed_visits"]),
            "media_files": {
                "total": len(cands["media_files"]),
                "bytes": sum(f["bytes"] for f in cands["media_files"]),
                "items": cands["media_files"][:_CAP],
            },
            "deliveries": _bucket(cands["deliveries"]),
            "grants": _bucket(cands["grants"]),
            "seen_requests": {
                "total": cands["seen_total"],
                "items": cands["seen_requests"][:_CAP],
            },
            "late_events": _bucket(cands["late_events"]),
            "poll_observations": _bucket(cands["poll_observations"]),
            "coverage_events": _bucket(cands["coverage_events"]),
        },
        "apply_token": _apply_token(cands, policy),
        "apply_scope": sorted(
            {
                "deliveries",
                "grants",
                "seen_requests",
                "late_events",
                "media_files",
                "poll_observations",
                "coverage_events",
            }
        ),
        "note": "Preview only: nothing was deleted or modified. apply() deletes only the "
        "non-chain categories listed in apply_scope, and only for the exact set this token "
        "covers. Closed visits, evidence, receipts, and reviews are chain-linked and are not "
        "deleted in place. Signed history_poll_coverage claims (and their interruption "
        "annotations) persist in receipts after the raw poll/coverage rows are purged.",
    }


def apply(
    store: Store,
    inbox: Any | None,
    media_root: Path,
    *,
    now: datetime | None = None,
    policy: RetentionPolicy | None = None,
    confirm: str,
) -> dict:
    """Delete the previewed non-chain candidates, gated by ``apply_token``.

    ``confirm`` must equal the ``apply_token`` from a current preview; if data has
    changed since then the token mismatches and nothing is deleted.
    """
    now = now or utcnow()
    policy = policy or RetentionPolicy()
    cands = _candidates(store, inbox, media_root, now, policy)
    if confirm != _apply_token(cands, policy):
        raise ValueError("retention candidates changed since preview; re-run the report")

    deleted = {
        "deliveries": inbox.delete([d["id"] for d in cands["deliveries"]]) if inbox is not None else 0,
        "seen_requests": store.delete_seen(cands["seen_requests"]),
        "late_events": store.delete_late_events([e["id"] for e in cands["late_events"]]),
        "poll_observations": store.delete_poll_observations([o["id"] for o in cands["poll_observations"]]),
        "coverage_events": store.delete_coverage_events([e["id"] for e in cands["coverage_events"]]),
        "media_files": _delete_media(media_root, [f["path"] for f in cands["media_files"]]),
    }
    deleted["grants"] = (
        store.delete_checkin_grants([g["id"] for g in cands["grants"] if g["kind"] == "checkin"])
        + store.delete_review_grants([g["id"] for g in cands["grants"] if g["kind"] == "review"])
        + store.delete_family_grants([g["id"] for g in cands["grants"] if g["kind"] == "family"])
    )

    return {
        "applied_at": now.isoformat(),
        "policy": asdict(policy),
        "deleted": deleted,
        "kept": {
            "closed_visits": len(cands["closed_visits"]),
            "note": "Chain-linked records are never deleted in place; archive support is pending.",
        },
    }


def _candidates(store: Store, inbox: Any | None, media_root: Path, now: datetime, policy) -> dict:
    """Full candidate lists. seen_requests is capped at _CAP so apply() removes
    exactly the set the preview showed."""
    grants, used, expired = [], 0, 0
    for kind, grant in (
        [("checkin", g) for g in store.checkin_grants()]
        + [("review", g) for g in store.review_grants()]
        + [("family", g) for g in store.family_grants()]
    ):
        is_used = grant.used_at is not None
        is_expired = _aware(grant.expires_at) < now - timedelta(days=policy.grants_days)
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

    visit_cutoff = now - timedelta(days=policy.visits_days)
    closed = store.visits(states=_CLOSED, limit=100_000)
    old_visits = [
        {
            "id": v.id,
            "state": str(v.state),
            "site_id": v.site_id,
            "closed_at": (v.closed_at or v.last_activity_at).isoformat(),
        }
        for v in closed
        if _aware(v.closed_at or v.last_activity_at) < visit_cutoff
    ]

    media_cutoff = now - timedelta(days=policy.media_days)
    media_candidates = []
    for f in _media_files(media_root):
        visit_id = Path(f["path"]).parts[0] if Path(f["path"]).parts else ""
        visit = store.visit(visit_id)
        if visit is None:
            media_candidates.append({**f, "reason": "no matching visit record"})
        elif visit.state in _CLOSED and _aware(visit.closed_at or visit.last_activity_at) < media_cutoff:
            media_candidates.append({**f, "reason": "visit past media retention"})

    seen_total, seen_ids = store.stale_seen(now - timedelta(days=policy.seen_days), limit=_CAP)

    late = []
    for row in store.late_event_rows():
        at = _late_event_at(row["body"])
        # Unparseable timestamps keep the row — a malformed timestamp must not
        # turn a late-event record into a deletion candidate.
        if at is not None and at < now - timedelta(days=policy.late_events_days):
            late.append({"id": row["id"], "site_id": row["site_id"], "at": at.isoformat()})

    poll_cutoff = now - timedelta(days=policy.poll_observations_days)
    poll_obs = [
        {"id": o.id, "device_id": o.device_id, "polled_at": o.polled_at.isoformat()}
        for o in store.poll_observation_rows()
        if o.polled_at < poll_cutoff
    ]

    cov_cutoff = now - timedelta(days=policy.coverage_events_days)
    coverage = [
        {"id": e.id, "kind": e.kind.value, "at": e.at.isoformat()}
        for e in store.coverage_event_rows()
        if _aware(e.at) < cov_cutoff
    ]

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

    return {
        "closed_visits": old_visits,
        "media_files": media_candidates,
        "deliveries": deliveries,
        "grants": grants,
        "grant_stats": {"used": used, "expired": expired},
        "seen_requests": seen_ids,
        "seen_total": seen_total,
        "late_events": late,
        "poll_observations": poll_obs,
        "coverage_events": coverage,
    }


def _apply_token(cands: dict, policy: RetentionPolicy) -> str:
    """Fingerprint the deletable candidate set so apply() only runs on reviewed data."""
    canonical = {
        "policy": asdict(policy),
        "deliveries": sorted(d["id"] for d in cands["deliveries"]),
        "grants": sorted(g["id"] for g in cands["grants"]),
        "seen_requests": sorted(cands["seen_requests"]),
        "late_events": sorted(e["id"] for e in cands["late_events"]),
        "poll_observations": sorted(o["id"] for o in cands["poll_observations"]),
        "coverage_events": sorted(e["id"] for e in cands["coverage_events"]),
        "media_files": sorted(f["path"] for f in cands["media_files"]),
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()[:32]


def _bucket(items: list) -> dict:
    return {"total": len(items), "items": items[:_CAP]}


def _media_files(media_root: Path) -> list[dict]:
    root = Path(media_root)
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out.append({"path": str(p.relative_to(root)), "bytes": p.stat().st_size})
    return out


def _delete_media(media_root: Path, paths: list[str]) -> int:
    root = Path(media_root).resolve()
    removed = 0
    for rel in paths:
        p = (root / rel).resolve()
        if p.is_relative_to(root) and p.is_file():
            p.unlink()
            removed += 1
            try:
                p.parent.rmdir()  # drop the visit dir when it becomes empty
            except OSError:
                pass
    return removed


def _aware(dt: datetime) -> datetime:
    """Rows may carry naive timestamps (legacy data, manual edits) — compare
    them as UTC rather than crashing the report."""
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _late_event_at(body: dict) -> datetime | None:
    try:
        ms = body["data"]["attributes"]["timestamp"]
        return datetime.fromtimestamp(ms / 1000, tz=UTC)
    except (KeyError, TypeError, ValueError, OSError):
        return None
