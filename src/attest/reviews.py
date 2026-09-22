from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from .clock import ExecutionClock
from .ledger import Signer, verify_receipt
from .models import (
    HouseholdStatementInput,
    ResolutionInput,
    ReviewBundle,
    ReviewEntry,
    ReviewGrant,
    ReviewInput,
    utcnow,
)
from .store import Store, atomic


def verify_bundle(bundle: ReviewBundle, *, public_key: str) -> tuple[bool, str]:
    original = bundle.original
    ok, reason = verify_receipt(original, public_key=public_key)
    if not ok:
        return False, f"original: {reason}"
    previous = original.payload_hash
    for revision, entry in enumerate(bundle.reviews, 1):
        receipt = entry.receipt
        ok, reason = verify_receipt(receipt, public_key=public_key)
        if not ok:
            return False, f"review {revision}: {reason}"
        if (
            entry.id != receipt.id
            or entry.visit_id != original.visit_id
            or receipt.visit_id != original.visit_id
        ):
            return False, "review identity does not match original"
        if entry.revision != revision or receipt.sequence != revision or receipt.prev_hash != previous:
            return False, "review sequence or previous hash mismatch"
        payload = receipt.payload
        if payload.get("record_type") != "review" or payload.get("original_receipt") != {
            "id": original.id,
            "hash": original.payload_hash,
        }:
            return False, "review is not anchored to this original"
        previous = receipt.payload_hash
    return True, f"original and {len(bundle.reviews)} append-only reviews verified (integrity only)"


_WORKER_STANCE = {
    "confirm": ("acknowledged", "Worker states the record matches their account"),
    "dispute": ("contested", "Worker disputes this record"),
    "correction": ("corrected", "Worker submitted a correction"),
    "inconclusive": ("inconclusive", "Worker could not confirm or dispute"),
}

_RESOLUTION_LABEL = {
    "record_upheld": "coordinator upheld the record",
    "account_accepted": "coordinator accepted the worker's account",
    "inconclusive": "coordinator closed the record as inconclusive",
}


def countersign_status(bundle: ReviewBundle) -> dict:
    """Derived bilateral state from the signed review chain. Not itself signed — it is
    a computed view over the chain, and any exported bundle recomputes identically.

    A worker ``confirm`` is an acknowledgment of the *record as issued* — bound to
    the original receipt hash — not a certification of attendance or identity.

    A coordinator *resolution* is the terminal signed conclusion: it never edits
    the worker's stance — it layers after it. The derived state is ``resolved``
    only while the latest resolution post-dates the latest worker statement, so a
    new worker statement naturally re-opens the record."""
    worker_reviews = [r for r in bundle.reviews if r.receipt.payload.get("actor", {}).get("role") == "worker"]
    resolutions = [
        r for r in bundle.reviews if r.receipt.payload.get("review", {}).get("kind") == "resolution"
    ]
    resolution = None
    if resolutions:
        latest_r = resolutions[-1]
        worker_rev = worker_reviews[-1].revision if worker_reviews else 0
        if latest_r.revision > worker_rev:
            p = latest_r.receipt.payload
            resolution = {
                "outcome": p["review"]["outcome"],
                "detail": _RESOLUTION_LABEL.get(p["review"]["outcome"], "coordinator concluded"),
                "statement": p["review"].get("statement"),
                "at": p.get("statement_received_at"),
                "revision": latest_r.revision,
            }
    if worker_reviews:
        latest = worker_reviews[-1].receipt.payload
        decision = latest["review"]["decision"]
        state, detail = _WORKER_STANCE.get(decision, ("reviewed", "Worker left a statement"))
        status = {
            "state": state,
            "detail": detail,
            "worker": latest["actor"].get("name"),
            "decision": decision,
            "at": latest.get("statement_received_at"),
            "revision": worker_reviews[-1].revision,
        }
        if resolution is not None:
            status["state"] = "resolved"
            status["detail"] = f"{detail} — {resolution['detail']}"
            status["resolution"] = resolution
        return status
    if resolution is not None:
        return {
            "state": "resolved",
            "detail": f"No worker statement — {resolution['detail']}",
            "resolution": resolution,
        }
    return {"state": "no_statement", "detail": "No worker statement on this record"}


class ReviewService:
    def __init__(self, store: Store, signer: Signer, clock: ExecutionClock):
        self.store, self.signer, self.clock = store, signer, clock

    def bundle(self, visit_id: str) -> ReviewBundle:
        original = self.store.receipt_for_visit(visit_id)
        if original is None:
            raise ValueError("close the observation record before reviewing it")
        return ReviewBundle(original=original, reviews=self.store.reviews_for(visit_id))

    def countersign(self, visit_id: str) -> dict:
        """Derived bilateral record state, including whether a worker link is outstanding."""
        status = countersign_status(self.bundle(visit_id))
        if status["state"] != "no_statement":
            return status
        grants = [g for g in self.store.review_grants() if g.id == visit_id]
        live = [g for g in grants if not g.used_at and g.expires_at > utcnow()]
        if live:
            expiry = min(g.expires_at for g in live)
            status.update(
                state="awaiting",
                detail=f"Worker statement requested — link expires {expiry:%Y-%m-%d %H:%M} UTC",
            )
        elif grants:
            status.update(state="unacknowledged", detail="Review link expired unused")
        else:
            status.update(state="unrequested", detail="No worker statement requested")
        return status

    def _checked_bundle(self, visit_id: str) -> ReviewBundle:
        bundle = self.bundle(visit_id)
        ok, reason = verify_bundle(bundle, public_key=self.signer.public_key_b64)
        if not ok:
            raise ValueError(reason)
        if len(bundle.reviews) >= 500:
            raise ValueError("review limit reached")
        return bundle

    def _append(self, visit_id: str, data: ReviewInput, actor: dict) -> ReviewEntry:
        bundle = self._checked_bundle(visit_id)
        previous = bundle.reviews[-1].receipt.payload_hash if bundle.reviews else bundle.original.payload_hash
        signed = self.signer.issue(
            visit_id=visit_id,
            sequence=len(bundle.reviews) + 1,
            prev_hash=previous,
            facts={
                "record_type": "review",
                "original_receipt": {"id": bundle.original.id, "hash": bundle.original.payload_hash},
                "actor": actor,
                "review": data.model_dump(mode="json"),
                "statement_received_at": utcnow().isoformat(),
                "effective_at": self.clock.now().isoformat(),
                "clock": self.clock.snapshot(),
                "original_assessment_unchanged": True,
                "independently_verified_attendance": False,
                "journal_head": self.store.journal_head(),
            },
        )
        entry = ReviewEntry(id=signed.id, visit_id=visit_id, revision=signed.sequence, receipt=signed)
        self.store.put_review(entry)
        return entry

    @atomic
    def coordinator_review(self, visit_id: str, data: ReviewInput) -> ReviewEntry:
        return self._append(
            visit_id,
            data,
            {
                "role": "coordinator",
                "authentication": "workspace_admin",
                "name": "Workspace coordinator",
            },
        )

    @atomic
    def resolve(self, visit_id: str, data: ResolutionInput) -> ReviewEntry:
        """Append the coordinator's terminal conclusion. Signed and append-only:
        the worker's stance stays in the chain; ``countersign_status`` derives
        ``resolved`` while this post-dates the latest worker statement."""
        bundle = self._checked_bundle(visit_id)
        # Idempotent re-submit: if the chain tip is already this exact
        # resolution (double-click, retry, refreshed form), return it rather
        # than chaining a byte-identical duplicate. A *different* outcome or
        # statement appends normally — a changed mind is legitimate history.
        if bundle.reviews:
            tip = bundle.reviews[-1].receipt.payload
            review = tip.get("review", {})
            if (
                tip.get("record_type") == "review"
                and review.get("kind") == "resolution"
                and tip.get("actor", {}).get("role") == "coordinator"
                and review.get("outcome") == data.outcome
                and review.get("statement") == data.statement
            ):
                return bundle.reviews[-1]
        previous = bundle.reviews[-1].receipt.payload_hash if bundle.reviews else bundle.original.payload_hash
        signed = self.signer.issue(
            visit_id=visit_id,
            sequence=len(bundle.reviews) + 1,
            prev_hash=previous,
            facts={
                "record_type": "review",
                "original_receipt": {"id": bundle.original.id, "hash": bundle.original.payload_hash},
                "actor": {
                    "role": "coordinator",
                    "authentication": "workspace_admin",
                    "name": "Workspace coordinator",
                },
                "review": {
                    "kind": "resolution",
                    "outcome": data.outcome,
                    "statement": data.statement,
                },
                "statement_received_at": utcnow().isoformat(),
                "effective_at": self.clock.now().isoformat(),
                "clock": self.clock.snapshot(),
                "original_assessment_unchanged": True,
                "independently_verified_attendance": False,
                "journal_head": self.store.journal_head(),
            },
        )
        entry = ReviewEntry(id=signed.id, visit_id=visit_id, revision=signed.sequence, receipt=signed)
        self.store.put_review(entry)
        return entry

    @atomic
    def issue_worker_link(self, visit_id: str) -> str:
        bundle = self._checked_bundle(visit_id)
        worker = bundle.original.payload.get("scheduled_worker")
        if not worker or not worker.get("id"):
            raise ValueError("original record has no signed scheduled-worker binding")
        token = secrets.token_urlsafe(32)
        self.store.put_review_grant(
            ReviewGrant(
                id=visit_id,
                worker_id=worker["id"],
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=utcnow() + timedelta(hours=24),
                original_hash=bundle.original.payload_hash,
            )
        )
        return token

    def worker_target(self, token: str):
        grant = self.store.review_grant(hashlib.sha256(token.encode()).hexdigest())
        if grant is None or grant.used_at or grant.expires_at <= utcnow():
            return None
        bundle = self._checked_bundle(grant.id)
        worker = bundle.original.payload.get("scheduled_worker") or {}
        if bundle.original.payload_hash != grant.original_hash or worker.get("id") != grant.worker_id:
            return None
        return grant, bundle

    @atomic
    def worker_review(self, token: str, data: ReviewInput) -> ReviewEntry:
        target = self.worker_target(token)
        if target is None:
            raise ValueError("invalid, expired, or used review link")
        grant, bundle = target
        worker = bundle.original.payload["scheduled_worker"]
        entry = self._append(
            grant.id,
            data,
            {
                "role": "worker",
                "authentication": "visit_review_link",
                "worker_id": grant.worker_id,
                "name": worker["name"],
                "identity_verified": False,
            },
        )
        grant.used_at = utcnow()
        self.store.put_review_grant(grant)
        return entry

    @atomic
    def household_statement(self, token: str, data: HouseholdStatementInput) -> ReviewEntry:
        """Append the household's own account via the scoped family link. The
        multi-use grant is not consumed — the link stays view+append until
        expiry. A household statement is self-reported like the worker's
        check-in: it joins the chain verbatim, never verifies presence, and
        never changes the derived worker/coordinator stance."""
        grant = self.store.family_grant(hashlib.sha256(token.encode()).hexdigest())
        if grant is None or grant.expires_at <= utcnow():
            raise ValueError("invalid or expired family link")
        return self._append(
            grant.id,
            data,
            {
                "role": "household",
                "authentication": "family_link",
                "name": "Household member",
                "identity_verified": False,
            },
        )
