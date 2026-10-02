"""Adversarial self-test: run real tamper attempts against the live store and
show the integrity machinery catching each one — then roll every attempt back.

Each attack runs inside a transaction that is never committed, so the store is
left exactly as it was. This is a demonstration harness, not a substitute for
offline verification of exported packs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .ledger import Signer, verify_chain
from .media import MediaStore
from .store import Store


class _Rollback(Exception):
    pass


def _attempt(store: Store, name: str, fn) -> dict:
    """Run one attack inside a transaction; fn returns (caught, detail) where
    caught is True/False, or None when the store has nothing to attack — a
    skipped attempt is not a missed defense."""
    try:
        with store.transaction():
            caught, detail = fn()
            raise _Rollback
    except _Rollback:
        pass
    return {"attack": name, "caught": caught, "detail": detail}


def run(store: Store, media_root: Path | None = None) -> dict:
    """Run the battery. Returns {"results": [...], "unchanged": bool}."""
    before = store.verify_journal()
    if before["entries"] == 0 and before["untracked_rows"]:
        stamped = store.journal_baseline()
        before = store.verify_journal()
        baseline_note = f"store predated journaling — stamped {stamped} rows as baseline"
    else:
        baseline_note = None

    results = []

    def forge_row() -> tuple[bool, str]:
        row = store._conn.execute("SELECT id, body FROM visits LIMIT 1").fetchone()
        if not row:
            return None, "no visits to forge"
        visit_id, body = row
        forged = json.loads(body)
        forged["state"] = "attended_verified"
        store._conn.execute("UPDATE visits SET body=? WHERE id=?", (json.dumps(forged), visit_id))
        report = store.verify_journal()
        hit = next((m for m in report["mismatches"] if "content changed" in m), None)
        return bool(hit), hit or "journal did not flag the edit"

    results.append(_attempt(store, "forge a visit row (state -> attended_verified)", forge_row))

    def delete_row() -> tuple[bool, str]:
        row = store._conn.execute("SELECT id FROM evidence ORDER BY at LIMIT 1").fetchone()
        if not row:
            return None, "no evidence rows to delete"
        store._conn.execute("DELETE FROM evidence WHERE id=?", (row[0],))
        report = store.verify_journal()
        hit = next((m for m in report["mismatches"] if "vanished" in m), None)
        return bool(hit), hit or "journal did not flag the deletion"

    results.append(_attempt(store, "delete an evidence row", delete_row))

    def truncate_interior() -> tuple[bool, str]:
        row = store._conn.execute("SELECT seq FROM journal ORDER BY seq LIMIT 1 OFFSET 2").fetchone()
        if not row:
            return None, "journal too short for an interior delete"
        store._conn.execute("DELETE FROM journal WHERE seq=?", (row[0],))
        report = store.verify_journal()
        hit = next((m for m in report["mismatches"] if "gap" in m or "link broken" in m), None)
        return bool(hit), hit or "journal did not flag the missing entry"

    results.append(_attempt(store, "erase a journal entry mid-chain (hide a past write)", truncate_interior))

    def truncate_tail() -> tuple[bool, str]:
        """Erase the log's end back through the newest signature anchor.
        Detectable only because receipts pin the head they were issued over —
        a pin that no longer resolves means history was cut after signing."""
        pins = store._pinned_journal_heads()
        if not pins:
            return None, "no receipt pins exist yet — tail deletion is not covered"
        seqs = [
            r[0]
            for p in pins
            if (
                r := store._conn.execute(
                    "SELECT seq FROM journal WHERE hash=? ORDER BY seq DESC LIMIT 1", (p,)
                ).fetchone()
            )
        ]
        if not seqs:
            return None, "no pin resolves in the current journal"
        store._conn.execute("DELETE FROM journal WHERE seq>=?", (max(seqs),))
        report = store.verify_journal()
        hit = next((m for m in report["mismatches"] if "pinned head" in m), None)
        return bool(hit), hit or "journal did not flag the truncation"

    results.append(_attempt(store, "truncate the journal tail (erase the log's end)", truncate_tail))

    def swap_key() -> tuple[bool, str]:
        row = store._conn.execute("SELECT id, body FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
        if not row:
            return None, "no receipts to re-sign"
        receipt_id, body = row
        forged = json.loads(body)
        attacker = Signer.ephemeral()
        forged["public_key"] = attacker.public_key_b64
        forged["signature"] = attacker.sign_hash(forged["payload_hash"])
        store._conn.execute("UPDATE receipts SET body=? WHERE id=?", (json.dumps(forged), receipt_id))
        journal = store.verify_journal()
        j_hit = any("content changed" in m for m in journal["mismatches"])
        from .models import Receipt

        chain_ok, chain_why = verify_chain(
            [Receipt.model_validate_json(r[0]) for r in store._conn.execute("SELECT body FROM receipts")]
        )
        caught = j_hit or not chain_ok
        return caught, (
            f"journal: {'flagged' if j_hit else 'missed'}; "
            f"chain verify: {chain_why if not chain_ok else 'missed'}"
        )

    results.append(_attempt(store, "re-sign a receipt with a different key (key swap)", swap_key))

    def replay_request() -> tuple[bool, str]:
        row = store._conn.execute("SELECT request_id FROM seen_requests LIMIT 1").fetchone()
        if not row:
            return None, "no webhook deliveries to replay"
        fresh = store.mark_seen(row[0], datetime.now(tz=UTC))
        return not fresh, f"replayed request_id {row[0][:20]}... accepted={fresh}"

    results.append(_attempt(store, "replay a delivered webhook request_id", replay_request))

    def out_of_band() -> tuple[bool, str]:
        store._conn.execute(
            "INSERT INTO visits (id, site_id, schedule_id, state, arrived_at, body) "
            "VALUES ('injected_row', 'x', 'x', 'attended_verified', '2026-01-01T00:00:00+00:00', '{}')"
        )
        report = store.verify_journal()
        return report["untracked_rows"] > before["untracked_rows"], (
            f"untracked rows: {before['untracked_rows']} -> {report['untracked_rows']}"
        )

    results.append(_attempt(store, "insert a row out-of-band (bypass the journal)", out_of_band))

    def retimestamp_coverage() -> tuple[bool, str]:
        """Slide a lifecycle event's denormalized `at` column — the signed body
        is untouched, but which coverage gaps look 'explained' changes."""
        row = store._conn.execute("SELECT id FROM coverage_events LIMIT 1").fetchone()
        if not row:
            return None, "no coverage events to retimestamp"
        store._conn.execute("UPDATE coverage_events SET at='1999-01-01T00:00:00+00:00' WHERE id=?", (row[0],))
        report = store.verify_journal()
        hit = next((m for m in report["mismatches"] if "index column" in m), None)
        return bool(hit), hit or "journal did not flag the column edit"

    results.append(
        _attempt(store, "retimestamp a lifecycle row's index column (re-explain a gap)", retimestamp_coverage)
    )

    def retimestamp_liveview() -> tuple[bool, str]:
        """Slide a live-view session's denormalized `opened_at` — the signed body
        is untouched, but 'when a human was watching' moves on the record."""
        row = store._conn.execute("SELECT id FROM liveview_sessions LIMIT 1").fetchone()
        if not row:
            return None, "no live-view sessions to retimestamp"
        store._conn.execute(
            "UPDATE liveview_sessions SET opened_at='1999-01-01T00:00:00+00:00' WHERE id=?",
            (row[0],),
        )
        report = store.verify_journal()
        hit = next((m for m in report["mismatches"] if "index column" in m), None)
        return bool(hit), hit or "journal did not flag the column edit"

    results.append(
        _attempt(store, "retimestamp a live-view session (move human attention)", retimestamp_liveview)
    )

    def forge_reason() -> tuple[bool, str]:
        """Rewrite a signed resolution's coded reason post-signature — the
        journal flags the row edit AND the chain signature fails, because the
        code rides inside the signed payload."""
        row = None
        for r in store._conn.execute(
            "SELECT id, visit_id, body FROM reviews ORDER BY revision DESC"
        ).fetchall():
            parsed = json.loads(r[2])
            rv = parsed.get("payload", {}).get("review")
            if isinstance(rv, dict) and rv.get("kind") == "resolution":
                row = (r[0], r[1], r[2])
                break
        if not row:
            return None, "no signed resolution to forge"
        review_id, visit_id, body = row
        forged = json.loads(body)
        rv = forged["payload"].get("review", {})
        rv["reason_code"] = "participant_refused" if rv.get("reason_code") != "participant_refused" else "other"
        store._conn.execute("UPDATE reviews SET body=? WHERE id=?", (json.dumps(forged), review_id))
        journal = store.verify_journal()
        j_hit = any("content changed" in m for m in journal["mismatches"])
        from .models import ReviewEntry
        from .reviews import ReviewBundle, verify_bundle

        original = store.receipt_for_visit(visit_id)
        entries = [
            ReviewEntry.model_validate_json(r[0])
            for r in store._conn.execute(
                "SELECT body FROM reviews WHERE visit_id=? ORDER BY revision", (visit_id,)
            )
        ]
        chain_ok, _ = verify_bundle(
            ReviewBundle(original=original, reviews=entries),
            public_key=original.public_key,
        )
        return (j_hit or not chain_ok), (
            f"journal: {'flagged' if j_hit else 'missed'}; "
            f"bundle verify: {'refused' if not chain_ok else 'MISSED the forged code'}"
        )

    results.append(_attempt(store, "forge a resolution's reason code post-signature", forge_reason))

    def swap_media() -> tuple[bool, str]:
        """Overwrite a media file's bytes post-signing — the digest check at
        serve time must refuse it. The file system isn't transactional, so the
        original bytes are restored by hand after the check runs."""
        if media_root is None:
            return None, "no media root configured"
        target = None
        for (body,) in store._conn.execute("SELECT body FROM evidence").fetchall():
            parsed = json.loads(body)
            if parsed.get("media_path") and parsed.get("media_sha256"):
                target = parsed
                break
        if target is None:
            return None, "no signed media to swap"
        media = MediaStore(media_root)
        original = media.read(target["media_path"])
        if original is None:
            return None, "media file already absent"
        path = Path(target["media_path"])
        if not path.is_absolute():
            path = media.root / path
        try:
            path.write_bytes(b"tampered-bytes")
            ok = media.verify(target["media_path"], target["media_sha256"])
            verdict = "refused the swapped bytes" if not ok else "MISSED the swap"
            return not ok, f"{path.name}: serve-time digest check {verdict}"
        finally:
            path.write_bytes(original)

    results.append(_attempt(store, "swap media bytes on disk after signing", swap_media))

    after = store.verify_journal()
    out = {
        "results": results,
        "unchanged": after["intact"] == before["intact"] and after["entries"] == before["entries"],
        "journal": after,
    }
    if baseline_note:
        out["baseline_note"] = baseline_note
    return out
