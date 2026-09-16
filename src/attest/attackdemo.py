"""Adversarial self-test: run real tamper attempts against the live store and
show the integrity machinery catching each one — then roll every attempt back.

Each attack runs inside a transaction that is never committed, so the store is
left exactly as it was. This is a demonstration harness, not a substitute for
offline verification of exported packs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from .ledger import Signer, verify_chain
from .store import Store


class _Rollback(Exception):
    pass


def _attempt(store: Store, name: str, fn) -> dict:
    """Run one attack inside a transaction; fn returns (caught, detail)."""
    try:
        with store.transaction():
            caught, detail = fn()
            raise _Rollback
    except _Rollback:
        pass
    return {"attack": name, "caught": caught, "detail": detail}


def run(store: Store) -> dict:
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
            return False, "no visits to forge"
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
            return False, "no evidence rows to delete"
        store._conn.execute("DELETE FROM evidence WHERE id=?", (row[0],))
        report = store.verify_journal()
        hit = next((m for m in report["mismatches"] if "vanished" in m), None)
        return bool(hit), hit or "journal did not flag the deletion"

    results.append(_attempt(store, "delete an evidence row", delete_row))

    def truncate_interior() -> tuple[bool, str]:
        row = store._conn.execute("SELECT seq FROM journal ORDER BY seq LIMIT 1 OFFSET 2").fetchone()
        if not row:
            return False, "journal too short for an interior delete"
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
            return False, "no receipt pins exist yet — tail deletion is not covered"
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
            return False, "no pin resolves in the current journal"
        store._conn.execute("DELETE FROM journal WHERE seq>=?", (max(seqs),))
        report = store.verify_journal()
        hit = next((m for m in report["mismatches"] if "pinned head" in m), None)
        return bool(hit), hit or "journal did not flag the truncation"

    results.append(_attempt(store, "truncate the journal tail (erase the log's end)", truncate_tail))

    def swap_key() -> tuple[bool, str]:
        row = store._conn.execute("SELECT id, body FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
        if not row:
            return False, "no receipts to re-sign"
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
            return False, "no webhook deliveries to replay"
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

    after = store.verify_journal()
    out = {
        "results": results,
        "unchanged": after["intact"] == before["intact"] and after["entries"] == before["entries"],
        "journal": after,
    }
    if baseline_note:
        out["baseline_note"] = baseline_note
    return out
