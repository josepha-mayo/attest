"""Adversarial self-test: run real tamper attempts against the live store and
show the integrity machinery catching each one — then roll every attempt back.

Each attack runs inside a transaction that is never committed, so the store is
left exactly as it was. This is a demonstration harness, not a substitute for
offline verification of exported packs.
"""

from __future__ import annotations

import io
import json
import tempfile
import warnings
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from .ledger import Signer, verify_chain
from .media import MediaStore
from .store import Store, StoreCorrupt


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


def run(store: Store, media_root: Path | None = None, inbox=None, engine=None) -> dict:
    """Run the battery. Returns {"results": [...], "unchanged": bool}.

    ``inbox`` is the optional WebhookInbox — the delivery-id conflict attack
    needs real deliveries to collide with; the refused enqueue writes nothing,
    so the separate inbox database needs no rollback of its own. ``engine`` is
    the optional VisitEngine — the forged-verifier attack needs it to mint a
    real signed pack to tamper with (its receipts roll back like everything
    else)."""
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

    def forge_rotation() -> tuple[bool, str]:
        """Self-endorsed pivot: write a key_rotation receipt claiming the
        deployment key retired to an attacker key — signed by the ATTACKER.
        A rotation only pivots when the retiring key signed it, so the hop
        must reject this and the chain must not accept post-pivot forgeries."""
        from .ledger import _rotation_hop
        from .models import Receipt

        row = store._conn.execute("SELECT body FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
        if not row:
            return None, "no receipts to pivot from"
        latest = Receipt.model_validate_json(row[0])
        attacker = Signer.ephemeral()
        forged = attacker.issue(
            visit_id=f"key:{latest.public_key[:12]}:{attacker.public_key_b64[:12]}",
            sequence=latest.sequence + 1,
            prev_hash=latest.payload_hash,
            facts={
                "record_type": "key_rotation",
                "previous_key": latest.public_key,  # claims the deployment endorsed it
                "new_key": attacker.public_key_b64,
            },
        )
        follow = attacker.issue(
            visit_id="vis_forged_after_pivot",
            sequence=forged.sequence + 1,
            prev_hash=forged.payload_hash,
            facts={"record_type": "visit_record", "forged": True},
        )
        pivot = _rotation_hop([forged], attacker.public_key_b64)
        chain_ok, chain_why = verify_chain(
            [Receipt.model_validate_json(r[0]) for r in store._conn.execute("SELECT body FROM receipts")]
            + [forged, follow]
        )
        caught = pivot is None and not chain_ok
        return caught, (
            f"pivot hop: {'rejected' if pivot is None else 'ACCEPTED'}; "
            f"chain verify: {chain_why if not chain_ok else 'missed'}"
        )

    results.append(_attempt(store, "forge a key_rotation pivot to an attacker key", forge_rotation))

    def forge_revocation() -> tuple[bool, str]:
        """Revocation downgrade: the tip issuer's whole history only becomes
        suspect when the TIP signs a key_revocation — an attacker (or any
        retired key) must not be able to mark the current key suspect."""
        from .ledger import revoked_issuer_keys
        from .models import Receipt

        rows = store._conn.execute("SELECT body FROM receipts ORDER BY sequence").fetchall()
        if not rows:
            return None, "no receipts"
        receipts = [Receipt.model_validate_json(r[0]) for r in rows]
        tip = receipts[-1].public_key
        attacker = Signer.ephemeral()
        forged = attacker.issue(
            visit_id=f"key:{attacker.public_key_b64[:12]}:revocation",
            sequence=receipts[-1].sequence + 1,
            prev_hash=receipts[-1].payload_hash,
            facts={
                "record_type": "key_revocation",
                "revoked_key": tip,
                "suspect_after": receipts[0].issued_at.isoformat(),  # would damn everything
                "reason": "attacker downgrade attempt",
            },
        )
        revoked = revoked_issuer_keys(receipts + [forged])
        caught = tip not in revoked
        return caught, "non-tip revocation ignored" if caught else "TIP MARKED SUSPECT by foreign key"

    results.append(_attempt(store, "forge a key_revocation against the live issuer", forge_revocation))

    def graft_revocation() -> tuple[bool, str]:
        """Pool-order graft: a self-signed revocation at sequence 0 sorts
        ahead of the honest chain in an attacker-assembled pool (pack
        key_rotations.json, an issuer document's key_receipts). Revocation
        authority anchors at the verified issuer's lineage root — pool
        position can never confer it."""
        from .ledger import revoked_issuer_keys
        from .models import Receipt

        rows = store._conn.execute("SELECT body FROM receipts ORDER BY sequence").fetchall()
        if not rows:
            return None, "no receipts"
        receipts = [Receipt.model_validate_json(r[0]) for r in rows]
        tip = receipts[-1].public_key
        forged = Signer.ephemeral().issue(
            visit_id="key:graft",
            sequence=0,  # sorts ahead of the honest chain
            prev_hash=None,
            facts={
                "record_type": "key_revocation",
                "revoked_key": tip,
                "suspect_after": receipts[0].issued_at.isoformat(),
                "reason": "grafted low-sequence smear attempt",
            },
        )
        revoked = revoked_issuer_keys(receipts + [forged], issuer_key=tip)
        caught = tip not in revoked
        return caught, (
            "grafted root ignored — authority stayed on the verified lineage"
            if caught
            else "POOL GRAFT WON: tip marked suspect"
        )

    results.append(_attempt(store, "graft a sequence-0 key_revocation ahead of the chain", graft_revocation))

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

    def corrupt_row_body() -> tuple[bool, str]:
        """Rewrite one row's body to bytes that no longer parse — reads must
        fail closed with StoreCorrupt (silently skipping would hide evidence)
        and the journal must still name the divergence."""
        row = store._conn.execute("SELECT id, body FROM visits LIMIT 1").fetchone()
        if not row:
            return None, "no visits to corrupt"
        visit_id, _ = row
        store._conn.execute("UPDATE visits SET body=? WHERE id=?", ('{"forged": ', visit_id))
        try:
            store.visit(visit_id)
        except StoreCorrupt:
            report = store.verify_journal()
            hit = any("content changed" in m for m in report["mismatches"])
            return True, f"read refused with StoreCorrupt; journal flagged={hit}"
        return False, "corrupt body read back without StoreCorrupt"

    results.append(_attempt(store, "corrupt a stored row's body (crash the read surfaces)", corrupt_row_body))

    def corrupt_settings() -> tuple[bool, str]:
        """A non-dict settings body is corruption, not a default — reads must
        fail closed instead of pretending the row never existed."""
        store._conn.execute("INSERT INTO settings (name, body) VALUES ('attack_demo', '42')")
        try:
            store.setting("attack_demo")
        except StoreCorrupt as exc:
            return True, f"settings read refused: {exc}"
        return False, "non-dict settings body read back without StoreCorrupt"

    results.append(_attempt(store, "corrupt a settings row (non-dict body)", corrupt_settings))

    def member_name_injection() -> tuple[bool, str]:
        """A hostile pack zip: duplicate names are ambiguous across extractors
        and ../absolute/drive segments dodge prefix whitelists. Both fail the
        pack at load — not just the member."""
        from .packdiff import check_member_names, load_artifact

        fd, tmp = tempfile.mkstemp(suffix=".zip", prefix="attest-attack-")
        buf = Path(tmp)
        with open(fd, "wb") as raw:
            with warnings.catch_warnings():
                # the duplicate member name is the attack — the stdlib
                # warning about it is expected noise, not a finding
                warnings.simplefilter("ignore")
                with zipfile.ZipFile(raw, "w") as z:
                    z.writestr("manifest.json", b'{"visits": []}')
                    z.writestr("manifest.json", b"{}")
                    z.writestr("media/../../escape.txt", b"x")
        try:
            named = check_member_names(["manifest.json", "manifest.json", "media/../../escape.txt"])
            try:
                load_artifact(buf)
            except ValueError as exc:
                return True, f"name check: {named}; loader: {exc}"
            return False, "pack loaded despite hostile member names"
        finally:
            buf.unlink(missing_ok=True)

    results.append(
        _attempt(
            store,
            "inject duplicate + traversal member names into a pack zip",
            member_name_injection,
        )
    )

    def forge_verifier_tool() -> tuple[bool, str]:
        """The strongest social-engineering play on offline review: hand the
        reviewer a genuine pack whose embedded verifier always prints VERIFIED.
        Member whitelists check names, never bytes — only the issuer-signed
        verifier_manifest.json pins each tool's sha256."""
        if engine is None:
            return None, "no signing engine — cannot mint a pinned pack to attack"
        sites = store.sites()
        if not sites:
            return None, "no site to export"
        site = sites[0]
        from .disputepack import build_case_pack, log_member
        from .models import ReviewBundle
        from .reviews import countersign_status

        entries = []
        for visit in store.visits(site_id=site.id, limit=10_000):
            receipt = store.receipt_for_visit(visit.id)
            if receipt is None:
                continue
            bundle = ReviewBundle(original=receipt, reviews=store.reviews_for(visit.id))
            entries.append((visit, bundle, countersign_status(bundle)))
        if not entries:
            return None, "no signed records to export"
        data = build_case_pack(
            store,
            media_root or Path("media"),
            site,
            entries,
            redact_media=True,
            manifest_signer=lambda m: engine.issue_export_manifest(site, m),
            issuer_key=engine.signer.public_key_b64,
            tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"site:{site.id}", t),
            log_fn=lambda rs: log_member(engine, rs),
        )
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            items = [(n, z.read(n)) for n in z.namelist()]
        forged = io.BytesIO()
        with zipfile.ZipFile(forged, "w") as z:
            for name, body in items:
                z.writestr(
                    name,
                    b"<html><body>VERIFIED - nothing checked</body></html>"
                    if name == "verify.html"
                    else body,
                )
        fd, tmp = tempfile.mkstemp(suffix=".zip", prefix="attest-attack-")
        try:
            with open(fd, "wb") as raw:
                raw.write(forged.getvalue())
            from .packdiff import load_artifact

            out = load_artifact(tmp)
            hits = [
                f for f in out["verify_failures"] if "pin" in f or "differ" in f or "verifier_manifest" in f
            ]
            return bool(hits), (
                hits[0] if hits else f"doctored verify.html accepted: {out['verify_failures']}"
            )
        finally:
            Path(tmp).unlink(missing_ok=True)

    results.append(
        _attempt(
            store,
            "ship a forged always-green verifier inside a genuine pack",
            forge_verifier_tool,
        )
    )

    def graft_unlogged_receipt() -> tuple[bool, str]:
        """The graft only the transparency log can catch: a receipt the
        deployment's own key really signed, minted off-chain and never
        committed to the receipts table — signature verifies, signer is
        trusted, and before Merkle proofs nothing could ask 'was it ever
        logged?'. key_rotations.json is unsigned pool content, so it is the
        one member an attacker can extend; the checkpoint's inclusion proofs
        must name every trusted-signed entry or the pack fails closed."""
        if engine is None:
            return None, "no signing engine — cannot mint a pack to attack"
        visit = next(iter(store.visits(limit=1)), None)
        if visit is None or store.receipt_for_visit(visit.id) is None:
            return None, "no signed records to export"
        from .disputepack import build_pack, log_member
        from .reviews import ReviewService

        service = ReviewService(store, engine.signer, engine.clock)
        bundle = service.bundle(visit.id)
        data = build_pack(
            store,
            media_root or Path("media"),
            bundle,
            tools_receipt_fn=lambda t: engine.issue_verifier_manifest(f"visit:{visit.id}", t),
            log_fn=lambda rs: log_member(engine, rs),
        )
        ghost = engine.signer.issue(
            visit_id="key:ghost-never-logged",
            sequence=0,
            prev_hash=None,
            facts={
                "record_type": "key_revocation",
                "revoked_key": "not-a-lineage-key",
                "suspect_after": "2000-01-01T00:00:00+00:00",
                "reason": "genuinely signed, never committed to the log",
            },
        )
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            items = [(n, z.read(n)) for n in z.namelist()]
        forged = io.BytesIO()
        have_kr = any(n == "key_rotations.json" for n, _ in items)
        with zipfile.ZipFile(forged, "w") as z:
            for name, body in items:
                if name == "key_rotations.json":
                    rj = json.loads(body)
                    rj["rotations"].append(ghost.model_dump(mode="json"))
                    body = json.dumps(rj).encode()
                z.writestr(name, body)
            if not have_kr:
                z.writestr(
                    "key_rotations.json",
                    json.dumps(
                        {
                            "schema": "attest.key-rotations/1",
                            "rotations": [ghost.model_dump(mode="json")],
                        }
                    ).encode(),
                )
        fd, tmp = tempfile.mkstemp(suffix=".zip", prefix="attest-attack-")
        try:
            with open(fd, "wb") as raw:
                raw.write(forged.getvalue())
            from .packdiff import load_artifact

            out = load_artifact(tmp)
            hits = [f for f in out["verify_failures"] if "inclusion proof" in f]
            return bool(hits), (
                hits[0] if hits else f"unlogged-but-signed graft accepted: {out['verify_failures']}"
            )
        finally:
            Path(tmp).unlink(missing_ok=True)

    results.append(
        _attempt(
            store,
            "graft a genuinely-signed receipt the deployment never logged",
            graft_unlogged_receipt,
        )
    )

    def inbox_id_conflict() -> tuple[bool, str]:
        """Reusing a delivery id with different bytes — legit retries repeat
        the SAME signature under the same id; a different body or signature
        is a replay probe and must refuse, writing nothing."""
        if inbox is None:
            return None, "no webhook inbox configured"
        rows = inbox.entries(limit=1)
        if not rows:
            return None, "no deliveries to collide with"
        try:
            inbox.enqueue(rows[0]["id"], b'{"forged": true}', "forged-signature")
        except ValueError as exc:
            return True, f"refused: {exc}"
        return False, "conflicting request id enqueued a second body"

    results.append(
        _attempt(
            store,
            "re-send a delivered request_id with different bytes",
            inbox_id_conflict,
        )
    )

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
        rv["reason_code"] = (
            "participant_refused" if rv.get("reason_code") != "participant_refused" else "other"
        )
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

    def graft_predecessor() -> tuple[bool, str]:
        """Claim the issuer descends from an attacker key: sign a key_rotation
        under the ATTACKER's key naming the deployment issuer as its
        successor. Endorsement is self-serve — any key can retire "into" a
        victim key — so trust must only extend when the successor also signs
        a key_adoption naming the rotation. No consent, no ancestor."""
        from .ledger import trusted_issuer_keys

        row = store._conn.execute("SELECT body FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
        if not row:
            return None, "no receipts to anchor an issuer against"
        issuer = json.loads(row[0])["public_key"]
        attacker = Signer.ephemeral()
        graft = attacker.issue(
            visit_id=f"key:{attacker.public_key_b64[:12]}:{issuer[:12]}",
            sequence=1,
            prev_hash=None,
            facts={
                "record_type": "key_rotation",
                "previous_key": attacker.public_key_b64,
                "new_key": issuer,
            },
        )
        trusted = trusted_issuer_keys(issuer, [graft])
        caught = attacker.public_key_b64 not in trusted
        return caught, (
            "graft refused — successor never countersigned"
            if caught
            else "attacker key entered the trusted issuer set"
        )

    results.append(_attempt(store, "graft a forged predecessor key onto the issuer", graft_predecessor))

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
