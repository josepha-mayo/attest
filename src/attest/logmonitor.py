"""Transparency-log monitor — the auditor half of the RFC 6962 story.

A signed tree head only constrains a deployment if someone *watches* it:
the deployment could sign a new head every hour and quietly fork the log
between them. This module is the third-party check — pin a signed
checkpoint, then demand that every later checkpoint extends it via a
consistency proof. A rewritten, truncated, or forked log cannot produce
the bridging nodes; the monitor says so instead of trusting the new head.

Everything fetched is verification material (issuer doc, tree head,
checkpoint receipt, proof nodes) — the signatures do the authenticating,
so plain-HTTP loopback is fine and a hostile network can only deny
service, never forge a consistent log.
"""

from __future__ import annotations

import json
from typing import Any

STATE_SCHEMA = "attest.log-monitor/1"


def _doc_checkpoint(head: dict) -> dict | None:
    cp = head.get("checkpoint")
    return cp if isinstance(cp, dict) else None


def _trusted_set(doc: dict) -> set:
    """Issuer lineage the issuer document certifies — ancestors through
    consented pivots plus descendants, so a deployment mid-rotation still
    verifies. Mirrors what pack verification does with the same doc."""
    from .ledger import descendant_issuer_keys, trusted_issuer_keys
    from .models import Receipt

    receipts = []
    for r in doc.get("key_receipts") or []:
        try:
            receipts.append(Receipt.model_validate(r))
        except Exception:  # noqa: BLE001 — malformed entries just can't bridge
            continue
    issuer = doc["issuer_key"]
    return trusted_issuer_keys(issuer, receipts) | descendant_issuer_keys(issuer, receipts)


def _check_sth(cp_raw: dict, trusted: set) -> tuple[dict | None, str | None]:
    """Validate the signed tree head inside a head response. Returns the
    payload or a failure string."""
    from .ledger import verify_receipt
    from .models import Receipt

    try:
        cp = Receipt.model_validate(cp_raw)
    except Exception as exc:  # noqa: BLE001
        return None, f"checkpoint is not a receipt ({exc})"
    payload = cp.payload
    if payload.get("record_type") != "log_checkpoint":
        return None, "head's checkpoint is not a log_checkpoint receipt"
    if cp.public_key not in trusted:
        return None, "checkpoint signed outside the issuer's certified lineage"
    ok, why = verify_receipt(cp, public_key=cp.public_key)
    if not ok:
        return None, f"checkpoint signature invalid: {why}"
    size, root_hex = payload.get("tree_size"), payload.get("root_sha256")
    if not isinstance(size, int) or size < 1 or not isinstance(root_hex, str):
        return None, "checkpoint carries a malformed tree head"
    try:
        bytes.fromhex(root_hex)
    except ValueError:
        return None, "checkpoint carries a malformed tree head"
    return payload, None


def check(
    state: dict | None,
    issuer_doc: dict,
    head: dict,
    fetch_consistency,
    checked_at: str,
) -> tuple[dict | None, bool, list[str]]:
    """One monitor cycle, transport-free.

    ``state`` is the persisted last-seen head (or None on first run);
    ``issuer_doc`` is the fetched attest.issuer/1 document; ``head`` is the
    fetched /api/log/head body; ``fetch_consistency(first, size) -> dict | None``
    pulls the consistency endpoint lazily — only called when the head
    moved. ``size`` bounds the proof to the checkpoint's tree: the live
    tip usually runs ahead of the newest signed head, so a proof to the
    tip can never bridge to the checkpoint the pin tracks. Returns
    (new_state, ok, human lines).
    """
    lines: list[str] = []
    if state is not None and state.get("schema") != STATE_SCHEMA:
        return None, False, [f"monitor state {state.get('schema')!r} is not {STATE_SCHEMA}"]
    live_size = head.get("tree_size")
    if not isinstance(live_size, int) or live_size < 0:
        return None, False, ["log head did not report a usable tree_size"]
    trusted = _trusted_set(issuer_doc)
    cp_raw = _doc_checkpoint(head)
    if cp_raw is None:
        if live_size == 0:
            return None, True, ["log is empty and unsigned — nothing to pin yet"]
        if state is not None:
            return (
                None,
                False,
                [
                    f"ALERT: head at tree size {live_size} serves no signed checkpoint — "
                    "the pinned head cannot be re-confirmed; the log may have been replaced"
                ],
            )
        return (
            None,
            False,
            [
                f"log holds {live_size} leaves but serves no signed checkpoint — "
                "nothing to pin; run attest checkpoint on the deployment first"
            ],
        )
    payload, err = _check_sth(cp_raw, trusted)
    if err:
        return None, False, [f"ALERT: {err}"]
    size, root_hex = int(payload["tree_size"]), payload["root_sha256"]
    if size > live_size:
        return (
            None,
            False,
            [
                f"ALERT: signed checkpoint at size {size} exceeds the live tree "
                f"({live_size}) — the head the deployment serves is smaller "
                "than one it signed"
            ],
        )
    new_state = {
        "schema": STATE_SCHEMA,
        "issuer_key": issuer_doc["issuer_key"],
        "tree_size": size,
        "root_sha256": root_hex,
        "checkpoint_id": cp_raw.get("id"),
        "checked_at": checked_at,
    }
    if state is None:
        lines.append(
            f"pinned checkpoint {str(cp_raw.get('id'))[:24]}… — tree size {size}, "
            f"root {root_hex[:24]}… ({len(trusted)} issuer key(s) trusted)"
        )
        lines.append(
            "every later checkpoint must extend this head — a rewritten log "
            "cannot produce the consistency proof"
        )
        return new_state, True, lines
    old_size, old_root = int(state["tree_size"]), state["root_sha256"]
    if size == old_size and root_hex == old_root:
        lines.append(f"head unchanged — checkpoint still commits to {size} leaves")
        return new_state, True, lines
    if size < old_size:
        return (
            None,
            False,
            [
                f"ALERT: signed head regressed — was {old_size} leaves, now {size}. "
                "A log cannot shrink honestly; the deployment is serving a "
                "different history than the one pinned"
            ],
        )
    # Extension claim: the new STH must bridge from the pinned one. The
    # proof is bounded at the CHECKPOINT's size — not the live tip, which
    # is almost always ahead of the newest signed head on an active log.
    proof = fetch_consistency(old_size, size)
    if proof is None or not isinstance(proof.get("proof"), list):
        return (
            None,
            False,
            [
                f"ALERT: no consistency proof from size {old_size} — the "
                "deployment cannot show the pinned head inside its current tree"
            ],
        )
    if int(proof.get("first") or -1) != old_size or int(proof.get("tree_size") or -1) != size:
        return (
            None,
            False,
            ["ALERT: consistency proof is for different tree sizes than the head claims"],
        )
    from .transparency import verify_consistency

    try:
        nodes = [bytes.fromhex(h) for h in proof["proof"]]
        bridges = verify_consistency(bytes.fromhex(old_root), old_size, bytes.fromhex(root_hex), size, nodes)
    except (TypeError, ValueError):
        return None, False, ["ALERT: consistency proof carries malformed nodes"]
    if not bridges:
        return (
            None,
            False,
            [
                f"ALERT: log does not extend the pinned head — checkpoint at "
                f"size {size} cannot be reached from the pinned size {old_size} "
                "root. The deployment rewrote or forked its receipt log"
            ],
        )
    lines.append(
        f"log extended {old_size} → {size} — consistency proof verifies "
        f"({len(nodes)} node(s)); nothing pinned was rewritten"
    )
    return new_state, True, lines


def state_load(path) -> dict | None:
    """Read a monitor state file; absent → None, malformed → a dict whose
    schema check fails the cycle loudly rather than silently repinning."""
    from pathlib import Path

    p = Path(path)
    if not p.is_file():
        return None
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"schema": f"unreadable state: {exc}"}
    return doc if isinstance(doc, dict) else {"schema": "state is not an object"}


def state_save(path, state: dict) -> None:
    """Persist the pinned head atomically — a crash must not leave a
    half-written state that a later run would misread as a trusted pin."""
    import os
    import tempfile
    from pathlib import Path

    p = Path(path)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=p.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(state, indent=2, ensure_ascii=False) + "\n")
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def fetch_json(url: str, client=None, *, bound: int = 4 * 1024 * 1024) -> Any:
    """GET a JSON verification endpoint under the issuer-doc transport
    policy — streamed, byte-capped, wall-clock bounded, fail-closed."""
    import time

    import httpx

    stream_ctx = client.stream if client is not None else httpx.stream
    deadline = time.monotonic() + 30
    try:
        with stream_ctx("GET", url, timeout=15) as r:
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code} from {url}")
            raw = bytearray()
            for chunk in r.iter_bytes(1 << 16):
                raw.extend(chunk)
                if len(raw) > bound:
                    raise ValueError(f"{url} exceeds the 4 MB bound")
                if time.monotonic() > deadline:
                    raise ValueError(f"{url} timed out")
    except httpx.HTTPError as exc:
        raise ValueError(f"{url} unreachable: {exc}") from exc
    except httpx.InvalidURL as exc:
        raise ValueError(f"{url} malformed: {exc}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{url} did not serve JSON: {exc}") from exc
