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
    moved AND the new checkpoint carries no usable embedded `extends`
    bridge (a chained checkpoint self-proves continuity, no fetch needed).
    ``size`` bounds the proof to the checkpoint's tree: the live
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
    # Extension claim: the new STH must bridge from the pinned one. Prefer
    # the checkpoint's OWN embedded `extends` bridge — the issuer signed
    # the bridging nodes at issuance, so they can't be tailored per
    # request, and they work even when the deployment exposes no
    # consistency endpoint. When it doesn't apply (legacy checkpoint, or
    # a bridge from a different ancestor than our pin), fall back to a
    # served proof bounded at the CHECKPOINT's size — not the live tip,
    # which is almost always ahead of the newest signed head.
    from .transparency import verify_consistency, verify_extends

    embedded = verify_extends(payload, first=old_size, first_root=bytes.fromhex(old_root))
    if embedded is True:
        lines.append(
            f"log extended {old_size} → {size} — the checkpoint's own signed "
            "bridge verifies (embedded extends); nothing pinned was rewritten"
        )
        return new_state, True, lines
    if embedded is False:
        return (
            None,
            False,
            [
                f"ALERT: checkpoint at size {size} signs an `extends` bridge that "
                f"cannot reach the pinned head at {old_size} — the deployment's "
                "own signed material contradicts the pinned history"
            ],
        )
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


def live_check(
    pack_cp_raw: dict,
    head: dict,
    fetch_consistency,
    trusted: set,
) -> tuple[bool | None, str]:
    """Cross-check a pack's signed tree head against the deployment's LIVE
    head — 'the log this pack proves membership in is a proven prefix of
    the log the deployment still serves'.

    The attack this closes: a hostile deployment can mint internally-
    consistent logs per victim — the pack's checkpoint verifies, every
    inclusion proof closes, and the auditor still holds a log nobody else
    was shown. Against a live endpoint the fork collapses: the deployment
    must produce a consistency bridge from the pack's head to the head it
    serves everyone else, and a forked history cannot produce it.

    ``fetch_consistency`` is reached only when the live checkpoint's own
    signed `extends` bridge does not already name the pack's head — a
    chained checkpoint self-proves the bridge, so the common case costs
    no extra request. Returns (verdict, line): True = provably the same
    log (identical head or a verified extension), False = a provable
    contradiction, None = undecidable (deployment serves no checkpoint,
    or the pack postdates the live head — say so rather than guess)."""
    payload, err = _check_sth(pack_cp_raw, trusted)
    if err:
        return False, f"pack checkpoint: {err}"
    pack_size, pack_root = int(payload["tree_size"]), payload["root_sha256"]
    live_cp = _doc_checkpoint(head)
    if live_cp is None:
        return None, "deployment serves no signed head — cannot cross-check"
    live_payload, err = _check_sth(live_cp, trusted)
    if err:
        return None, f"live checkpoint does not validate ({err}) — cannot cross-check"
    live_size, live_root = int(live_payload["tree_size"]), live_payload["root_sha256"]
    if pack_size == live_size:
        if pack_root == live_root:
            return True, f"pack's signed head is the live head — tree size {pack_size}"
        return False, (
            f"FORK: pack and live heads both sign tree size {pack_size} with "
            "different roots — the deployment served this auditor a different log"
        )
    if pack_size < live_size:
        # Fast path: when the live checkpoint's own signed bridge names the
        # pack's head as its ancestor, no separate proof fetch is needed —
        # and a bridge that claims our size but can't reach our root is a
        # signed self-contradiction, a hard fork rather than a soft one.
        from .transparency import verify_extends

        embedded = verify_extends(live_payload, first=pack_size, first_root=bytes.fromhex(pack_root))
        if embedded is True:
            return True, (
                f"live checkpoint's own signed bridge extends the pack's head "
                f"({pack_size} → {live_size} leaves) — the pack's log is the one still served"
            )
        if embedded is False:
            return False, (
                "FORK: the live checkpoint signs a bridge claiming the pack's "
                "tree size but starting from a different root — split-view log"
            )
        proof = fetch_consistency(pack_size, live_size)
        if not isinstance(proof, dict) or not isinstance(proof.get("proof"), list):
            return False, (
                "live head cannot bridge from the pack's head — the deployment "
                "cannot show the pack's log inside the one it serves now"
            )
        try:
            nodes = [bytes.fromhex(h) for h in proof["proof"]]
        except (TypeError, ValueError):
            return False, "live consistency proof carries malformed nodes"
        from .transparency import verify_consistency

        if verify_consistency(
            bytes.fromhex(pack_root), pack_size, bytes.fromhex(live_root), live_size, nodes
        ):
            return True, (
                f"live log provably extends the pack's head ({pack_size} → "
                f"{live_size} leaves) — the pack's log is the one still served"
            )
        return False, (
            "FORK: the deployment's live log does not extend the head this "
            "pack signed — the bridging consistency proof cannot be produced"
        )
    return None, (
        f"pack's signed head (size {pack_size}) postdates the live head "
        f"({live_size}) — the pack may come from a newer or different log instance"
    )


WITNESS_SCHEMA = "attest.witness/1"


def witness_cosign(store, signer, body: dict) -> tuple[int, dict]:
    """The witness's decision, transport-free: (status_code, response).

    A sigsum-style cosigning witness for the transparency log: this
    deployment countersigns ANOTHER issuer's signed tree head — but only
    after proving it extends the head this witness last pinned for that
    issuer. A forked or regressed head can still be self-consistently
    signed; it cannot collect the counter-signature that makes 'public
    log' mean something, because the witness refuses to attest it.

    The requester supplies its issuer document and the checkpoint
    receipt; continuity is proven by the checkpoint's own embedded
    `extends` bridge when it names the pinned head, else by a
    `consistency` proof document in the request. A 409 response carries
    the pinned head — the requester's retry is exactly the bridge the
    fork cannot produce.
    """
    from .models import Receipt
    from .transparency import verify_consistency, verify_extends

    issuer_doc = body.get("issuer_doc")
    if not isinstance(issuer_doc, dict) or not isinstance(issuer_doc.get("issuer_key"), str):
        return 422, {"error": "issuer_doc missing or malformed"}
    cp_raw = body.get("checkpoint")
    if not isinstance(cp_raw, dict):
        return 422, {"error": "checkpoint receipt missing"}
    try:
        trusted = _trusted_set(issuer_doc)
        payload, err = _check_sth(cp_raw, trusted)
    except Exception as exc:  # noqa: BLE001 — malformed doc is a client error
        return 422, {"error": f"issuer document rejected: {exc}"}
    if err:
        return 422, {"error": f"checkpoint rejected: {err}"}
    issuer_key = issuer_doc["issuer_key"]
    cp = Receipt.model_validate(cp_raw)
    size, root_hex = int(payload["tree_size"]), payload["root_sha256"]

    state = store.setting(f"witness:{issuer_key}") or {}
    if state and state.get("schema") != WITNESS_SCHEMA:
        return 500, {"error": "witness pin state is corrupt — refusing to repin"}
    old_size = state.get("tree_size")
    old_root = state.get("root_sha256")
    if old_size is not None:
        if size < int(old_size) or (size == int(old_size) and root_hex != old_root):
            return 409, {
                "error": "offered head forks or regresses the pinned head",
                "pinned": {
                    "tree_size": old_size,
                    "root_sha256": old_root,
                    "checkpoint_id": state.get("checkpoint_id"),
                },
            }
        if size != int(old_size):
            bridge = verify_extends(
                payload, first=int(old_size), first_root=bytes.fromhex(old_root)
            )
            if bridge is None:
                cons = body.get("consistency")
                try:
                    bridge = (
                        isinstance(cons, dict)
                        and int(cons.get("first") or -1) == int(old_size)
                        and int(cons.get("tree_size") or -1) == size
                        and verify_consistency(
                            bytes.fromhex(old_root),
                            int(old_size),
                            bytes.fromhex(root_hex),
                            size,
                            [bytes.fromhex(h) for h in cons["proof"]],
                        )
                    )
                except (KeyError, TypeError, ValueError):
                    bridge = False
            if not bridge:
                return 409, {
                    "error": "cannot bridge the pinned head to the offered checkpoint — "
                    "retry with a consistency proof from the pinned size",
                    "pinned": {
                        "tree_size": old_size,
                        "root_sha256": old_root,
                        "checkpoint_id": state.get("checkpoint_id"),
                    },
                }

    pseudo_id = f"witness:{issuer_key[:24]}:{cp.id}"
    cosig = store.receipt_for_visit(pseudo_id)
    if cosig is None:
        prev = store.latest_receipt()
        cosig = signer.issue(
            visit_id=pseudo_id,
            sequence=prev.sequence + 1 if prev else 1,
            prev_hash=prev.payload_hash if prev else None,
            facts={
                "record_type": "witness_cosignature",
                "subject_checkpoint": cp.id,
                "subject_tree_size": size,
                "subject_root_sha256": root_hex,
                "subject_issuer": issuer_key,
                "boundary": (
                    "The countersigning deployment attests it OBSERVED this "
                    "signed tree head and verified it extends the head it "
                    "previously pinned for this issuer — a forked, regressed, "
                    "or rewritten log cannot collect this counter-signature. "
                    "It does not attest the log's contents are true."
                ),
            },
        )
        store.put_receipt(cosig)
    new_state = {
        "schema": WITNESS_SCHEMA,
        "issuer_key": issuer_key,
        "tree_size": size,
        "root_sha256": root_hex,
        "checkpoint_id": cp.id,
    }
    store.put_setting(f"witness:{issuer_key}", new_state)
    return 200, {"cosignature": cosig.model_dump(mode="json"), "pinned": new_state}


def cosign_at(
    base_url: str, issuer_doc: dict, checkpoint_raw: dict, consistency_fn
) -> tuple[dict | None, str]:
    """One witness exchange: POST the checkpoint, retry once with the
    consistency bridge the 409 names (``consistency_fn(pinned_size)`` must
    produce the requester's own proof document — the witness verifies the
    math itself, so handing it the bridge is not trusting the requester).
    Returns (cosignature receipt | None, human line)."""
    body = {"issuer_doc": issuer_doc, "checkpoint": checkpoint_raw}
    resp = post_json(f"{base_url}/api/witness/cosign", body)
    if resp.get("status") == 409 and resp.get("pinned"):
        body["consistency"] = consistency_fn(int(resp["pinned"]["tree_size"]))
        resp = post_json(f"{base_url}/api/witness/cosign", body)
    if resp.get("status") == 200 and isinstance(resp.get("cosignature"), dict):
        return resp["cosignature"], f"cosigned ({resp['cosignature']['id'][:24]}…)"
    return None, f"refused — {resp.get('error') or resp}"


def check_cosignatures(doc: dict, cp_id: str, size: int, root_hex: str) -> tuple[int, list[str]]:
    """Verify the witness counter-signatures a checkpoint document carries.
    Each cosig is a witness_cosignature receipt whose subject fields must
    name THIS checkpoint and tree head — a validly-signed cosig about a
    different head is not a cosig of this head. Returns (verified_count,
    signer_ids)."""
    from .ledger import verify_receipt
    from .models import Receipt

    verified, signers = 0, []
    for raw in doc.get("cosignatures") or []:
        try:
            cosig = Receipt.model_validate(raw)
            p = cosig.payload
            if p.get("record_type") != "witness_cosignature":
                continue
            if (
                p.get("subject_checkpoint") != cp_id
                or int(p.get("subject_tree_size") or -1) != size
                or p.get("subject_root_sha256") != root_hex
            ):
                continue
            ok, _ = verify_receipt(cosig, public_key=cosig.public_key)
            if ok:
                verified += 1
                signers.append(cosig.public_key)
        except Exception:  # noqa: BLE001 — one bad cosig doesn't taint the rest
            continue
    return verified, signers


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


def post_json(url: str, body: dict, client=None, *, bound: int = 4 * 1024 * 1024) -> dict:
    """POST a JSON verification request — the witness cosign exchange —
    under the same transport policy as fetch_json: byte-capped response,
    wall-clock bounded, non-2xx surfaced as data ({'status', ...}), never
    as a trusted verdict. Everything in the exchange is verification
    material — signatures authenticate; transport denial can only stall,
    never forge."""
    import httpx

    post = client.post if client is not None else httpx.post
    try:
        r = post(url, json=body, timeout=15)
    except httpx.HTTPError as exc:
        raise ValueError(f"{url} unreachable: {exc}") from exc
    except httpx.InvalidURL as exc:
        raise ValueError(f"{url} malformed: {exc}") from exc
    raw = r.content
    if len(raw) > bound:
        raise ValueError(f"{url} response exceeds the 4 MB bound")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{url} did not serve JSON: {exc}") from exc
    return {"status": r.status_code, **(doc if isinstance(doc, dict) else {"body": doc})}
