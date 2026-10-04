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
    try:
        proof_first, proof_size = int(proof.get("first")), int(proof.get("tree_size"))
    except (TypeError, ValueError):
        return (
            None,
            False,
            ["ALERT: consistency proof is for different tree sizes than the head claims"],
        )
    if proof_first != old_size or proof_size != size:
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
    # A requester-supplied key_receipts pool feeds the lineage walks — bound it:
    # real lineages are single-digit hops, but every candidate is an Ed25519
    # verification, so an oversized pool is a CPU denial-of-service amplifier.
    if (
        not isinstance(issuer_doc.get("key_receipts") or [], list)
        or len(issuer_doc.get("key_receipts") or []) > 64
    ):
        return 422, {"error": "issuer_doc key_receipts malformed or over the 64-entry bound"}
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

    # The pin-check → sequence-allocate → sign → repin section is a single
    # store transaction: without it, two parallel offers each read the same
    # stale pin and BOTH get counter-signed — the witness would attest two
    # mutually-exclusive heads, which is exactly what a witness exists to
    # refuse. The RLock + BEGIN IMMEDIATE serializes us against every other
    # writer (checkpoints, cosigns, receipts) — the codebase's own @atomic
    # discipline, just applied to a free function.
    with store.transaction():
        state = store.setting(f"witness:{issuer_key}") or {}
        if state and state.get("schema") != WITNESS_SCHEMA:
            return 500, {"error": "witness pin state is corrupt — refusing to repin"}
        old_size = state.get("tree_size")
        old_root = state.get("root_sha256")
        if old_size is not None and not (isinstance(old_size, int) and isinstance(old_root, str)):
            return 500, {"error": "witness pin fields are corrupt — refusing to repin"}
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
                bridge = verify_extends(payload, first=int(old_size), first_root=bytes.fromhex(old_root))
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
        # Idempotency must still bind THIS head: a stored cosig attesting a
        # different (size, root) — an issuer re-signed the same checkpoint id
        # over different content — is not a cosig of this offer, so issue a
        # fresh one under the root-qualified pseudo instead of repinning onto
        # a mismatched attestation.
        if cosig is not None and (
            cosig.payload.get("subject_tree_size") != size
            or cosig.payload.get("subject_root_sha256") != root_hex
        ):
            cosig = None
            pseudo_id = f"witness:{issuer_key[:24]}:{cp.id}:{root_hex[:16]}"
            cosig = store.receipt_for_visit(pseudo_id)
            if cosig is not None and (
                cosig.payload.get("subject_tree_size") != size
                or cosig.payload.get("subject_root_sha256") != root_hex
            ):
                # A 64-bit root-prefix collision landed a different
                # attestation under the qualified pseudo — never reuse it;
                # fall deeper so the fresh cosig still stores uniquely.
                cosig = None
                pseudo_id = f"witness:{issuer_key[:24]}:{cp.id}:{root_hex}"
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
                    # Same discipline as engine-issued receipts: pin the
                    # mutation-journal head so the cosig also covers the
                    # witness's own audit trail at signing time.
                    "journal_head": store.journal_head(),
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
            "cosignature_id": cosig.id,
        }
        store.put_setting(f"witness:{issuer_key}", new_state)
        return 200, {"cosignature": cosig.model_dump(mode="json"), "pinned": new_state}


def witness_heads(store, issuer_key: str) -> dict:
    """This deployment's published witness view — every issuer head it has
    pinned by cosigning, transport-free and read-only. Served publicly so a
    third party can compare what THIS witness attests against what the
    issuer's deployment currently serves: two independently-signed views of
    'the log' that either agree or expose a fork.

    Every pin carries the cosignature RECEIPT itself — the settings row is
    unsigned, so publishing it alone would let a MITM or a dishonest
    endpoint claim any view. The receipt is the attestation: it verifies
    under the witness's own key and its signed subject fields are the only
    view a cross-check believes. Pins whose receipt is missing or no longer
    verifies are dropped — an unservable view is published as absent."""
    pins = []
    for _name, state in sorted(store.settings_by_prefix("witness:").items()):
        cosig_id = state.get("cosignature_id")
        cosig = store.receipt_for_visit(_pseudo_for(state)) if cosig_id is None else store.receipt(cosig_id)
        if (
            state.get("schema") != WITNESS_SCHEMA
            or not isinstance(state.get("issuer_key"), str)
            or not isinstance(state.get("tree_size"), int)
            or not isinstance(state.get("root_sha256"), str)
            or cosig is None
        ):
            continue
        pins.append(
            {
                "issuer_key": state["issuer_key"],
                "tree_size": state["tree_size"],
                "root_sha256": state["root_sha256"],
                "checkpoint_id": state.get("checkpoint_id"),
                "cosignature_id": cosig_id or cosig.id,
                "cosignature": cosig.model_dump(mode="json"),
            }
        )
    return {
        "schema": "attest.witness-heads/1",
        "witness_key": issuer_key,
        "pins": pins,
        "boundary": (
            "These are heads this deployment counter-signed after verifying "
            "each extended its previous pin — they attest what the witness "
            "OBSERVED, not that the logged content is true. Each pin's view "
            "lives in the signed cosignature receipt; the unsigned fields "
            "are a serving hint only."
        ),
    }


def _pseudo_for(state: dict) -> str | None:
    """The pseudo visit-id a cosignature is stored under —
    ``witness:{issuer_key[:24]}:{checkpoint_id}`` — for pins written before
    the state carried an explicit cosignature_id."""
    issuer_key, cp_id = state.get("issuer_key"), state.get("checkpoint_id")
    if not issuer_key or not cp_id:
        return None
    return f"witness:{str(issuer_key)[:24]}:{cp_id}"


def anchor_published_pins(store, heads: dict) -> dict:
    """Anchor each published pin inside the WITNESS's own transparency log.

    A witness_cosignature is a leaf in this deployment's Merkle log like
    every other receipt — so once a checkpoint covers it, "the witness
    attested this head" is itself publicly anchored. A witness that served
    one auditor cosig A and another auditor cosig B couldn't hide the
    double-speak: both attestations sit in its own published log, and any
    auditor can demand the inclusion proof. Pins whose cosig post-dates the
    newest checkpoint stay unanchored — absence is honest, never a claim."""
    from .models import Receipt

    receipts = store.receipts()
    latest_cp = next(
        (r for r in reversed(receipts) if r.payload.get("record_type") == "log_checkpoint"),
        None,
    )
    if latest_cp is None:
        return heads
    try:
        size = int(latest_cp.payload["tree_size"])
    except (TypeError, ValueError):
        return heads  # a malformed own-checkpoint just can't anchor anything
    from .transparency import inclusion_proof, leaf_hashes

    leaves = leaf_hashes(receipts)  # compute once, not per pin
    for pin in heads.get("pins") or []:
        cosig = pin.get("cosignature")
        if not isinstance(cosig, dict):
            continue
        try:
            proof = inclusion_proof(leaves, Receipt.model_validate(cosig).payload_hash, size=size)
        except Exception:  # noqa: BLE001 — unanchorable cosigs stay unanchored
            proof = None
        if proof is not None:
            pin["witness_anchor"] = {
                "checkpoint": latest_cp.model_dump(mode="json"),
                "proof": proof,
            }
    return heads


def compare_views(
    mine: dict | None,
    theirs: dict | None,
    witness_trusted: set | None = None,
    *,
    witness_pin: dict | None = None,
    fetch_wconsistency=None,
) -> tuple[str, str]:
    """Cross-check two independent pins of the same issuer's log — mine (the
    monitor's last verified head) against a witness's published pin.

    The pin's own fields are unsigned serving hints; the view a comparison
    believes comes only from the pin's signed cosignature receipt — its
    signature must verify under the witness's certified lineage
    (``witness_trusted``, from the witness's issuer doc) and its subject
    fields must name the pin's claimed head. Without that, a MITM or a
    dishonest endpoint could claim agreement it never signed or fabricate
    divergences to cry wolf. An unsigned or unverifiable view is reported
    as such — never silently compared, never a fork accusation.

    Two observers signing the same (size, root) is the strongest public-log
    evidence available: it means a single log was served to both. Same size
    with different roots is the unforgeable divergence — one of us was shown
    a forked history and no bridge can reconcile equal-size distinct roots.
    Different sizes stay honestly undecidable: cosign cadence lags behind
    log growth, so ahead/behind alone never proves a fork — it only names
    which observer saw further. Returns (verdict, human line).

    ``witness_pin`` is THIS monitor's own pinned head of the WITNESS's log
    (``{tree_size, root_sha256}``): a served witness_anchor only binds
    'the attestation is in the witness's published log' when the anchor's
    checkpoint provably extends — or is provably extended by — that pinned
    head. Without it the anchor verifies in isolation: still genuine
    crypto, but over a tree the witness could mint per victim.
    ``fetch_wconsistency(first, size)`` pulls consistency proofs off the
    witness's own log for the bridging cases the anchor's embedded
    `extends` doesn't already name."""
    if theirs is None:
        return "unseen", "the witness has never cosigned this issuer — no second view exists"
    if mine is None:
        return "no_pin", "no local pin to compare — run a monitor cycle first"
    from .ledger import verify_receipt
    from .models import Receipt

    cosig_raw = theirs.get("cosignature")
    try:
        cosig = Receipt.model_validate(cosig_raw)
    except Exception:  # noqa: BLE001
        return (
            "unverifiable",
            "the witness's pin carries no usable cosignature — the view is "
            "unsigned serving data, not an attestation; nothing to compare",
        )
    ok, why = verify_receipt(cosig, public_key=cosig.public_key)
    if not ok:
        return "unverifiable", f"the witness's published cosignature fails verification ({why})"
    if witness_trusted is not None and cosig.public_key not in witness_trusted:
        return (
            "unverifiable",
            "the published cosignature is signed outside the witness's certified "
            "issuer lineage — the view can't be attributed to this witness",
        )
    p = cosig.payload
    if (
        p.get("record_type") != "witness_cosignature"
        or p.get("subject_tree_size") != theirs.get("tree_size")
        or p.get("subject_root_sha256") != theirs.get("root_sha256")
        or p.get("subject_checkpoint") != theirs.get("checkpoint_id")
        or p.get("subject_issuer") != theirs.get("issuer_key")
        # The signed subject must name the issuer MY pin tracks — a pin
        # selected for a different issuer can never yield an honest verdict.
        or (isinstance(mine.get("issuer_key"), str) and p.get("subject_issuer") != mine["issuer_key"])
    ):
        return (
            "unverifiable",
            "the signed cosignature does not attest the pin's claimed head — "
            "the unsigned fields disagree with the receipt; the view is unusable",
        )
    # The witness may also publish its own log anchor: the cosig is a leaf
    # in the WITNESS's transparency log, and a checkpoint covering it means
    # the attestation itself is publicly committed — the witness can't
    # double-speak without forking its own log too. A served anchor that
    # doesn't verify is a lie like any other served falsehood.
    from .transparency import verify_inclusion

    anchor = theirs.get("witness_anchor")
    anchored_size: int | None = None
    if isinstance(anchor, dict):
        try:
            acp = Receipt.model_validate(anchor.get("checkpoint"))
            ap = acp.payload
            aproof = anchor.get("proof") or {}
            anchored = (
                ap.get("record_type") == "log_checkpoint"
                and (witness_trusted is None or acp.public_key in witness_trusted)
                and verify_receipt(acp, public_key=acp.public_key)[0]
                and isinstance(ap.get("tree_size"), int)
                and isinstance(ap.get("root_sha256"), str)
                and verify_inclusion(
                    bytes.fromhex(cosig.payload_hash),
                    int(ap["tree_size"]),
                    int(aproof["leaf_index"]),
                    [bytes.fromhex(h) for h in aproof["path"]],
                    bytes.fromhex(ap["root_sha256"]),
                )
            )
        except Exception:  # noqa: BLE001 — any malformed anchor is a lie, not None
            anchored = False
        if anchored:
            anchored_size = int(ap["tree_size"])
        else:
            return (
                "unverifiable",
                "the pin's witness_anchor does not verify — the cosig does not "
                "sit inside the witness's own published log as claimed",
            )
    elif anchor is not None:
        return (
            "unverifiable",
            "the pin's witness_anchor is malformed — not a checkpoint+proof "
            "document; a served anchor is either verifiable or a lie",
        )
    if anchored_size is not None:
        anchor_note = (
            f"; the cosig itself sits inside the witness's published log at "
            f"size {anchored_size} — the attestation is publicly anchored"
        )
        if witness_pin is not None:
            # Bind the anchor to the head THIS monitor pins of the witness's
            # own log — verified in isolation, an anchor could be a checkpoint
            # the witness minted over a per-victim private fork. Bridged to
            # our pin, 'published log' becomes provable rather than claimed.
            from .transparency import verify_consistency, verify_extends

            try:
                wp_size = int(witness_pin["tree_size"])
                wp_root = bytes.fromhex(witness_pin["root_sha256"])
                a_root = bytes.fromhex(ap["root_sha256"])
            except (KeyError, TypeError, ValueError):
                return (
                    "unverifiable",
                    "the monitor's own pin of the witness log is malformed — "
                    "the anchor can't be bound to a broken pin",
                )

            def _bridge(f_sz, f_root, t_sz, t_root) -> bool:
                proof = fetch_wconsistency(f_sz, t_sz) if fetch_wconsistency else None
                try:
                    nodes = [bytes.fromhex(h) for h in (proof or {}).get("proof") or []]
                except (TypeError, ValueError):
                    return False
                return bool(nodes) and verify_consistency(f_root, f_sz, t_root, t_sz, nodes)

            if anchored_size == wp_size:
                same_log = a_root == wp_root
            elif anchored_size > wp_size:
                # the anchor must provably extend the head we pinned
                ext = verify_extends(ap, first=wp_size, first_root=wp_root)
                same_log = ext if ext is not None else _bridge(wp_size, wp_root, anchored_size, a_root)
            else:
                # our pin moved past the anchor — append-only means the
                # published log must provably contain the anchor's tree
                same_log = _bridge(anchored_size, a_root, wp_size, wp_root)
            if not same_log:
                return (
                    "unverifiable",
                    "the pin's witness_anchor cannot be reconciled with the "
                    "witness log head this monitor pinned — a checkpoint over "
                    "a private per-victim fork verifies in isolation and is "
                    "exactly what this check exists to catch",
                )
            anchor_note = (
                f"; the cosig sits inside the witness's published log at size "
                f"{anchored_size} — verified against our own pin of that log, "
                "so double-speak would fork it publicly"
            )
    else:
        anchor_note = ""
    # From here the comparison runs on the SIGNED subject fields — the only
    # view the witness actually attested.
    my_size, my_root = int(mine["tree_size"]), str(mine["root_sha256"])
    w_size, w_root = int(p["subject_tree_size"]), str(p["subject_root_sha256"])
    w_id = cosig.id[:24]
    if my_size == w_size and my_root == w_root:
        return (
            "agree",
            f"witness attests the same head I see ({w_size} leaves, cosig {w_id}…) — "
            f"two independent observers, one log{anchor_note}",
        )
    if my_size == w_size:
        return (
            "diverged",
            f"DIVERGED: the witness pinned a DIFFERENT root at the same size {w_size} — "
            "a forked log was served to exactly one of us and no consistency proof "
            f"can reconcile equal-size distinct roots{anchor_note}",
        )
    if w_size < my_size:
        return (
            "witness_behind",
            f"witness last attested size {w_size}, behind my pinned {my_size} — "
            "undecidable without a bridge (cosign cadence honestly lags log growth)"
            f"{anchor_note}",
        )
    return (
        "witness_ahead",
        f"witness attests a NEWER head at size {w_size} than my pinned {my_size} — "
        "undecidable without a bridge: my pin may be stale, or the witness saw a "
        f"head the log can no longer produce{anchor_note}",
    )


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
    if resp.get("status") == 409 and isinstance(resp.get("pinned"), dict):
        try:
            body["consistency"] = consistency_fn(int(resp["pinned"].get("tree_size") or -1))
        except (TypeError, ValueError):
            return None, f"refused — malformed 409 pinned head: {resp.get('pinned')}"
        if not isinstance(body["consistency"], dict):
            return None, "refused — no consistency proof available for the pinned head"
        resp = post_json(f"{base_url}/api/witness/cosign", body)
    if resp.get("status") == 200:
        cosig = resp.get("cosignature")
        if isinstance(cosig, dict) and isinstance(cosig.get("id"), str):
            anchor = resp.get("witness_anchor")
            note = ""
            if isinstance(anchor, dict):
                try:
                    note = (
                        f" — attestation anchored in the witness's own log "
                        f"at size {int(anchor['checkpoint']['payload']['tree_size'])}"
                    )
                except (KeyError, TypeError, ValueError):
                    note = ""
            return cosig, f"cosigned ({cosig['id'][:24]}…){note}"
        return None, f"refused — malformed cosignature in response: {cosig}"
    return None, f"refused — {resp.get('error') or resp}"


def check_cosignatures(
    doc: dict,
    cp_id: str,
    size: int,
    root_hex: str,
    issuer_keys: set[str] | list[str] | None = None,
) -> tuple[int, list[str]]:
    """Verify the witness counter-signatures a checkpoint document carries.
    Each cosig is a witness_cosignature receipt whose subject fields must
    name THIS checkpoint and tree head — a validly-signed cosig about a
    different head is not a cosig of this head. Returns (verified_count,
    distinct_signer_ids).

    The count is an honest measure of independent attestations: the same
    cosig receipt pasted twice counts once, two cosigs from one witness
    key count once, and a cosig signed by the issuer's OWN key lineage
    (self-vouching — a sock-puppet) is not a witness at all. ``issuer_keys``
    is the issuer's trusted lineage where the caller has computed it;
    absent that, the checkpoint's own signer key is the floor."""
    from .ledger import verify_receipt
    from .models import Receipt

    self_keys = set(issuer_keys or ())
    cp_raw = doc.get("checkpoint")
    if isinstance(cp_raw, dict) and isinstance(cp_raw.get("public_key"), str):
        self_keys.add(cp_raw["public_key"])
    verified, signers = 0, []
    seen_ids, seen_keys = set(), set()
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
            # The cosig must name THIS issuer — one attesting another
            # deployment's head never counts here (compare_views parity).
            # Only gated when the caller computed a lineage — without it the
            # issuer family can't be told apart from a foreign one.
            if issuer_keys and p.get("subject_issuer") not in self_keys:
                continue
            if cosig.id in seen_ids or cosig.public_key in seen_keys:
                continue
            if cosig.public_key in self_keys:
                continue
            ok, _ = verify_receipt(cosig, public_key=cosig.public_key)
            if ok:
                seen_ids.add(cosig.id)
                seen_keys.add(cosig.public_key)
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
    if not isinstance(doc, dict):
        return {"status": r.status_code, "body": doc}
    # A "status" key in the body must never overwrite the real HTTP status —
    # a witness serving {"status": 200, ...} on an error response would
    # spoof the accepted path. The transport verdict wins; keep the body's
    # copy under its own key so nothing is lost.
    if "status" in doc:
        doc["body_status"] = doc.pop("status")
    return {"status": r.status_code, **doc}
