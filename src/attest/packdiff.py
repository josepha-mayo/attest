"""Compare two exported artifacts — case packs, dispute packs, or bare
bundle.json files — and report what changed between them.

Legitimate drift is append-only: new visits, new review receipts. Anything else
(a record vanishing, a signed payload changing under the same id, a receipt
hash disagreeing) is an anomaly worth stopping for, because none of it should
be possible on an honest deployment.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from . import transparency


class BoundedZip:
    """z.read wrapper enforcing per-file and cumulative decompressed caps —
    central-directory file_size entries can lie, so reads are capped on the
    actual inflated stream."""

    def __init__(self, z, *, per_file: int = 64 * 1024 * 1024, total: int = 256 * 1024 * 1024):
        self._z, self.per_file, self.total, self.seen = z, per_file, total, 0
        # The browser verifier implements stored/deflate only — a member
        # compressed another way (bzip2, lzma) must fail here too, never
        # verify on one surface and vanish on another. ZIP64 is likewise
        # outside the shared envelope: extract_version is the same
        # version-needed field the JS reader checks, and any member
        # genuinely needing it is definitionally over the bounds below.
        for i in z.infolist():
            if i.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError(
                    f"unsupported compression method {i.compress_type} for member {i.filename!r}"
                )
            if (
                i.extract_version >= zipfile.ZIP64_VERSION
                or i.file_size == 0xFFFFFFFF
                or i.compress_size == 0xFFFFFFFF
            ):
                # The browser reader rejects the 0xFFFFFFFF sentinels outright;
                # zipfile would decode a smuggled ZIP64 extra field even when
                # version-needed stays under 45 — one rule on both surfaces.
                raise ValueError(f"ZIP64 member {i.filename!r} exceeds the verification envelope")

    def namelist(self):
        return self._z.namelist()

    def read(self, name: str) -> bytes:
        with self._z.open(name) as f:
            chunks, n = [], 0
            while chunk := f.read(1 << 20):
                n += len(chunk)
                self.seen += len(chunk)
                if n > self.per_file or self.seen > self.total:
                    raise ValueError("pack expands beyond the 256 MB verification bound")
                chunks.append(chunk)
        return b"".join(chunks)


def check_member_names(names: list) -> str | None:
    """Fail closed on hostile or ambiguous zip member names.

    Duplicate names are ambiguous — different extractors pick different
    entries, so a pack can carry a benign member that verifies while a
    same-named hostile member overwrites it on unzip. ``..`` and absolute
    path segments slip past prefix/whitelist sweeps (``media/../x`` still
    starts with ``media/``) and escape the pack root on extraction. Neither
    is legitimate pack output — both fail the pack, not just the member.
    """
    seen: set = set()
    for name in names:
        if name in seen:
            return f"duplicate member name: {name}"
        seen.add(name)
        parts = name.replace("\\", "/").split("/")
        if ".." in parts or name.startswith(("/", "\\")) or ":" in name:
            return f"unsafe member name: {name}"
    return None


def _tools_pin_check(z, names, trusted, scope, failures, notes):
    """``verifier_manifest.json`` binds the pack's tooling bytes to the issuer:
    membership whitelists check *names* — only this signed receipt pins the
    *bytes*, which is what stops a forged always-green verifier riding a real
    pack. Same rule the server and embedded verifiers enforce."""
    pinned, err = check_tools_pin(
        lambda n: z.read(n) if n in names else None,
        names,
        trusted or set(),
        scope,
    )
    if err:
        failures.append(err)
    elif pinned:
        notes.append(f"{pinned} verifier tool(s) pinned by issuer-signed manifest")


def _log_pin_check(z, names, trusted, member_ids, failures, notes):
    """``log_checkpoint.json`` turns 'the pack's receipts verify' into 'the
    pack's receipts were committed to the deployment's published log' —
    an RFC 6962 inclusion proof each, checked against a signed tree head.
    A validly-signed receipt never committed to the log now fails.
    Returns the validated checkpoint payload when the member verifies so
    the artifact can carry its head into cross-pack comparison."""
    try:
        res, err = check_log_pin(
            lambda n: z.read(n) if n in names else None,
            member_ids,
            trusted or set(),
        )
    except Exception as exc:  # noqa: BLE001 — a pack member is hostile input:
        # an unhandled shape inside the checker must fail the diff closed,
        # never kill the whole comparison.
        failures.append(f"log_checkpoint.json: checker crashed on malformed pack data ({exc})")
        return None
    if err:
        failures.append(err)
        return None
    if not res:
        return None
    proven, size, cosigs, anchored, head, chain = res
    note = f"{proven} receipt(s) proven inside the deployment transparency log at checkpoint size {size}"
    if cosigs:
        note += f" — cosigned by {cosigs} witness(es)"
        if anchored:
            note += f" ({anchored} anchored in the witness's own published log)"
    if chain:
        note += f" — {len(chain)} prior signed head(s) embedded for cross-export reconciliation"
    notes.append(note)
    return {"head": head, "chain": chain}


def _bundle_receipt_ids(bundle) -> list[tuple[str, str, str]]:
    """(receipt_id, payload_hash, public_key) for the bundle's log-member
    receipts — the original. Review entries anchor to its hash inside the
    review chain (verified separately); they are not leaves of the
    receipts-table log."""
    try:
        o = bundle["original"]
        return [(o["id"], o["payload_hash"], o["public_key"])]
    except (KeyError, TypeError):
        return []  # malformed bundles already fail in the verify loop


_TOOLS_PIN_NAME = "verifier_manifest.json"
_VERIFIER_TOOL_NAMES = frozenset(
    {"verify_case.py", "verify_bundle.py", "verify.html", "index.html", "README.txt"}
)


def check_tools_pin(read_member, names, trusted: set, scope: str) -> tuple[int | None, str | None]:
    """Validate the issuer-signed ``verifier_manifest.json`` pin: the pack's
    own verifier tooling must byte-match the signed sha256 set, or a forged
    always-green script can ride a genuine pack — membership whitelists names,
    never bytes. ``scope`` binds the receipt to this pack (``visit:{id}`` or
    ``site:{id}``). Mirrors the embedded ``check_tools`` and the browser
    verifier's ``checkTools`` exactly: absent is a legacy pack (reported,
    not failed); present-and-wrong fails. ``read_member(name)`` returns member
    bytes or None. Returns (pinned_count, None), (None, None) when absent, or
    (None, error)."""
    raw = read_member(_TOOLS_PIN_NAME)
    if raw is None:
        return None, None
    import hashlib

    from .ledger import verify_receipt
    from .models import Receipt

    try:
        vm = transparency.json_loads(raw)
    except Exception:  # noqa: BLE001
        return None, "verifier_manifest.json: not readable JSON"
    try:
        receipt = Receipt.model_validate(vm)
    except Exception as exc:  # noqa: BLE001
        return None, f"verifier_manifest.json: not a receipt ({exc})"
    payload = receipt.payload
    if payload.get("record_type") != "verifier_manifest":
        return None, "verifier_manifest.json: not a verifier_manifest receipt"
    if payload.get("scope") != scope:
        return None, "verifier_manifest.json: signed for a different pack — grafted pin"
    if receipt.public_key not in trusted:
        return None, "verifier_manifest.json: signed outside the trusted issuer chain"
    ok, why = verify_receipt(receipt, public_key=receipt.public_key)
    if not ok:
        return None, f"verifier_manifest.json: {why}"
    tools = payload.get("tools")
    if not isinstance(tools, dict) or not tools:
        return None, "verifier_manifest.json: tools map missing or malformed"
    for name, want in tools.items():
        if not isinstance(name, str) or not isinstance(want, str) or name not in _VERIFIER_TOOL_NAMES:
            return None, f"verifier_manifest.json: unsafe or unknown member {name!r}"
        body = read_member(name)
        if body is None:
            return None, f"{name}: pinned verifier tool missing from the pack"
        if hashlib.sha256(body).hexdigest() != want:
            return None, (
                f"{name}: bytes differ from the issuer-signed pin — "
                "a verifier script modified after export cannot be trusted"
            )
    for name in names:
        # A tool member that ISN'T pinned is as suspect as a mismatched one —
        # otherwise the forger just ships a doctored index.html. Tools live at
        # the pack root, so nested members can't smuggle the check.
        if "/" not in name and name in _VERIFIER_TOOL_NAMES and name not in tools:
            return None, f"{name}: verifier tooling present but not covered by the signed pin"
    return len(tools), None


_LOG_MEMBER = "log_checkpoint.json"


def check_log_pin(
    read_member, receipt_ids: list[tuple[str, str, str]], trusted: set
) -> tuple[tuple[int, int, int, dict] | None, str | None]:
    """Validate ``log_checkpoint.json``: a signed Merkle Tree Head plus an
    RFC 6962 inclusion path proving every receipt in the pack sat inside the
    deployment's published log — 'valid signature' alone no longer implies
    'was ever logged'. ``receipt_ids`` is ``(receipt_id, payload_hash,
    public_key)`` for every receipts-table member the pack holds (bundle
    originals, attestations, manifests, lifecycle receipts — review entries
    anchor to the original's hash instead of sitting in the log). Absent is a
    pre-checkpoint pack — reported,
    not failed; present-and-incomplete fails closed. The checkpoint receipt
    itself anchors the tree and carries no proof (its own leaf postdates its
    head). Returns ((proven, tree_size, cosigs, anchored_cosigs,
    checkpoint_payload), None), (None, None) when absent, or
    (None, error)."""
    raw = read_member(_LOG_MEMBER)
    if raw is None:
        return None, None
    from .ledger import verify_receipt
    from .models import Receipt
    from .transparency import (
        MAX_TREE_SIZE,
        hex_bytes,
        json_is_int,
        verify_extends,
        verify_inclusion,
    )

    try:
        doc = transparency.json_loads(raw)
    except Exception:  # noqa: BLE001
        return None, "log_checkpoint.json: not readable JSON"
    cp_raw = doc.get("checkpoint") if isinstance(doc, dict) else None
    proofs = doc.get("proofs") if isinstance(doc, dict) else None
    if not isinstance(cp_raw, dict) or not isinstance(proofs, dict):
        return None, "log_checkpoint.json: malformed checkpoint document"
    try:
        cp = Receipt.model_validate(cp_raw)
    except Exception as exc:  # noqa: BLE001
        return None, f"log_checkpoint.json: checkpoint is not a receipt ({exc})"
    payload = cp.payload
    if payload.get("record_type") != "log_checkpoint":
        return None, "log_checkpoint.json: not a log_checkpoint receipt"
    if cp.public_key not in trusted:
        return None, "log_checkpoint.json: signed outside the trusted issuer chain"
    ok, why = verify_receipt(cp, public_key=cp.public_key)
    if not ok:
        return None, f"log_checkpoint.json: {why}"
    size = payload.get("tree_size")
    root_hex = payload.get("root_sha256")
    if not json_is_int(size) or size < 1 or size > MAX_TREE_SIZE or not isinstance(root_hex, str):
        return None, "log_checkpoint.json: malformed tree head"
    size = int(size)
    try:
        root_b = hex_bytes(root_hex, length=32)
    except ValueError:
        return None, "log_checkpoint.json: malformed tree head"
    # The checkpoint's own signed continuity claim — a head whose embedded
    # bridge fails is attesting a history it cannot prove (verify_extends
    # self-check parity with the standalone checkpoint path).
    if verify_extends(payload) is False:
        return None, "log_checkpoint.json: extends bridge attests a history it cannot prove"
    proven = 0
    referenced_ph: set = set()
    for rid, ph, pub in receipt_ids:
        # Only issuer-lineage receipts owe proofs: a foreign-signed pool
        # entry is inert (it can't join the trust walk) and never claimed
        # log membership — requiring its proof would let a graft kill packs.
        if pub not in trusted:
            continue
        if ph == cp.payload_hash:
            continue
        p = proofs.get(ph)
        if not isinstance(p, dict):
            return None, (
                f"log_checkpoint.json: receipt {rid} has no inclusion proof — "
                "never committed to the deployment log"
            )
        path_v = p.get("path")
        if path_v is not None and not isinstance(path_v, list):
            # a dict path would iterate keys — reject outright on all surfaces
            return None, f"log_checkpoint.json: malformed proof for receipt {rid}"
        try:
            path = [hex_bytes(h, length=32) for h in path_v or []]
        except (TypeError, ValueError):
            return None, f"log_checkpoint.json: malformed proof for receipt {rid}"
        idx = p.get("leaf_index")
        try:
            leaf_b = hex_bytes(ph, length=32)
        except (TypeError, ValueError):
            return None, f"log_checkpoint.json: malformed receipt hash for {rid}"
        if not json_is_int(idx) or not verify_inclusion(leaf_b, size, int(idx), path, root_b):
            return None, (
                f"log_checkpoint.json: inclusion proof for receipt {rid} does not reach the signed tree head"
            )
        referenced_ph.add(ph)
        proven += 1
    # Embedded evidence receipts (`attest checkpoint --include monitor:`)
    # riding a crafted checkpoint doc — same closed discipline as the CLI,
    # the embedded verifier, and the browser page: dedupe, issuer lineage,
    # signature, and a working inclusion proof.
    embedded = doc.get("receipts")
    if embedded is not None:
        if not isinstance(embedded, list) or len(embedded) > 2048:
            return None, "log_checkpoint.json: 'receipts' must be a list of at most 2048"
        seen_ids: set = set()
        for raw in embedded:
            try:
                er = Receipt.model_validate(raw)
            except Exception as exc:  # noqa: BLE001
                return None, f"log_checkpoint.json: embedded receipt malformed ({exc})"
            if er.id in seen_ids:
                return None, f"log_checkpoint.json: embedded receipt {er.id[:24]}… listed twice"
            seen_ids.add(er.id)
            if er.public_key not in trusted:
                return None, (
                    f"log_checkpoint.json: embedded receipt {er.id[:24]}… signed outside the issuer lineage"
                )
            ok2, why2 = verify_receipt(er, public_key=er.public_key)
            if not ok2:
                return None, f"log_checkpoint.json: embedded receipt {er.id[:24]}… invalid: {why2}"
            p = proofs.get(er.payload_hash)
            if not isinstance(p, dict):
                return None, (
                    f"log_checkpoint.json: embedded receipt {er.id[:24]}… carries no working inclusion proof"
                )
            try:
                path = [hex_bytes(h, length=32) for h in p.get("path") or []]
                idx = p.get("leaf_index")
                leaf_b = hex_bytes(er.payload_hash, length=32)
            except (TypeError, ValueError):
                return None, f"log_checkpoint.json: malformed proof for receipt {er.id[:24]}…"
            if not json_is_int(idx) or not verify_inclusion(leaf_b, size, int(idx), path, root_b):
                return None, (
                    f"log_checkpoint.json: embedded receipt {er.id[:24]}… carries no working inclusion proof"
                )
            referenced_ph.add(er.payload_hash)
            proven += 1
    # Every proofs entry must verify — the CLI and both embedded verifiers
    # refuse an unreferenced junk entry; a broken proof is a lie, not
    # decoration. An extra entry that DOES verify is tolerated here.
    for ph, p in proofs.items():
        if ph in referenced_ph:
            continue
        if not isinstance(p, dict):
            return None, "log_checkpoint.json: unreferenced inclusion proof is malformed"
        try:
            path = [hex_bytes(h, length=32) for h in p.get("path") or []]
            idx = p.get("leaf_index")
            leaf_b = hex_bytes(ph, length=32)
        except (TypeError, ValueError):
            return None, "log_checkpoint.json: unreferenced inclusion proof is malformed"
        if not json_is_int(idx) or not verify_inclusion(leaf_b, size, int(idx), path, root_b):
            return None, (
                "log_checkpoint.json: unreferenced inclusion proof does not reach the signed tree head"
            )
    # The signed checkpoint chain (`chain`): prior heads the export embeds
    # so packs exported far apart can reconcile offline — each member is a
    # full signed checkpoint receipt whose own `extends` bridge does the
    # hopping. Members verify like embedded evidence receipts minus the
    # inclusion proof (checkpoints are heads, not leaves), each must sit
    # strictly below the doc's head, and one tree size may carry only one
    # root — two signed roots at a single size inside one document is a
    # fork claim the walk cannot read honestly, so it fails closed.
    chain_members: list = []
    chain = doc.get("chain")
    if chain is not None:
        if not isinstance(chain, list) or len(chain) > 64:
            return None, "log_checkpoint.json: 'chain' must be a list of at most 64"
        seen_cids: set = set()
        seen_sizes: dict = {}
        for raw in chain:
            try:
                mr = Receipt.model_validate(raw)
            except Exception as exc:  # noqa: BLE001
                return None, f"log_checkpoint.json: chain member malformed ({exc})"
            if mr.id in seen_cids:
                return None, f"log_checkpoint.json: chain member {mr.id[:24]}… listed twice"
            seen_cids.add(mr.id)
            mp = mr.payload
            if not isinstance(mp, dict) or mp.get("record_type") != "log_checkpoint":
                return None, (
                    f"log_checkpoint.json: chain member {mr.id[:24]}… is not a log_checkpoint receipt"
                )
            if mr.public_key not in trusted:
                return None, (
                    f"log_checkpoint.json: chain member {mr.id[:24]}… signed outside the issuer lineage"
                )
            ok3, why3 = verify_receipt(mr, public_key=mr.public_key)
            if not ok3:
                return None, f"log_checkpoint.json: chain member {mr.id[:24]}… invalid: {why3}"
            msize, mroot = mp.get("tree_size"), mp.get("root_sha256")
            if (
                not json_is_int(msize)
                or not 1 <= int(msize) < size
                or not isinstance(mroot, str)
                or len(mroot) != 64
            ):
                return None, (
                    f"log_checkpoint.json: chain member {mr.id[:24]}… carries a malformed or non-prior head"
                )
            if verify_extends(mp) is False:
                return None, (
                    f"log_checkpoint.json: chain member {mr.id[:24]}… signs a bridge it cannot prove"
                )
            if msize in seen_sizes and seen_sizes[msize] != mroot.lower():
                return None, (f"log_checkpoint.json: chain carries two signed heads at size {msize}")
            seen_sizes[msize] = mroot.lower()
            chain_members.append({"id": mr.id, "size": int(msize), "root": mroot, "payload": mp})
        chain_members.sort(key=lambda m: m["size"])
    # Witness counter-signatures ride the checkpoint document: verified
    # under each cosig's own key + subject binding, reported as auxiliary
    # attestation — never the gate the issuer's own checkpoint is.
    from .logmonitor import check_cosig_anchors, check_cosignatures

    cosigs, _ = check_cosignatures(doc, cp.id, size, root_hex, issuer_keys=trusted)
    # Packed self-anchors are auxiliary too, but a PRESENT one that fails
    # is a lie, not a downgrade — same closed posture as a bad proof.
    anchored, anchor_errors = check_cosig_anchors(doc)
    if anchor_errors:
        return None, f"log_checkpoint.json: {anchor_errors[0]}"
    # The validated checkpoint payload rides out so callers diffing two
    # packs can compare the SIGNED heads themselves — same-size different-
    # root is a proven fork; an embedded extends bridge proves append-only
    # growth between consecutive exports with no network at all. `chain`
    # members ride alongside so the reconcile can multi-hop: a signed head
    # reached by walking verified bridges is as proven as a direct one.
    return (proven, size, cosigs, anchored, payload, chain_members), None


def _key_pool(z, attestations: dict) -> list:
    """The pack's signed key-rotation link receipts (rotations AND adoptions),
    read from its attestation files — a pack written across a key rotation
    legitimately mixes issuer keys, and the trust set derives from these."""
    from .models import Receipt

    pool = []
    for rid in attestations:
        try:
            att = Receipt.model_validate(transparency.json_loads(z.read(f"attestations/{rid}.json")))
        except Exception:  # noqa: BLE001 — unreadable members fail in the verify loop
            continue
        if att.payload.get("record_type") in ("key_rotation", "key_adoption", "key_revocation"):
            pool.append(att)
    return pool


def _trusted_set(issuer: str | None, key_pool: list) -> set | None:
    """Issuer plus every key the signed, successor-consented rotation chain
    endorses — ``None`` when there is nothing to derive trust from."""
    if not issuer:
        return None
    from .ledger import descendant_issuer_keys, trusted_issuer_keys

    return trusted_issuer_keys(issuer, key_pool) | descendant_issuer_keys(issuer, key_pool)


def _ancestor_set(issuer: str | None, key_pool: list) -> set | None:
    """The declared issuer plus its consented ancestors — the membership set
    for case-pack content. A key NEWER than the manifest's own issuer can
    never honestly sign a member of that pack: descendants belong only to
    the pin's reachability check, mirroring _verify_case_pack and the
    embedded/browser verifiers."""
    if not issuer:
        return None
    from .ledger import trusted_issuer_keys

    return trusted_issuer_keys(issuer, key_pool)


def _pin_linked(key: str | None, declared: str | None, key_pool: list) -> bool:
    """Whether the pinned key shares one signed lineage with the pack's
    declared issuer — either direction (a newer doc pins a pre-rotation
    pack; an older doc still verifies a rotated deployment's packs)."""
    if key is None:
        return True
    if not declared:
        return False
    from .ledger import descendant_issuer_keys, trusted_issuer_keys

    return key in (trusted_issuer_keys(declared, key_pool) | descendant_issuer_keys(declared, key_pool))


def _verify_artifact_bundles(
    visits_bundles: dict, issuer: str | None, trusted: set | None = None
) -> list[str]:
    """Independently verify each bundle in an artifact before trusting its
    contents — a diff over unverified receipts is meaningless."""
    from .models import ReviewBundle
    from .reviews import verify_bundle

    failures = []
    for vid, bundle in visits_bundles.items():
        try:
            parsed = ReviewBundle.model_validate(bundle)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{vid}: not a valid bundle ({exc})")
            continue
        if trusted is not None:
            ok, why = verify_bundle(parsed, trusted_keys=trusted)
        else:
            ok, why = verify_bundle(parsed, public_key=issuer or parsed.original.public_key)
        if not ok:
            failures.append(f"{vid}: {why}")
    return failures


def _visit_summary(bundle: dict, manifest_entry: dict | None = None) -> dict:
    """Normalize one visit into a comparable record."""
    original = bundle["original"]
    review_hashes = [r["receipt"]["payload_hash"] for r in bundle.get("reviews", [])]
    out = {
        "receipt_id": original["id"],
        "payload_hash": original["payload_hash"],
        "state": original["payload"].get("state"),
        "review_hashes": review_hashes,
        "media_digests": sorted(
            e["media_sha256"] for e in original["payload"].get("evidence", []) if e.get("media_sha256")
        ),
        # The raw payload rides along so a changed-record anomaly can name
        # the altered top-level fields, not just the receipt that moved.
        "original_payload": original["payload"],
    }
    if manifest_entry:
        out["manifest_state"] = manifest_entry.get("state")
        out["manifest_hash"] = manifest_entry.get("payload_hash")
        out["countersign"] = (manifest_entry.get("countersign") or {}).get("state")
    return out


def _verify_attestation_files(
    z, attestations: dict, issuer: str | None, trusted: set | None = None
) -> list[str]:
    """Verify each attestation receipt file the manifest lists — signature AND
    the manifest's claimed visit_id/payload_hash, so a swapped (but validly
    signed) receipt file cannot pass as the listed attestation. Attestations
    signed under rotation-endorsed retired keys verify under their own key."""
    from .ledger import verify_receipt
    from .models import Receipt

    failures = []
    for rid, entry in attestations.items():
        try:
            att = Receipt.model_validate(transparency.json_loads(z.read(f"attestations/{rid}.json")))
        except Exception as exc:  # noqa: BLE001
            failures.append(f"attestation {rid}: missing or invalid ({exc})")
            continue
        if att.id != rid:
            failures.append(f"attestation {rid}: file contains receipt {att.id}")
            continue
        # Strict like every verdict surface: an absent manifest field is a
        # MISMATCH (att fields are always non-None), not a skipped compare.
        if entry.get("payload_hash") != att.payload_hash:
            failures.append(f"attestation {rid}: payload hash differs from manifest entry")
            continue
        if entry.get("visit_id") != att.visit_id:
            failures.append(f"attestation {rid}: visit_id differs from manifest entry")
            continue
        if trusted is not None and att.public_key not in trusted:
            failures.append(f"attestation {rid}: issued under a key outside the rotation chain")
            continue
        ok, why = verify_receipt(att, public_key=att.public_key if trusted else issuer or att.public_key)
        if not ok:
            failures.append(f"attestation {rid}: {why}")
    return failures


def _verify_manifest_signature(manifest: dict, issuer: str | None, trusted: set | None = None) -> str | None:
    """Verify the manifest's signature_receipt and its hash-cover over the
    visit list — returns a failure string or None."""
    from .ledger import payload_hash, verify_receipt
    from .models import Receipt

    sig = manifest.get("signature_receipt")
    if sig is None:
        return None
    try:
        receipt = Receipt.model_validate(sig)
    except Exception as exc:  # noqa: BLE001
        return f"manifest signature_receipt invalid ({exc})"
    if trusted is not None and receipt.public_key not in trusted:
        return "manifest signature: signed by a key outside the rotation chain"
    ok, why = verify_receipt(
        receipt, public_key=receipt.public_key if trusted else issuer or receipt.public_key
    )
    if not ok:
        return f"manifest signature: {why}"
    core = {k: v for k, v in manifest.items() if k != "signature_receipt"}
    if payload_hash(core) != sig["payload"].get("manifest_sha256"):
        return "manifest content hash mismatch (manifest was altered)"
    # The signed export also names the exact visit↔hash set — a manifest whose
    # listed records disagree with what was signed is an altered export, not
    # an unsigned one. Mirrors _verify_case_pack's receipt_hashes check.
    signed_hashes = sig["payload"].get("receipt_hashes", {})
    # Guard like _manifest_consistency: a malformed visit entry must fail
    # the comparison, never raise out of the verifier on a signed export.
    listed = {
        v["visit_id"]: v["payload_hash"]
        for v in manifest.get("visits", [])
        if isinstance(v, dict) and "visit_id" in v and "payload_hash" in v
    }
    # Homogeneous types before comparing — str->str JSON maps only, so a
    # cross-type listed key/value can never bridge (True==1, 5 vs "5").
    if (
        not isinstance(signed_hashes, dict)
        or any(not isinstance(k, str) or not isinstance(h, str) for k, h in signed_hashes.items())
        or any(not isinstance(k, str) or not isinstance(h, str) for k, h in listed.items())
        or listed != signed_hashes
    ):
        return "manifest visit list disagrees with the signed export"
    return None


def _manifest_consistency(manifest: dict, bundles: dict, notes: list[str]) -> list[str]:
    """Checks beyond signatures: duplicate visit entries and manifest-claimed
    payload hashes must match the bundles actually shipped. Mirrors the parity
    every other verifier enforces."""
    failures = []
    seen = set()
    for v in manifest.get("visits", []):
        if not isinstance(v, dict):
            failures.append("manifest visit entry malformed")
            continue
        vid = v.get("visit_id")
        if vid in seen:
            failures.append(f"{vid}: listed twice in manifest")
            continue
        seen.add(vid)
        claimed = v.get("payload_hash")
        bundle = bundles.get(vid)
        # An absent manifest hash is a MISMATCH like the verdict surfaces
        # (bundle hash is never None), not a skipped comparison.
        if bundle and claimed != bundle["original"]["payload_hash"]:
            actual = bundle["original"]["payload_hash"]
            c = claimed[:12] if isinstance(claimed, str) else repr(claimed)
            a = actual[:12] if isinstance(actual, str) else repr(actual)
            failures.append(f"{vid}: manifest claims {c}… but bundle hashes {a}…")
    if manifest.get("signature_receipt") is None:
        notes.append("unsigned manifest — listed states and worker stances are unverified claims")
    return failures


def _pyset(x):
    """set() mirror for JSON values: list→elements, dict→keys, str→chars —
    exactly what ``set(x)`` yields on the other surfaces. Non-iterables
    (null/int/bool) return None so the caller can fail like the TypeError
    the Python surfaces hit."""
    if isinstance(x, (list, tuple, set)):
        return set(x)
    if isinstance(x, (str, dict)):
        return set(x)
    return None


def _redaction_withheld(z, marker_name: str, failures: list) -> set:
    """Read a redaction.json member's withheld digest set.

    Absent marker → empty set (nothing withheld). Present-but-unreadable or
    non-set()-able withheld_digests → flagged, treated as empty — a malformed
    marker can never *mask* a missing media digest."""
    if marker_name not in z.namelist():
        return set()
    try:
        marker = transparency.json_loads(z.read(marker_name))
        if not isinstance(marker, dict):
            raise ValueError("marker is not an object")
        # Absent key → ∅; explicit null → set(None) TypeError on the Python
        # surfaces → fail here too. Dict/str coerce like set() does.
        raw = marker["withheld_digests"] if "withheld_digests" in marker else []
        withheld = _pyset(raw)
        if withheld is None:
            raise ValueError("withheld_digests is not set-able")
        return withheld
    except Exception as exc:  # noqa: BLE001 — malformed marker flags, never masks
        failures.append(f"{marker_name}: malformed ({exc})")
        return set()


def _media_members_check(z, names: set, prefix: str, payload: dict, withheld: set, failures: list) -> None:
    """Hash each ``prefix``-rooted member and compare against the signed
    evidence digests — the same check app/embedded/browser run. A member
    whose bytes hash to nothing the evidence names is smuggled content, and
    a signed digest neither present nor withheld is missing."""
    import hashlib

    evidence = payload.get("evidence") if isinstance(payload, dict) else None
    digests = {
        e.get("media_sha256")
        for e in (evidence if isinstance(evidence, list) else [])
        if isinstance(e, dict) and isinstance(e.get("media_sha256"), str)
    }
    if not withheld <= digests:
        failures.append("redaction.json lists digests not in the signed evidence")
    found = set()
    for name in names:
        if not name.startswith(prefix) or name.endswith("/"):
            continue
        try:
            h = hashlib.sha256(z.read(name)).hexdigest()
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{name}: unreadable media member ({exc})")
            continue
        if h not in digests:
            failures.append(f"{name}: media not named by the signed evidence")
            continue
        found.add(h)
    for d in digests:
        if d not in found and d not in withheld:
            failures.append(f"media {d[:12]}… missing (not listed as withheld)")


def load_artifact(path: str | Path, key: str | None = None, extra_key_receipts: list | None = None) -> dict:
    """Load a case pack, dispute pack, or bare bundle.json into a normalized map.
    Each artifact's signed contents are independently verified — a diff over
    unverified receipts would silently compare forged data. A pinned `key`
    makes verification trust only that issuer. ``extra_key_receipts`` (e.g. a
    deployment's fetched issuer document) extends the lineage the pack itself
    carries — a pre-rotation export still verifies under the current issuer."""
    path = Path(path)
    visits: dict[str, dict] = {}
    issuer = None
    failures: list[str] = []
    notes: list[str] = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as raw:
            bad_name = check_member_names(raw.namelist())
            if bad_name:
                raise ValueError(f"{path}: {bad_name}")
            # Declared-size bound before any reads, same as app._verify_pack /
            # the browser: a member never opened (e.g. media) can still carry a
            # lying central-directory usize over the limit.
            if sum(i.file_size for i in raw.infolist()) > 256 * 1024 * 1024:
                raise ValueError(f"{path}: zip too large (declared size over 256MB)")
            z = BoundedZip(raw)
            names = set(z.namelist())
            if "manifest.json" in names:
                manifest = transparency.json_loads(z.read("manifest.json"))
                if not isinstance(manifest, dict):
                    raise ValueError(f"{path}: manifest.json is not an object")
                declared = manifest.get("issuer_key")
                issuer = key or declared
                attestations = {}
                for a in manifest.get("attestations", []):
                    if not isinstance(a, dict) or not a.get("receipt_id"):
                        failures.append("manifest attestation entry malformed")
                        continue
                    attestations[a["receipt_id"]] = a
                entries = {}
                for v in manifest.get("visits", []):
                    if not isinstance(v, dict) or not v.get("visit_id"):
                        failures.append("manifest visit entry malformed")
                        continue
                    entries[v["visit_id"]] = v
                bundles = {}
                for vid in entries:
                    try:
                        bundles[vid] = transparency.json_loads(z.read(f"visits/{vid}/bundle.json"))
                    except KeyError:
                        failures.append(f"{vid}: bundle listed but missing from pack")
                        continue
                    except (ValueError, TypeError):
                        failures.append(f"{vid}: bundle member is not valid JSON")
                        continue
                    try:
                        visits[vid] = _visit_summary(bundles[vid], entries[vid])
                    except Exception as exc:  # noqa: BLE001 — flag the member, keep diffing
                        failures.append(f"{vid}: bundle malformed ({exc})")
                        bundles.pop(vid, None)
                failures += _manifest_consistency(manifest, bundles, notes)
                pool = _key_pool(z, attestations) + list(extra_key_receipts or [])
                # Membership trusts the declared issuer plus its ancestors —
                # a forward-linked descendant can never honestly sign pack
                # content. The pin links through the pooled lifecycle in
                # either direction, like _verify_case_pack.
                trusted = _ancestor_set(declared, pool)
                if not _pin_linked(key, declared, pool):
                    failures.append(
                        "pinned issuer has no signed lifecycle link to the "
                        "pack's declared issuer — wrong deployment?"
                    )
                failures += _verify_artifact_bundles(bundles, issuer, trusted)
                failures += _verify_attestation_files(z, attestations, issuer, trusted)
                # The revocation overlay annotates, never fails — the same
                # suspect-window line every other verifier surface reports.
                # With no issuer anchor at all there is no revocation
                # authority either — pool position must never confer it, so
                # an issuer-less manifest gets no suspect-window notes.
                from .ledger import revoked_issuer_keys, suspect_receipts
                from .models import Receipt as _R

                revoked = revoked_issuer_keys(pool, issuer_key=issuer) if issuer else {}
                if revoked:
                    recs = []
                    for b in bundles.values():
                        try:
                            recs.append(_R.model_validate(b["original"]))
                            recs += [_R.model_validate(e["receipt"]) for e in b.get("reviews", [])]
                        except Exception:  # noqa: BLE001 — malformed already flagged
                            continue
                    sN = len(suspect_receipts(recs, revoked=revoked))
                    if sN:
                        notes.append(
                            f"{sN} record(s) signed by a revoked issuer inside its "
                            "suspect window — integrity intact, trust qualified"
                        )
                    pN = len(suspect_receipts(pool, revoked=revoked))
                    if pN:
                        notes.append(
                            f"{pN} key-lifecycle receipt(s) signed inside a suspect "
                            "window — the trust pivot itself inherits the doubt"
                        )
                # Fail closed on ANY member the signed manifest does not name —
                # top-level files and extra members inside listed visit dirs
                # too, not just foreign attestations/visits trees.
                allowed = {
                    "manifest.json",
                    "README.txt",
                    "verify_case.py",
                    "verify.html",
                    "index.html",
                    "verifier_manifest.json",
                    "log_checkpoint.json",
                }
                allowed |= {f"attestations/{rid}.json" for rid in attestations}
                for vid in entries:
                    allowed |= {
                        f"visits/{vid}/bundle.json",
                        f"visits/{vid}/redaction.json",
                    }
                for name in names:
                    if name.endswith("/") or name in allowed:
                        continue
                    parts = name.split("/")
                    if (
                        len(parts) >= 4
                        and parts[0] == "visits"
                        and parts[2] == "media"
                        and parts[1] in entries
                    ):
                        continue  # digest-checked against the evidence below
                    failures.append(f"{name}: present but not in the signed manifest")
                # Media bytes are NOT exempt — every visits/<vid>/media/ member
                # must hash to a digest the visit's signed evidence names, and
                # every signed digest must resolve to a member or a withheld
                # listing. The manifest's media_withheld must match the
                # redaction marker exactly.
                for vid, mentry in entries.items():
                    marker = f"visits/{vid}/redaction.json"
                    withheld = _redaction_withheld(z, marker, failures)
                    # Absent → ∅; explicit null/non-set-able → the Python
                    # surfaces' set(x) raises → fail here too.
                    mw = _pyset(mentry["media_withheld"] if "media_withheld" in mentry else [])
                    if mw is None or mw != withheld:
                        failures.append(f"{vid}: media_withheld disagrees with redaction.json")
                    ob = b.get("original") if isinstance(b := bundles.get(vid), dict) else None
                    payload = ob.get("payload") if isinstance(ob, dict) else None
                    _media_members_check(
                        z,
                        names,
                        f"visits/{vid}/media/",
                        payload if isinstance(payload, dict) else {},
                        withheld,
                        failures,
                    )
                _site = manifest.get("site")
                _tools_pin_check(
                    z,
                    names,
                    trusted,
                    f"site:{(_site.get('id') if isinstance(_site, dict) else None) or ''}",
                    failures,
                    notes,
                )
                member_ids = []
                for b in bundles.values():
                    member_ids += _bundle_receipt_ids(b)
                for rid in attestations:
                    try:
                        att = transparency.json_loads(z.read(f"attestations/{rid}.json"))
                        if att.get("id") and att.get("payload_hash"):
                            member_ids.append((att["id"], att["payload_hash"], att.get("public_key")))
                    except Exception:  # noqa: BLE001 — flagged in the verify loop
                        continue
                sr = manifest.get("signature_receipt") or {}
                if sr.get("id") and sr.get("payload_hash"):
                    member_ids.append((sr["id"], sr["payload_hash"], sr.get("public_key")))
                if "verifier_manifest.json" in names:
                    try:
                        vm = transparency.json_loads(z.read("verifier_manifest.json"))
                        if vm.get("id") and vm.get("payload_hash"):
                            member_ids.append((vm["id"], vm["payload_hash"], vm.get("public_key")))
                    except Exception:  # noqa: BLE001 — flagged by check_tools_pin
                        pass
                log_head = _log_pin_check(z, names, trusted, member_ids, failures, notes)
                mfail = _verify_manifest_signature(manifest, issuer, trusted)
                if mfail:
                    failures.append(mfail)
                return {
                    "issuer": issuer,
                    "visits": visits,
                    "attestations": attestations,
                    "kind": "case-pack",
                    "log_head": log_head,
                    "verify_failures": failures,
                    "notes": notes,
                }
            if "bundle.json" in names:
                bundle = transparency.json_loads(z.read("bundle.json"))
                original = bundle.get("original") if isinstance(bundle, dict) else None
                if not isinstance(original, dict) or not original.get("visit_id"):
                    raise ValueError(f"{path}: bundle.json lacks an 'original' receipt")
                issuer = key or original.get("public_key")
                visits[original["visit_id"]] = _visit_summary(bundle)
                kr_pool = []
                kr_member = []
                if "key_rotations.json" in names:
                    from .models import Receipt

                    try:
                        kr = transparency.json_loads(z.read("key_rotations.json"))
                        raw_pool = kr.get("rotations") if isinstance(kr, dict) else None
                        if not isinstance(raw_pool, list):
                            failures.append("key_rotations.json: malformed")
                        else:
                            # Unsigned pool content: malformed members are
                            # inert-skipped — only signed, consented pivots
                            # extend trust (cli/app/embedded/JS parity).
                            for r in raw_pool:
                                try:
                                    kr_member.append(Receipt.model_validate(r))
                                except Exception:  # noqa: BLE001
                                    continue
                            kr_pool = list(kr_member)
                    except Exception as exc:  # noqa: BLE001
                        failures.append(f"key_rotations.json: malformed ({exc})")
                kr_pool += list(extra_key_receipts or [])
                failures += _verify_artifact_bundles(
                    {original["visit_id"]: bundle}, issuer, _trusted_set(issuer, kr_pool)
                )
                from .ledger import revoked_issuer_keys, suspect_receipts

                # Same gate as the manifest branch: no issuer anchor, no
                # revocation authority — pool position never confers it.
                revoked = revoked_issuer_keys(kr_pool, issuer_key=issuer) if issuer else {}
                if revoked:
                    from .models import Receipt as _R

                    try:
                        recs = [_R.model_validate(bundle["original"])] + [
                            _R.model_validate(e["receipt"]) for e in bundle.get("reviews", [])
                        ]
                    except Exception:  # noqa: BLE001 — malformed already flagged
                        recs = []
                    sN = len(suspect_receipts(recs, revoked=revoked))
                    if sN:
                        notes.append(
                            f"{sN} record(s) signed by a revoked issuer inside its "
                            "suspect window — integrity intact, trust qualified"
                        )
                allowed = {
                    "bundle.json",
                    "README.txt",
                    "verify_bundle.py",
                    "verify.html",
                    "index.html",
                    "redaction.json",
                    "key_rotations.json",
                    "verifier_manifest.json",
                    "log_checkpoint.json",
                }
                for name in names:
                    if name.endswith("/") or name in allowed or name.startswith("media/"):
                        continue
                    failures.append(f"{name}: present but not in the signed manifest")
                # Same media-digest rule as the case pack: every media/ member
                # must hash into the signed evidence, every signed digest must
                # resolve to a member or a redaction.json withheld listing.
                _media_members_check(
                    z,
                    names,
                    "media/",
                    original.get("payload") or {},
                    _redaction_withheld(z, "redaction.json", failures),
                    failures,
                )
                _tools_pin_check(
                    z,
                    names,
                    _trusted_set(issuer, kr_pool) or {issuer},
                    f"visit:{original['visit_id']}",
                    failures,
                    notes,
                )
                member_ids = _bundle_receipt_ids(bundle)
                # Only the pack's own key_rotations.json members need proofs —
                # --issuer doc receipts are external pin material, not members.
                member_ids += [(r.id, r.payload_hash, r.public_key) for r in kr_member]
                if "verifier_manifest.json" in names:
                    try:
                        vm = transparency.json_loads(z.read("verifier_manifest.json"))
                        if vm.get("id") and vm.get("payload_hash"):
                            member_ids.append((vm["id"], vm["payload_hash"], vm.get("public_key")))
                    except Exception:  # noqa: BLE001 — flagged by check_tools_pin
                        pass
                log_head = _log_pin_check(
                    z,
                    names,
                    _trusted_set(issuer, kr_pool) or {issuer},
                    member_ids,
                    failures,
                    notes,
                )
                return {
                    "issuer": issuer,
                    "visits": visits,
                    "kind": "pack",
                    "log_head": log_head,
                    "verify_failures": failures,
                    "notes": notes,
                }
            raise ValueError(f"{path}: zip contains neither manifest.json nor bundle.json")
    data = transparency.json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a pack artifact (expected a JSON object)")
    if "original" in data:
        original = data.get("original")
        if not isinstance(original, dict) or not original.get("visit_id"):
            raise ValueError(f"{path}: 'original' receipt missing or malformed")
        issuer = key or original.get("public_key")
        visits[original["visit_id"]] = _visit_summary(data)
        failures += _verify_artifact_bundles(
            {original["visit_id"]: data}, issuer, _trusted_set(issuer, list(extra_key_receipts or []))
        )
        return {
            "issuer": issuer,
            "visits": visits,
            "kind": "bundle",
            "verify_failures": failures,
            "notes": notes,
        }
    if "visits" in data:  # a bare manifest without its bundles
        declared = data.get("issuer_key")
        issuer = key or declared
        bare_pool = list(extra_key_receipts or [])
        bare_trusted = _ancestor_set(declared, bare_pool)
        if not _pin_linked(key, declared, bare_pool):
            failures.append(
                "pinned issuer has no signed lifecycle link to the "
                "manifest's declared issuer — wrong deployment?"
            )
        mfail = _verify_manifest_signature(data, issuer, bare_trusted)
        if mfail:
            failures.append(mfail)
        else:
            failures.append("bare manifest: bundle signatures cannot be checked without the packs")
        seen = set()
        for v in data["visits"]:
            if not isinstance(v, dict) or not v.get("visit_id"):
                failures.append("manifest visit entry malformed")
                continue
            vid = v["visit_id"]
            if vid in seen:
                failures.append(f"{vid}: listed twice in manifest")
                continue
            seen.add(vid)
            visits[vid] = {
                "receipt_id": v.get("receipt_id"),
                "payload_hash": v.get("payload_hash"),
                "state": v.get("state"),
                "review_hashes": [],
                "media_digests": [],
                "manifest_state": v.get("state"),
                "manifest_hash": v.get("payload_hash"),
                "countersign": (v.get("countersign") or {}).get("state"),
            }
        if data.get("signature_receipt") is None:
            notes.append("unsigned manifest — listed states and worker stances are unverified claims")
        return {
            "issuer": issuer,
            "visits": visits,
            "attestations": {a["receipt_id"]: a for a in data.get("attestations", [])},
            "kind": "manifest",
            "verify_failures": failures,
            "notes": notes,
        }
    raise ValueError(f"{path}: unrecognized artifact (no 'original' or 'visits' key)")


def diff(
    old_path: str | Path,
    new_path: str | Path,
    key: str | None = None,
    extra_key_receipts: list | None = None,
) -> tuple[list[str], int]:
    """Return (report lines, anomaly count). Order: old export, newer export.
    `key` pins verification to a trusted issuer public key; `extra_key_receipts`
    extends the lineage (an issuer document's signed lifecycle receipts)."""
    old = load_artifact(old_path, key, extra_key_receipts)
    new = load_artifact(new_path, key, extra_key_receipts)
    events, anomalies = _diff_events(old, new, key, str(old_path), str(new_path))
    return [e["line"] for e in events], anomalies


def diff_report(
    old_path: str | Path,
    new_path: str | Path,
    key: str | None = None,
    extra_key_receipts: list | None = None,
) -> dict:
    """Machine-readable diff — the same events `diff` renders, structured so
    `attest diff --json` can gate CI on append-only drift. Every event carries
    a severity (ok/info/drift/anomaly), the visit or attestation it names, and
    the human detail string."""
    old = load_artifact(old_path, key, extra_key_receipts)
    new = load_artifact(new_path, key, extra_key_receipts)
    events, anomalies = _diff_events(old, new, key, str(old_path), str(new_path))

    def side(art):
        fails = art.get("verify_failures")
        return {
            "kind": art["kind"],
            "issuer": art.get("issuer"),
            "verify_failures": fails,
            "notes": art.get("notes") or [],
            "verified": fails == [],
        }

    return {
        "old": {"path": str(old_path), **side(old)},
        "new": {"path": str(new_path), **side(new)},
        "events": [
            {k: e[k] for k in ("severity", "target", "detail", "line") if e.get(k) is not None}
            for e in events
        ],
        "anomalies": anomalies,
        "clean": anomalies == 0,
    }


_SEV_CLASS = {"ok": "ok", "info": "info", "drift": "drift", "anomaly": "bad"}
_SEV_LABEL = {"ok": "ok", "info": "new", "drift": "drift", "anomaly": "anomaly"}


def _side_card(side: dict, label: str) -> str:
    import html as h

    name = h.escape(side.get("path") or label)
    kind = h.escape(side.get("kind") or "?")
    issuer = side.get("issuer")
    issuer_txt = (
        f'issuer <code title="{h.escape(issuer)}">{h.escape(issuer[:18])}…</code>'
        if isinstance(issuer, str)
        else "issuer unknown"
    )
    fails = side.get("verify_failures")
    if fails == []:
        verdict = '<span class="chip ok">VERIFIED</span> all signed contents verify'
    elif fails is None:
        verdict = '<span class="chip drift">UNVERIFIED</span> no verification ran'
    else:
        n = len(fails)
        verdict = f'<span class="chip bad">FAILED</span> {n} verification failure(s)'
    return (
        f'<div class="side"><div class="path">{name}</div>'
        f'<div class="meta">{kind} · {issuer_txt}</div>'
        f'<div class="meta">{verdict}</div></div>'
    )


def diff_html(report: dict) -> str:
    """Render a `diff_report` dict as a self-contained HTML page — the
    attachable rendering of `attest diff` (a coordinator hands a mediator a
    page, not a JSON dump). Everything on the page is re-derivable:
    `attest diff A B --json` emits the same events the table shows. The page
    itself is unsigned — the packs are the evidence; this is a reading."""
    import html as h

    esc = h.escape
    anomalies = report.get("anomalies") or 0
    events = report.get("events") or []
    # Per-side rows (target "old"/"new") are each pack's self-reported notes,
    # not pack-vs-pack movement — only events naming a member or the log head
    # mean the two exports actually differ.
    cross = [
        e
        for e in events
        if e.get("severity") in ("drift", "anomaly") and e.get("target") not in ("old", "new")
    ]
    appended = [
        e
        for e in events
        if e.get("severity") == "info" and e.get("target") not in (None, "old", "new", "log_checkpoint.json")
    ]
    heads_open = any(e.get("severity") == "info" and e.get("target") == "log_checkpoint.json" for e in events)

    if anomalies:
        stamp = f'<div class="stamp bad">ANOMALIES DETECTED — {anomalies}</div>'
        stamp_sub = (
            "Vanished or altered signed records — one export is inauthentic, "
            "or a record was edited after signing."
        )
    elif cross or appended:
        stamp = '<div class="stamp drift">APPEND-ONLY DRIFT — 0 anomalies</div>'
        stamp_sub = (
            "New signed records appeared (normal export growth); nothing vanished and nothing was altered."
            + (
                " The signed log heads could not be reconciled offline — `attest consistency` decides."
                if heads_open
                else ""
            )
        )
    elif heads_open:
        stamp = '<div class="stamp drift">LOG HEADS UNRECONCILED — no record differences found</div>'
        stamp_sub = (
            "Both exports carry the same signed membership, but their transparency-log "
            "heads can't be bridged offline — `attest consistency` against the live "
            "deployment decides whether one history diverged."
        )
    else:
        stamp = '<div class="stamp ok">NO SIGNED DIFFERENCES</div>'
        stamp_sub = "Both exports verify and carry the same signed contents."

    rows = []
    for e in events:
        sev = e.get("severity") or "info"
        cls = _SEV_CLASS.get(sev, "info")
        target = e.get("target")
        lab = "compare" if target is None and sev == "info" else _SEV_LABEL.get(sev, sev)
        target_html = f"<code>{esc(str(target))}</code>" if target else "—"
        detail = esc(e.get("detail") or "")
        chip = f'<span class="chip {cls}">{esc(str(lab))}</span>'
        rows.append(f"<tr><td>{chip}</td><td>{target_html}</td><td>{detail}</td></tr>")

    pin = report.get("pin") or {}
    pin_line = ""
    if pin.get("issuer_key"):
        src = pin.get("issuer_url") or "a trusted --key"
        pin_line = (
            f'<p class="small">Trust anchor pinned to '
            f"<code>{esc(str(pin['issuer_key'])[:24])}…</code> via "
            f"{esc(str(src))}.</p>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Append-only export diff · Attest</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:64em;margin:0 auto;
padding:1.4rem 1.2rem;color:#1c1c1e;line-height:1.5}}
h1{{font-size:1.35rem;margin-bottom:.1rem}}
code{{background:#f4f4f5;padding:.08rem .35rem;border-radius:4px;
font-size:.85em;word-break:break-all}}
.sides{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}
.side{{flex:1;min-width:16em;border:1px solid #e4e4e7;border-radius:8px;
padding:.7rem .9rem}}
.path{{font-family:ui-monospace,monospace;font-size:.85rem;font-weight:600;
word-break:break-all}}
.meta{{font-size:.8rem;color:#52525b;margin-top:.3rem}}
.stamp{{font-weight:700;font-size:1.05rem;padding:.8rem 1.1rem;
border-radius:10px;margin:.9rem 0 .3rem}}
.stamp.ok{{background:#f0fdf4;border:1px solid #86efac;color:#166534}}
.stamp.drift{{background:#fffbeb;border:1px solid #fde68a;color:#92400e}}
.stamp.bad{{background:#fef2f2;border:1px solid #fecaca;color:#991b1b}}
table{{border-collapse:collapse;width:100%;font-size:.86rem;margin-top:1rem}}
th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #e4e4e7;
vertical-align:top}}
.chip{{display:inline-block;font-size:.72rem;font-weight:700;
letter-spacing:.03em;border-radius:5px;padding:.1rem .45rem}}
.chip.ok{{background:#dcfce7;color:#166534}}
.chip.info{{background:#dbeafe;color:#1d4ed8}}
.chip.drift{{background:#fef3c7;color:#92400e}}
.chip.bad{{background:#fee2e2;color:#991b1b}}
.small{{color:#6b6b70;font-size:.8rem}}
footer{{margin-top:2rem;padding-top:.8rem;border-top:1px solid #e4e4e7;
color:#6b6b70;font-size:.78rem}}
</style>
</head>
<body>
<main>
<h1>Append-only export diff</h1>
<p class="small">Two signed evidence exports compared member-by-member.
Appended records are normal; a vanished or altered one is an anomaly —
records are append-only.</p>
<div class="sides">
{_side_card(report.get("old") or {}, "old export")}
{_side_card(report.get("new") or {}, "new export")}
</div>
{pin_line}
{stamp}
<p class="small">{stamp_sub}</p>
<table>
<thead><tr><th>verdict</th><th>member</th><th>what the diff found</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
<footer>Generated by <code>attest diff --html</code>. This page is a readable
rendering, not a signed artifact — re-derive the same events any time with
<code>attest diff &lt;old&gt; &lt;new&gt; --json</code> (exit 1 on anomaly),
or verify each export on its own merits with <code>attest verify</code> or
the bundled <code>verify.html</code>. "Both verify" and "identical" are
different claims; this page separates them.</footer>
</main>
</body>
</html>
"""


def _walk_chain(hi: dict, lo_size: int, lo_root: bytes) -> tuple[str, int] | None:
    """Walk the newer side's embedded checkpoint chain hop-by-hop toward the
    older head. Each hop re-verifies the signed `extends` bridge inside the
    CURRENT head's payload against the signed chain member it names — a hop
    that lands exactly on `lo` proves append-only across arbitrarily many
    intervening checkpoints with no network at all.

    Returns ("extends", hops) when the walk lands on the older head,
    ("fork", hops) when it collides — a signed member occupies the target
    size under a different root, or a head's own signed bridge fails against
    the member it names — and None when the chain simply cannot reach the
    older head (a gap, a missing bridge, or no chain at all)."""
    from .transparency import hex_bytes, verify_extends

    by_size = {m["size"]: m for m in hi.get("chain") or []}
    # A chain member occupying the OLDER head's exact size under a different
    # root is already the collision — two issuer-signed heads at one tree
    # size, no bridging walk needed.
    probe = by_size.get(lo_size)
    if probe is not None:
        try:
            if hex_bytes(probe["root"], length=32) != lo_root:
                return "fork", 0
        except (KeyError, TypeError, ValueError):
            return None
    cur = hi["head"]
    hops = 0
    while hops <= len(by_size):
        ext = cur.get("extends") if isinstance(cur, dict) else None
        first = ext.get("first") if isinstance(ext, dict) else None
        if not isinstance(first, int) or isinstance(first, bool):
            return None  # no usable bridge — cannot descend further
        if first == lo_size:
            r = verify_extends(cur, first=lo_size, first_root=lo_root)
            if r is True:
                return "extends", hops + 1
            if r is False:
                # The signed bridge names the older head's SIZE but not its
                # ROOT — the issuer's own proof material contradicts it.
                return "fork", hops + 1
            return None
        m = by_size.get(first)
        if m is None:
            return None  # chain gap — the head bridges somewhere we can't see
        try:
            mroot = hex_bytes(m["root"], length=32)
        except (KeyError, TypeError, ValueError):
            return None
        r = verify_extends(cur, first=m["size"], first_root=mroot)
        if r is True:
            cur, hops = m["payload"], hops + 1
            continue
        if r is False:
            # cur's signed bridge names a member at `first` whose signed root
            # differs from what the bridge attests — a same-size collision.
            return "fork", hops + 1
        return None
    return None


def _log_head_verdict(a: dict, b: dict) -> tuple[str, str] | None:
    """Compare two VALIDATED log heads — ``{head, chain}`` per pack, the
    signed tree heads two exports committed to plus the signed prior-head
    chain each embeds. Returns (severity, line) or None when a head is too
    malformed to judge (the pack verify loop already flags malformed
    checkpoints; this only sees ones that parsed)."""
    ah, bh = a.get("head") or {}, b.get("head") or {}
    try:
        from .transparency import hex_bytes

        sa, sb = int(ah["tree_size"]), int(bh["tree_size"])
        ra, rb = hex_bytes(ah["root_sha256"], length=32), hex_bytes(bh["root_sha256"], length=32)
    except (KeyError, TypeError, ValueError):
        return None
    if sa == sb:
        if ra == rb:
            return "ok", f"both exports commit to the same signed log head (tree size {sa})"
        return (
            "anomaly",
            f"both exports carry size-{sa} log heads with DIFFERENT roots — "
            "the issuer signed two histories at one tree size: a provable fork",
        )
    # Direction matters: the LARGER head walked back to the smaller proves
    # append-only growth — a single embedded bridge for adjacent heads, or
    # the multi-hop signed chain the export carries for non-adjacent ones.
    # A reached member at the target size under a DIFFERENT root upgrades
    # 'undecidable' to a provable fork collision.
    from .transparency import verify_extends

    if sb > sa:
        hi, lo_size, lo_root, lo_tag, hi_tag = b, sa, ra, "old", "new"
    else:
        hi, lo_size, lo_root, lo_tag, hi_tag = a, sb, rb, "new", "old"
    hi_head = hi["head"]
    # Fork probe, consulted before any bridge: a signed chain member at the
    # smaller head's exact size under a DIFFERENT root is two issuer-signed
    # heads at one tree size — evidence that stands even when the bridge
    # itself verifies (the pack carries a head contradicting its own
    # attested ancestry).
    probe = next((m for m in hi.get("chain") or [] if m["size"] == lo_size), None)
    if probe is not None:
        try:
            if hex_bytes(probe["root"], length=32) != lo_root:
                return (
                    "anomaly",
                    f"the {hi_tag} export's embedded chain carries a signed head at "
                    f"size {lo_size} whose root differs from the {lo_tag} export's — "
                    "two issuer-signed heads at one tree size: a provable fork",
                )
        except (KeyError, TypeError, ValueError):
            pass
    bridged = verify_extends(hi_head, first=lo_size, first_root=lo_root)
    if bridged is True:
        if sb > sa:
            return (
                "ok",
                f"the size-{sb} head provably extends the size-{sa} head "
                "via the larger checkpoint's own signed bridge — the log only "
                "appended between these exports",
            )
        return (
            "drift",
            f"the newer export pins an EARLIER signed head (size {sb} < {sa}) — "
            "the old head provably extends it: either this pack was exported "
            "before the old one, or the deployment served a regressed head "
            "(a rollback is indistinguishable from an older export offline)",
        )
    if bridged is False:
        return (
            "anomaly",
            f"the {hi_tag} export's size-{max(sa, sb)} checkpoint signs a bridge "
            f"naming the {lo_tag} head's size but not its root — the issuer's "
            "own proof material contradicts the pack: fork evidence",
        )
    # No direct bridge — walk the embedded signed chain hop-by-hop.
    walked = _walk_chain(hi, lo_size, lo_root)
    if walked is not None:
        outcome, hops = walked
        if outcome == "extends":
            if sb > sa:
                return (
                    "ok",
                    f"the size-{sb} head provably extends the size-{sa} head — "
                    f"{hops} signed checkpoint hop(s) verified inside the "
                    "newer pack's embedded chain, no network needed",
                )
            return (
                "drift",
                f"the {hi_tag} export's size-{sa} head provably extends the "
                f"{lo_tag} export's size-{sb} head over {hops} signed "
                "checkpoint hop(s) — the 'newer' pack is a verified EARLIER "
                "snapshot of the same log: exported before, or a regressed "
                "head honestly identified (a rollback stays indistinguishable "
                "from an older export offline)",
            )
        return (
            "anomaly",
            f"the embedded signed chain COLLIDES with the {lo_tag} export's "
            f"size-{lo_size} head after {hops} verified hop(s) — two signed "
            "heads claim different roots at one tree size: a provable fork",
        )
    if sb > sa:
        return (
            "info",
            f"export log heads differ (size {sa} vs {sb}) with no embedded "
            "bridge or chain reaching between them — `attest consistency` "
            "against the live deployment decides",
        )
    return (
        "drift",
        f"the newer export pins an earlier signed head (size {sb} < {sa}) with "
        "no bridge or chain reaching back — an older export or a regression, "
        "undecidable offline",
    )


def _diff_events(old: dict, new: dict, key: str | None, old_path: str, new_path: str):
    """The single comparison core — text output and the JSON report are built
    from the same event stream so the two can never disagree."""
    import re

    events: list[dict] = []
    anomalies = 0

    def ev(severity: str, target: str | None, detail: str, marker: str | None = None) -> None:
        # Pack-controlled strings (visit ids, member names, failure text) land in
        # detail — strip control bytes so a hostile name can't forge terminal
        # lines or inject ANSI into text output. JSON/HTML renderings escape
        # independently; this keeps all three views consistent.
        detail = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "�", str(detail))
        if isinstance(target, str):
            target = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "�", target)
        events.append(
            {
                "severity": severity,
                "target": target,
                "detail": detail,
                "line": f"{marker}{detail}" if marker else detail,
            }
        )

    ev("info", None, f"{old_path} [{old['kind']}] -> {new_path} [{new['kind']}]")
    try:
        if Path(old_path).read_bytes() == Path(new_path).read_bytes():
            ev("ok", None, "identical bytes — the two inputs are the same archive")
    except OSError:
        pass

    for label, art in (("old", old), ("new", new)):
        for fail in art.get("verify_failures") or []:
            ev("anomaly", label, f"{label} artifact fails verification: {fail}", "!! ")
            anomalies += 1
        for note in art.get("notes") or []:
            ev("drift", label, f"{label} artifact: {note}", "~  ")
        if art.get("verify_failures") is not None and not art.get("verify_failures"):
            issuer_note = (
                f"issuer {art['issuer'][:20]}… (self-declared)" if art.get("issuer") else "no issuer"
            )
            if key:
                issuer_note = f"pinned issuer {key[:20]}…"
            ev("ok", label, f"{label} artifact: all signed contents verify under the {issuer_note}", "ok ")

    if old["issuer"] and new["issuer"] and old["issuer"] != new["issuer"]:
        ev(
            "anomaly",
            None,
            "issuer key differs between exports — one was not signed by this deployment",
            "!! ",
        )
        anomalies += 1

    # Two exports = two snapshots of the same transparency log, each
    # carrying a signed tree head and the signed prior-head chain its
    # export embedded. Same head is agreement; adjacent checkpoints bridge
    # via the embedded extends proof; non-adjacent heads reconcile by
    # walking the signed chain hop-by-hop (append-only between exports,
    # verified offline either way); a signed chain member colliding at the
    # other head's size under a different root is a PROVEN fork.
    oh, nh = old.get("log_head"), new.get("log_head")
    if oh is not None and nh is not None:
        verdict = _log_head_verdict(oh, nh)
        if verdict:
            severity, detail = verdict
            ev(
                severity,
                "log_checkpoint.json",
                detail,
                {"ok": "ok ", "info": "+  ", "anomaly": "!! ", "drift": "~  "}[severity],
            )
            if severity == "anomaly":
                anomalies += 1
    elif oh is not None or nh is not None:
        ev(
            "drift",
            "log_checkpoint.json",
            f"only the {'old' if oh is not None else 'new'} export carries a transparency "
            "checkpoint — the append-only postures can't be compared",
            "~  ",
        )

    for vid in sorted(set(old["visits"]) | set(new["visits"])):
        a, b = old["visits"].get(vid), new["visits"].get(vid)
        if a is None:
            ev("info", vid, f"{vid}: new visit ({b['state']})", "+  ")
            continue
        if b is None:
            ev(
                "anomaly",
                vid,
                f"{vid}: record present before, absent now — records are append-only",
                "!! ",
            )
            anomalies += 1
            continue
        if a["payload_hash"] != b["payload_hash"]:
            detail = (
                f"{vid}: signed original changed ({a['payload_hash'][:12]} -> "
                f"{b['payload_hash'][:12]}) — a signed record cannot change; one export is inauthentic"
            )
            # Name the altered fields — detection becomes diagnosis. The
            # fields' direction is honest: we can say what moved between the
            # two copies, never which copy is true.
            ap, bp = a.get("original_payload") or {}, b.get("original_payload") or {}
            moved = [k for k in set(ap) | set(bp) if ap.get(k) != bp.get(k)]
            if moved:
                detail += f" — changed field(s): {', '.join(sorted(moved))}"
            ev("anomaly", vid, detail, "!! ")
            anomalies += 1
            continue
        if a.get("original_payload") != b.get("original_payload"):
            # Same signed envelope, different signed-content bytes: the
            # payload_hash field no longer binds (verification already
            # flagged it). Name what moved — detection becomes diagnosis.
            ap, bp = a.get("original_payload") or {}, b.get("original_payload") or {}
            moved = [k for k in set(ap) | set(bp) if ap.get(k) != bp.get(k)]
            detail = (
                f"{vid}: signed payload content differs under an identical "
                "envelope — one export's bytes were rewritten after signing"
            )
            if moved:
                detail += f" — changed field(s): {', '.join(sorted(moved))}"
            ev("anomaly", vid, detail, "!! ")
            anomalies += 1
            continue
        added = [h for h in b["review_hashes"] if h not in a["review_hashes"]]
        removed = [h for h in a["review_hashes"] if h not in b["review_hashes"]]
        if removed:
            ev(
                "anomaly",
                vid,
                f"{vid}: {len(removed)} review receipt(s) vanished — reviews are append-only",
                "!! ",
            )
            anomalies += 1
        if added:
            ev("drift", vid, f"{vid}: +{len(added)} appended review receipt(s)", "~  ")
        ac, bc = a.get("countersign"), b.get("countersign")
        if ac and bc and ac != bc:
            ev("drift", vid, f"{vid}: worker stance {ac} -> {bc}", "~  ")
        if a["media_digests"] != b["media_digests"]:
            ev(
                "anomaly",
                vid,
                f"{vid}: media digest set changed — evidence cannot change post-signature",
                "!! ",
            )
            anomalies += 1

    # Site attestations (coverage certs, digests, prior exports, disconnects)
    # are chain events too — new ones are drift, vanished or altered ones are
    # anomalies on the same append-only argument as visits.
    old_att = old.get("attestations") or {}
    new_att = new.get("attestations") or {}
    for rid in sorted(set(old_att) | set(new_att)):
        a, b = old_att.get(rid), new_att.get(rid)
        if a is None:
            ev(
                "info",
                rid,
                f"attestation {b['record_type'] or 'record'} ({rid[:20]}…): new site event",
                "+  ",
            )
            continue
        if b is None:
            ev(
                "anomaly",
                rid,
                f"attestation {rid}: present before, absent now — receipts are append-only",
                "!! ",
            )
            anomalies += 1
            continue
        if a["payload_hash"] != b["payload_hash"]:
            ev(
                "anomaly",
                rid,
                f"attestation {rid}: signed payload changed — one export is inauthentic",
                "!! ",
            )
            anomalies += 1
    if not anomalies:
        ev("ok", None, "clean: all changes are append-only")
    return events, anomalies
