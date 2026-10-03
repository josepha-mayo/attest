"""Compare two exported artifacts — case packs, dispute packs, or bare
bundle.json files — and report what changed between them.

Legitimate drift is append-only: new visits, new review receipts. Anything else
(a record vanishing, a signed payload changing under the same id, a receipt
hash disagreeing) is an anomaly worth stopping for, because none of it should
be possible on an honest deployment.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path


class BoundedZip:
    """z.read wrapper enforcing per-file and cumulative decompressed caps —
    central-directory file_size entries can lie, so reads are capped on the
    actual inflated stream."""

    def __init__(self, z, *, per_file: int = 64 * 1024 * 1024, total: int = 256 * 1024 * 1024):
        self._z, self.per_file, self.total, self.seen = z, per_file, total, 0

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


def _key_pool(z, attestations: dict) -> list:
    """The pack's signed key-rotation link receipts (rotations AND adoptions),
    read from its attestation files — a pack written across a key rotation
    legitimately mixes issuer keys, and the trust set derives from these."""
    from .models import Receipt

    pool = []
    for rid in attestations:
        try:
            att = Receipt.model_validate(json.loads(z.read(f"attestations/{rid}.json")))
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
            att = Receipt.model_validate(json.loads(z.read(f"attestations/{rid}.json")))
        except Exception as exc:  # noqa: BLE001
            failures.append(f"attestation {rid}: missing or invalid ({exc})")
            continue
        if att.id != rid:
            failures.append(f"attestation {rid}: file contains receipt {att.id}")
            continue
        if entry.get("payload_hash") and entry["payload_hash"] != att.payload_hash:
            failures.append(f"attestation {rid}: payload hash differs from manifest entry")
            continue
        if entry.get("visit_id") and entry["visit_id"] != att.visit_id:
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
    signed_hashes = sig["payload"].get("receipt_hashes")
    if signed_hashes is not None:
        # Guard like _manifest_consistency: a malformed visit entry must fail
        # the comparison, never raise out of the verifier on a signed export.
        listed = {
            v["visit_id"]: v["payload_hash"]
            for v in manifest.get("visits", [])
            if isinstance(v, dict) and "visit_id" in v and "payload_hash" in v
        }
        if listed != signed_hashes:
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
        if bundle and claimed and claimed != bundle["original"]["payload_hash"]:
            actual = bundle["original"]["payload_hash"]
            failures.append(f"{vid}: manifest claims {claimed[:12]}… but bundle hashes {actual[:12]}…")
    if manifest.get("signature_receipt") is None:
        notes.append("unsigned manifest — listed states and worker stances are unverified claims")
    return failures


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
            z = BoundedZip(raw)
            names = set(z.namelist())
            if "manifest.json" in names:
                manifest = json.loads(z.read("manifest.json"))
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
                        bundles[vid] = json.loads(z.read(f"visits/{vid}/bundle.json"))
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
                from .ledger import revoked_issuer_keys, suspect_receipts
                from .models import Receipt as _R

                revoked = revoked_issuer_keys(pool, issuer_key=issuer)
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
                        continue  # media members — digest-checked upstream
                    failures.append(f"{name}: present but not in the signed manifest")
                mfail = _verify_manifest_signature(manifest, issuer, trusted)
                if mfail:
                    failures.append(mfail)
                return {
                    "issuer": issuer,
                    "visits": visits,
                    "attestations": attestations,
                    "kind": "case-pack",
                    "verify_failures": failures,
                    "notes": notes,
                }
            if "bundle.json" in names:
                bundle = json.loads(z.read("bundle.json"))
                original = bundle.get("original") if isinstance(bundle, dict) else None
                if not isinstance(original, dict) or not original.get("visit_id"):
                    raise ValueError(f"{path}: bundle.json lacks an 'original' receipt")
                issuer = key or original.get("public_key")
                visits[original["visit_id"]] = _visit_summary(bundle)
                kr_pool = []
                if "key_rotations.json" in names:
                    from .models import Receipt

                    try:
                        kr = json.loads(z.read("key_rotations.json"))
                        kr_pool = [Receipt.model_validate(r) for r in kr.get("rotations") or []]
                    except Exception as exc:  # noqa: BLE001
                        failures.append(f"key_rotations.json: malformed ({exc})")
                kr_pool += list(extra_key_receipts or [])
                failures += _verify_artifact_bundles(
                    {original["visit_id"]: bundle}, issuer, _trusted_set(issuer, kr_pool)
                )
                from .ledger import revoked_issuer_keys, suspect_receipts

                revoked = revoked_issuer_keys(kr_pool, issuer_key=issuer)
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
                }
                for name in names:
                    if name.endswith("/") or name in allowed or name.startswith("media/"):
                        continue
                    failures.append(f"{name}: present but not in the signed manifest")
                return {
                    "issuer": issuer,
                    "visits": visits,
                    "kind": "pack",
                    "verify_failures": failures,
                    "notes": notes,
                }
            raise ValueError(f"{path}: zip contains neither manifest.json nor bundle.json")
    data = json.loads(path.read_text(encoding="utf-8"))
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
    side = lambda art: {  # noqa: E731
        "kind": art["kind"],
        "issuer": art.get("issuer"),
        "verify_failures": art.get("verify_failures") or [],
        "notes": art.get("notes") or [],
        "verified": art.get("verify_failures") == [],
    }
    return {
        "old": {"path": str(old_path), **side(old)},
        "new": {"path": str(new_path), **side(new)},
        "events": [
            {k: e[k] for k in ("severity", "target", "detail") if e.get(k) is not None} for e in events
        ],
        "anomalies": anomalies,
        "clean": anomalies == 0,
    }


def _diff_events(old: dict, new: dict, key: str | None, old_path: str, new_path: str):
    """The single comparison core — text output and the JSON report are built
    from the same event stream so the two can never disagree."""
    events: list[dict] = []
    anomalies = 0

    def ev(severity: str, target: str | None, detail: str, marker: str | None = None) -> None:
        events.append(
            {
                "severity": severity,
                "target": target,
                "detail": detail,
                "line": f"{marker}{detail}" if marker else detail,
            }
        )

    ev("info", None, f"{old_path} [{old['kind']}] -> {new_path} [{new['kind']}]")

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
            ev(
                "anomaly",
                vid,
                f"{vid}: signed original changed ({a['payload_hash'][:12]} -> "
                f"{b['payload_hash'][:12]}) — a signed record cannot change; one export is inauthentic",
                "!! ",
            )
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
