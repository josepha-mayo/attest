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


def _verify_artifact_bundles(visits_bundles: dict, issuer: str | None) -> list[str]:
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


def _verify_attestation_files(z, attestations: dict, issuer: str | None) -> list[str]:
    """Verify each attestation receipt file the manifest lists — signature AND
    the manifest's claimed visit_id/payload_hash, so a swapped (but validly
    signed) receipt file cannot pass as the listed attestation."""
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
        ok, why = verify_receipt(att, public_key=issuer or att.public_key)
        if not ok:
            failures.append(f"attestation {rid}: {why}")
    return failures


def _verify_manifest_signature(manifest: dict, issuer: str | None) -> str | None:
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
    ok, why = verify_receipt(receipt, public_key=issuer or receipt.public_key)
    if not ok:
        return f"manifest signature: {why}"
    core = {k: v for k, v in manifest.items() if k != "signature_receipt"}
    if payload_hash(core) != sig["payload"].get("manifest_sha256"):
        return "manifest content hash mismatch (manifest was altered)"
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


def load_artifact(path: str | Path, key: str | None = None) -> dict:
    """Load a case pack, dispute pack, or bare bundle.json into a normalized map.
    Each artifact's signed contents are independently verified — a diff over
    unverified receipts would silently compare forged data. A pinned `key`
    makes verification trust only that issuer."""
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
                issuer = key or manifest.get("issuer_key")
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
                failures += _verify_artifact_bundles(bundles, issuer)
                failures += _verify_attestation_files(z, attestations, issuer)
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
                mfail = _verify_manifest_signature(manifest, issuer)
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
                failures += _verify_artifact_bundles({original["visit_id"]: bundle}, issuer)
                allowed = {
                    "bundle.json",
                    "README.txt",
                    "verify_bundle.py",
                    "verify.html",
                    "index.html",
                    "redaction.json",
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
        failures += _verify_artifact_bundles({original["visit_id"]: data}, issuer)
        return {
            "issuer": issuer,
            "visits": visits,
            "kind": "bundle",
            "verify_failures": failures,
            "notes": notes,
        }
    if "visits" in data:  # a bare manifest without its bundles
        issuer = key or data.get("issuer_key")
        mfail = _verify_manifest_signature(data, issuer)
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


def diff(old_path: str | Path, new_path: str | Path, key: str | None = None) -> tuple[list[str], int]:
    """Return (report lines, anomaly count). Order: old export, newer export.
    `key` pins verification to a trusted issuer public key."""
    old, new = load_artifact(old_path, key), load_artifact(new_path, key)
    lines = [f"{old_path} [{old['kind']}] -> {new_path} [{new['kind']}]"]
    anomalies = 0

    for label, art in (("old", old), ("new", new)):
        for fail in art.get("verify_failures") or []:
            lines.append(f"!! {label} artifact fails verification: {fail}")
            anomalies += 1
        for note in art.get("notes") or []:
            lines.append(f"~  {label} artifact: {note}")
        if art.get("verify_failures") is not None and not art.get("verify_failures"):
            issuer_note = (
                f"issuer {art['issuer'][:20]}… (self-declared)" if art.get("issuer") else "no issuer"
            )
            if key:
                issuer_note = f"pinned issuer {key[:20]}…"
            lines.append(f"ok {label} artifact: all signed contents verify under the {issuer_note}")

    if old["issuer"] and new["issuer"] and old["issuer"] != new["issuer"]:
        lines.append("!! issuer key differs between exports — one was not signed by this deployment")
        anomalies += 1

    for vid in sorted(set(old["visits"]) | set(new["visits"])):
        a, b = old["visits"].get(vid), new["visits"].get(vid)
        if a is None:
            lines.append(f"+  {vid}: new visit ({b['state']})")
            continue
        if b is None:
            lines.append(f"!! {vid}: record present before, absent now — records are append-only")
            anomalies += 1
            continue
        if a["payload_hash"] != b["payload_hash"]:
            lines.append(
                f"!! {vid}: signed original changed ({a['payload_hash'][:12]} -> "
                f"{b['payload_hash'][:12]}) — a signed record cannot change; one export is inauthentic"
            )
            anomalies += 1
            continue
        added = [h for h in b["review_hashes"] if h not in a["review_hashes"]]
        removed = [h for h in a["review_hashes"] if h not in b["review_hashes"]]
        if removed:
            lines.append(f"!! {vid}: {len(removed)} review receipt(s) vanished — reviews are append-only")
            anomalies += 1
        if added:
            lines.append(f"~  {vid}: +{len(added)} appended review receipt(s)")
        ac, bc = a.get("countersign"), b.get("countersign")
        if ac and bc and ac != bc:
            lines.append(f"~  {vid}: worker stance {ac} -> {bc}")
        if a["media_digests"] != b["media_digests"]:
            lines.append(f"!! {vid}: media digest set changed — evidence cannot change post-signature")
            anomalies += 1

    # Site attestations (coverage certs, digests, prior exports, disconnects)
    # are chain events too — new ones are drift, vanished or altered ones are
    # anomalies on the same append-only argument as visits.
    old_att = old.get("attestations") or {}
    new_att = new.get("attestations") or {}
    for rid in sorted(set(old_att) | set(new_att)):
        a, b = old_att.get(rid), new_att.get(rid)
        if a is None:
            lines.append(f"+  attestation {b['record_type'] or 'record'} ({rid[:20]}…): new site event")
            continue
        if b is None:
            lines.append(f"!! attestation {rid}: present before, absent now — receipts are append-only")
            anomalies += 1
            continue
        if a["payload_hash"] != b["payload_hash"]:
            lines.append(f"!! attestation {rid}: signed payload changed — one export is inauthentic")
            anomalies += 1
    if not anomalies:
        lines.append("clean: all changes are append-only")
    return lines, anomalies
