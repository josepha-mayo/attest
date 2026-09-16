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


def load_artifact(path: str | Path) -> dict:
    """Load a case pack, dispute pack, or bare bundle.json into a normalized map."""
    path = Path(path)
    visits: dict[str, dict] = {}
    issuer = None
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            if "manifest.json" in names:
                manifest = json.loads(z.read("manifest.json"))
                issuer = manifest.get("issuer_key")
                entries = {v["visit_id"]: v for v in manifest.get("visits", [])}
                for vid in entries:
                    try:
                        bundle = json.loads(z.read(f"visits/{vid}/bundle.json"))
                    except KeyError:
                        continue
                    visits[vid] = _visit_summary(bundle, entries[vid])
                return {"issuer": issuer, "visits": visits, "kind": "case-pack"}
            if "bundle.json" in names:
                bundle = json.loads(z.read("bundle.json"))
                issuer = bundle["original"]["public_key"]
                visits[bundle["original"]["visit_id"]] = _visit_summary(bundle)
                return {"issuer": issuer, "visits": visits, "kind": "pack"}
            raise ValueError(f"{path}: zip contains neither manifest.json nor bundle.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    if "original" in data:
        issuer = data["original"]["public_key"]
        visits[data["original"]["visit_id"]] = _visit_summary(data)
        return {"issuer": issuer, "visits": visits, "kind": "bundle"}
    if "visits" in data:  # a bare manifest without its bundles
        issuer = data.get("issuer_key")
        for v in data["visits"]:
            visits[v["visit_id"]] = {
                "receipt_id": v.get("receipt_id"),
                "payload_hash": v.get("payload_hash"),
                "state": v.get("state"),
                "review_hashes": [],
                "media_digests": [],
                "manifest_state": v.get("state"),
                "manifest_hash": v.get("payload_hash"),
                "countersign": (v.get("countersign") or {}).get("state"),
            }
        return {"issuer": issuer, "visits": visits, "kind": "manifest"}
    raise ValueError(f"{path}: unrecognized artifact (no 'original' or 'visits' key)")


def diff(old_path: str | Path, new_path: str | Path) -> tuple[list[str], int]:
    """Return (report lines, anomaly count). Order: old export, newer export."""
    old, new = load_artifact(old_path), load_artifact(new_path)
    lines = [f"{old_path} [{old['kind']}] -> {new_path} [{new['kind']}]"]
    anomalies = 0

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
    if not anomalies:
        lines.append("clean: all changes are append-only")
    return lines, anomalies
