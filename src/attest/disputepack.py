"""Dispute pack: a single portable artifact for third-party review.

One zip containing the signed bundle, the media bytes referenced by evidence,
a plain-language README of exactly what the record does and does not establish,
and ``verify_bundle.py`` — a *zero-dependency* verifier implementing RFC 8032
Ed25519 verification with the standard library alone. Anyone can check the pack
on any machine with plain Python; no attest install, no pip, no trust in us.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from .models import ReviewBundle, Site, Visit
from .store import Store

_README = """\
ATTEST DISPUTE PACK — what this is and is not
============================================

bundle.json    The signed visit record plus every appended review, hash-chained.
media/         The media bytes the record references (when included).
verify_bundle.py  Offline verifier. Run:  python verify_bundle.py bundle.json
verify.html    Zero-install verifier — open in any browser and drop the pack
               files in. Same checks, pure JavaScript, works from file://.
               Also renders each record's timeline (scheduled window, poll
               coverage, observations) from the signed payload.

WHAT A VALID VERIFICATION PROVES
- Every receipt in bundle.json is byte-identical to what was signed: the payload
  hashes to payload_hash, and the Ed25519 signature covers that hash.
- Reviews are anchored to the original receipt's hash and ordered by revision.
- Media files match the sha256 digests recorded in the evidence list (when the
  verifier is run from this directory, it checks media/ too).

WHAT IT DOES NOT PROVE
- Identity. The signature authenticates the record, not who appears in media.
- Attendance or time worked. Observations are events, not presence.
- Absence. A silent window means no events were observed — not that nobody came.
- The worker's device or person. Worker statements arrive through a scoped link;
  they are the worker's account, recorded, not a verified identity.

The private signing key stays with the deployment. The public key embedded in
each receipt verifies this pack; pin against a key you obtained out-of-band
(verify_bundle.py --key <base64>) to rule out a pack that swapped keys.
"""

# stdlib-only RFC 8032 verifier library, generated into every pack. Kept in sync
# with ledger.py's canonicalization (json sort_keys, compact separators) and
# receipt checks (payload hash, envelope agreement, Ed25519 signature, chain links).
_VERIFIER_LIB = '''\
#!/usr/bin/env python3
"""Verify Attest records offline. Stdlib only — no pip, no attest install.

Checks: payload sha256, envelope/payload agreement, Ed25519 signatures,
revision ordering, and anchoring to the original receipt. Media digests are
checked against files inside the pack.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

# --- Ed25519 verification (RFC 8032), pure Python ---------------------------
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, q - 2, q)) % q
I = pow(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, q - 2, q)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = x * I % q
    return x if x % 2 == 0 else q - x


By = 4 * pow(5, q - 2, q) % q
B = (_xrecover(By), By)


def _add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    den = d * x1 * x2 * y1 * y2
    return (
        (x1 * y2 + x2 * y1) * pow(1 + den, q - 2, q) % q,
        (y1 * y2 + x1 * x2) * pow(1 - den, q - 2, q) % q,
    )


def _mul(P, e):
    R = (0, 1)
    while e:
        if e & 1:
            R = _add(R, P)
        P = _add(P, P)
        e >>= 1
    return R


def _point(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if bool(x & 1) != bool(s[31] & 0x80):
        x = q - x
    if (-x * x + y * y - 1 - d * x * x * y * y) % q != 0:
        raise ValueError("point not on curve")
    return (x, y)


def ed25519_verify(sig, msg, pk):
    if len(sig) != 64 or len(pk) != 32:
        return False
    R = _point(sig[:32])
    A = _point(pk)
    S = int.from_bytes(sig[32:], "little")
    if S >= l:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little")
    return _mul(B, S) == _add(R, _mul(A, h))


# --- Attest receipt checks ---------------------------------------------------
def canonical(payload):
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()


def check_receipt(r, key):
    if r.get("public_key") != key:
        return False, "signed by a different key than this issuer"
    payload = r["payload"]
    digest = hashlib.sha256(canonical(payload)).hexdigest()
    if digest != r["payload_hash"]:
        return False, "payload hash mismatch (payload was altered)"
    if payload.get("sequence") != r["sequence"] or payload.get("prev_hash") != r["prev_hash"]:
        return False, "envelope fields disagree with signed payload"
    if payload.get("visit_id") != r["visit_id"]:
        return False, "visit id disagrees with signed payload"
    if payload.get("schema") == "attest.receipt/2":
        # issued_at serializes as "...Z" in the envelope but "+00:00" in the signed
        # payload — compare parsed instants, not strings.
        from datetime import datetime as _dt

        same_instant = (
            _dt.fromisoformat(payload.get("issued_at", ""))
            == _dt.fromisoformat(r["issued_at"])
        )
        if payload.get("receipt_id") != r["id"] or not same_instant:
            return False, "receipt envelope identity disagrees with signed payload"
    elif payload.get("schema") != "attest.receipt/1":
        return False, "unsupported receipt schema"
    if not ed25519_verify(
        base64.b64decode(r["signature"]), bytes.fromhex(r["payload_hash"]), base64.b64decode(key)
    ):
        return False, "signature invalid"
    return True, "ok"


def check_bundle(bundle, key):
    """Verify one bundle's original + review chain. Returns (ok, detail, n_reviews)."""
    original = bundle["original"]
    ok, why = check_receipt(original, key)
    if not ok:
        return False, f"original: {why}", 0
    prev = original["payload_hash"]
    n = 0
    for n, entry in enumerate(bundle.get("reviews", []), 1):
        r = entry["receipt"]
        ok, why = check_receipt(r, key)
        if not ok:
            return False, f"review {n}: {why}", n
        if entry["revision"] != n or r["prev_hash"] != prev:
            return False, f"review {n}: broken chain", n
        anchor = r["payload"].get("original_receipt") or {}
        if anchor.get("hash") != original["payload_hash"]:
            return False, f"review {n}: not anchored to this original", n
        prev = r["payload_hash"]
    return True, "ok", n + 1


def check_media(bundle, media_dir, withheld=None):
    """Match each evidence media digest to a file under media_dir.

    ``withheld`` lists digests deliberately redacted from the pack: they are
    reported as withheld, not as missing. A digest that matches neither a file
    nor the withheld list fails. Returns (checked, withheld_count, bad_digest).
    """
    withheld = set(withheld or [])
    checked = held = 0
    for e in bundle["original"]["payload"].get("evidence", []):
        digest = e.get("media_sha256")
        if not digest:
            continue
        for p in media_dir.rglob("*"):
            if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() == digest:
                checked += 1
                break
        else:
            if digest in withheld:
                held += 1
                continue
            return checked, held, digest
    return checked, held, None


def redaction_for(bundle, pack_dir="."):
    """Read redaction.json inside pack_dir, if present. Returns the withheld
    digests or None. Fails closed: a redaction file naming digests absent from
    the signed evidence is itself suspicious."""
    marker = Path(pack_dir) / "redaction.json"
    if not marker.is_file():
        return None
    data = json.loads(marker.read_text(encoding="utf-8"))
    digests = set(data.get("withheld_digests", []))
    signed = {
        e.get("media_sha256")
        for e in bundle["original"]["payload"].get("evidence", [])
        if e.get("media_sha256")
    }
    if not digests <= signed:
        raise ValueError("redaction.json lists digests not in the signed evidence")
    return digests


def check_manifest(manifest, key):
    """If the manifest carries a signature_receipt, verify it: the export was
    signed at pack time and names exactly which receipt hashes it carries —
    a pack that drops or swaps a record fails here, not just on a missing
    file. Older packs without a signature are reported, not failed."""
    sig = manifest.get("signature_receipt")
    if sig is None:
        return True, "unsigned manifest (pre-signature pack)"
    ok, why = check_receipt(sig, key)
    if not ok:
        return False, f"manifest signature: {why}"
    core = {k: v for k, v in manifest.items() if k != "signature_receipt"}
    digest = hashlib.sha256(canonical(core)).hexdigest()
    if digest != sig["payload"].get("manifest_sha256"):
        return False, "manifest content hash mismatch (manifest was altered)"
    signed_hashes = sig["payload"].get("receipt_hashes", {})
    listed = {v["visit_id"]: v["payload_hash"] for v in manifest.get("visits", [])}
    if listed != signed_hashes:
        return False, "manifest visit list disagrees with the signed export"
    return True, f"export signed: {len(listed)} record(s)"
'''

# verify_bundle.py — verifies one pack's bundle.json (and media/ next to it).
_BUNDLE_MAIN = """\
def main():
    args = sys.argv[1:]
    key = None
    if "--key" in args:
        i = args.index("--key")
        key = args[i + 1]
        del args[i : i + 2]
    bundle = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    key = key or bundle["original"]["public_key"]
    ok, why, n = check_bundle(bundle, key)
    if not ok:
        sys.exit(f"FAIL {why}")
    try:
        withheld = redaction_for(bundle)
    except ValueError as exc:
        sys.exit(f"FAIL {exc}")
    checked, held, bad = check_media(bundle, Path("media"), withheld)
    if bad:
        sys.exit(f"FAIL media digest not found in pack: {bad[:16]}...")
    redact_note = f", {held} withheld by redaction" if held else ""
    print(f"OK: {n} receipt(s) verified; {checked} media digests matched{redact_note}.")
    print("Signature proves record integrity under the issuer key - not identity,")
    print("attendance, or absence.")


if __name__ == "__main__":
    main()
"""

_VERIFIER = _VERIFIER_LIB + _BUNDLE_MAIN

# verify_case.py — verifies every visit bundle in a site case pack plus the
# manifest's receipt hashes, under one pinned issuer key.
_CASE_MAIN = """\
def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    key = manifest["issuer_key"]
    failed = 0
    for v in manifest["visits"]:
        vid = v["visit_id"]
        bundle = json.loads((root / "visits" / vid / "bundle.json").read_text(encoding="utf-8"))
        ok, why, n = check_bundle(bundle, key)
        if not ok:
            print(f"FAIL {vid}: {why}")
            failed += 1
            continue
        if bundle["original"]["payload_hash"] != v["payload_hash"]:
            print(f"FAIL {vid}: manifest hash disagrees with signed original")
            failed += 1
            continue
        vdir = root / "visits" / vid
        try:
            withheld = redaction_for(bundle, vdir)
        except ValueError as exc:
            print(f"FAIL {vid}: {exc}")
            failed += 1
            continue
        if set(v.get("media_withheld", [])) != set(withheld or []):
            print(f"FAIL {vid}: manifest redaction list disagrees with redaction.json")
            failed += 1
            continue
        checked, held, bad = check_media(bundle, vdir / "media", withheld)
        if bad:
            print(f"FAIL {vid}: media digest not found: {bad[:16]}...")
            failed += 1
            continue
        redact_note = f", {held} withheld" if held else ""
        print(f"OK   {vid}: {v['state']} — {v['countersign']['state']}"
              f" ({n} receipt(s), {checked} media digest(s){redact_note})")
    mok, mwhy = check_manifest(manifest, key)
    print(f"{'OK  ' if mok else 'FAIL'} manifest: {mwhy}")
    if not mok:
        failed += 1
    if failed:
        sys.exit(f"{failed} record(s) failed verification")
    print(f"OK: {len(manifest['visits'])} visit records verified under issuer key")
    print(f"    {key[:16]}...")
    print("Integrity only — not identity, attendance, or absence.")


if __name__ == "__main__":
    main()
"""

_CASE_VERIFIER = _VERIFIER_LIB + _CASE_MAIN

_CASE_README = """\
ATTEST CASE PACK — a site's signed visit records for third-party review
=======================================================================

index.html          START HERE — a self-contained offline record browser. It
                    verifies every signed record in your browser and renders
                    each visit's timeline. No install, no network.
manifest.json       Every visit's receipt hash, state, and worker stance.
visits/<id>/        Per-visit bundle.json + the media bytes it references.
verify_case.py      Offline verifier. Run:  python verify_case.py .
verify.html         Zero-install verifier — open in any browser and drop the
                    pack files in. Same checks, pure JavaScript, works offline.
                    Also checks the media bytes index.html can only list.

WHAT A VALID VERIFICATION PROVES
- Each bundle.json is byte-identical to what was signed, and every appended
  review is hash-anchored to its original receipt.
- manifest.json's receipt hashes match the signed originals — the case summary
  cannot quietly describe different records than the signed ones.
- Media files match the sha256 digests in each record's evidence list.

WHAT IT DOES NOT PROVE
- Identity. Signatures authenticate records, not who appears in media.
- Attendance or time worked. Observations are events, not presence.
- Absence. A silent window means nothing was observed — not that nobody came.
- The worker's person. Worker statements arrive through scoped links; they are
  the worker's account, recorded — not a verified identity.

The private signing key stays with the deployment. The issuer public key in
manifest.json verifies this pack; compare it to a key obtained out-of-band to
rule out a pack that swapped keys.
"""


def _media_files(store: Store, media_root: Path, visit_id: str) -> list[tuple[Path, str]]:
    """(absolute path, media-relative name) for evidence media — resolved under
    media_root so a stored path can never escape the media directory."""
    root = Path(media_root).resolve()
    out = []
    for e in store.evidence_for(visit_id):
        if not e.media_path:
            continue
        p = Path(e.media_path)
        p = p.resolve() if p.is_absolute() else (root / p).resolve()
        if p.is_relative_to(root) and p.is_file():
            out.append((p, p.relative_to(root).as_posix()))
    return out


def _withheld_digests(bundle: ReviewBundle) -> list[str]:
    return sorted(
        {e["media_sha256"] for e in bundle.original.payload.get("evidence", []) if e.get("media_sha256")}
    )


def _redaction_marker(bundle: ReviewBundle) -> str:
    import json

    return json.dumps(
        {
            "schema": "attest.redaction/1",
            "media_redacted": True,
            "withheld_digests": _withheld_digests(bundle),
            "note": (
                "Media bytes withheld for privacy. The sha256 digests remain inside "
                "the signed payload — a later full pack can be compared against them."
            ),
        },
        indent=2,
    )


def build_pack(
    store: Store,
    media_root: Path,
    bundle: ReviewBundle,
    *,
    include_media: bool = True,
    redact_media: bool = False,
) -> bytes:
    """Assemble the zip. Media is matched to evidence digests, not filenames.
    With ``redact_media`` the bytes are withheld and a redaction.json marker is
    written — the signed digests stay verifiable, the footage stays private."""
    from .verifyjs import VERIFY_HTML

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bundle.json", bundle.model_dump_json(indent=2))
        z.writestr("README.txt", _README)
        z.writestr("verify_bundle.py", _VERIFIER)
        z.writestr("verify.html", VERIFY_HTML)
        if redact_media:
            z.writestr("redaction.json", _redaction_marker(bundle))
        elif include_media:
            for p, rel in _media_files(store, media_root, bundle.original.visit_id):
                z.write(p, f"media/{rel}")
    return buf.getvalue()


def build_case_pack(
    store: Store,
    media_root: Path,
    site: Site,
    entries: list[tuple[Visit, ReviewBundle, dict]],
    *,
    include_media: bool = True,
    redact_media: bool = False,
    manifest_signer=None,
) -> bytes:
    """A whole-site export: every visit's signed bundle + media, one manifest of
    receipt hashes and worker stances, and a stdlib-only verifier that checks
    all of it. For disputes about a pattern of visits, not a single record.
    With ``redact_media``, media bytes are withheld per visit and the manifest
    records the signed digests — shareable without handing over footage.
    ``manifest_signer`` (e.g. ``engine.issue_export_manifest``) signs the
    manifest itself — the export becomes a chain event naming exactly which
    records it carries, so a pack that drops or swaps one fails verification."""
    import json
    from datetime import UTC, datetime

    manifest = {
        "schema": "attest.case-pack/1",
        "site": {"id": site.id, "name": site.name},
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "issuer_key": entries[0][1].original.public_key if entries else None,
        "media_redacted": redact_media,
        "visits": [
            {
                "visit_id": visit.id,
                "receipt_id": bundle.original.id,
                "payload_hash": bundle.original.payload_hash,
                "state": visit.state,
                "arrived_at": visit.arrived_at.isoformat() if visit.arrived_at else None,
                "last_activity_at": (visit.last_activity_at.isoformat() if visit.last_activity_at else None),
                "countersign": {"state": cs["state"], "detail": cs["detail"]},
                "reviews": len(bundle.reviews),
                "media_withheld": _withheld_digests(bundle) if redact_media else [],
            }
            for visit, bundle, cs in entries
        ],
        "boundary": (
            "Signatures prove record integrity under the issuer key — never "
            "identity, attendance, time worked, or absence."
        ),
    }
    if manifest_signer is not None:
        receipt = manifest_signer(manifest)
        if receipt is not None:
            manifest["signature_receipt"] = receipt.model_dump(mode="json")
    from .verifyjs import VERIFY_HTML, case_index_html

    bundle_texts = [(visit.id, bundle.model_dump_json(indent=2)) for visit, bundle, _ in entries]
    manifest_text = json.dumps(manifest, indent=2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", manifest_text)
        z.writestr("README.txt", _CASE_README)
        z.writestr("verify_case.py", _CASE_VERIFIER)
        z.writestr("verify.html", VERIFY_HTML)
        z.writestr(
            "index.html",
            case_index_html(
                {
                    "site": manifest["site"],
                    "generated_at": manifest["generated_at"],
                    "issuer_key": manifest["issuer_key"],
                    "media_redacted": redact_media,
                },
                bundle_texts,
                manifest_text,
            ),
        )
        for (vid, text), (visit, bundle, _) in zip(bundle_texts, entries, strict=True):
            base = f"visits/{vid}"
            z.writestr(f"{base}/bundle.json", text)
            if redact_media:
                z.writestr(f"{base}/redaction.json", _redaction_marker(bundle))
            elif include_media:
                for p, rel in _media_files(store, media_root, visit.id):
                    z.write(p, f"{base}/media/{rel}")
    return buf.getvalue()
