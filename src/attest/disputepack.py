"""Dispute pack: a single portable artifact for third-party review.

One zip containing the signed bundle, the media bytes referenced by evidence,
a plain-language README of exactly what the record does and does not establish,
and ``verify_bundle.py`` — a *zero-dependency* verifier implementing RFC 8032
Ed25519 verification with the standard library alone. Anyone can check the pack
on any machine with plain Python; no attest install, no pip, no trust in us.
"""

from __future__ import annotations

import io
import json
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
               files or the .zip itself in. Same checks, pure JavaScript,
               works from file://. Also renders each record's timeline
               (scheduled window, poll coverage, observations).
index.html     Offline record browser — the record verified live in-browser
               with its timeline, a day-by-day strip of the whole window,
               source-by-source corroboration, and any signed
               worker/household/coordinator statements rendered verbatim.
key_rotations.json  Present only if the deployment rotated its signing key:
               the signed pivot receipts — each endorsed by the retiring key —
               that let reviews written under the successor verify. A key that
               appears without a signed endorsement link is rejected, never
               trusted.

WHAT A VALID VERIFICATION PROVES
- Every receipt in bundle.json is byte-identical to what was signed: the payload
  hashes to payload_hash, and the Ed25519 signature covers that hash.
- Reviews are anchored to the original receipt's hash and ordered by revision.
- If the deployment rotated keys, the rotation receipts prove the retiring
  key endorsed each successor — records on both sides of the transition
  verify under one signed chain.
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


def _member_check(r, allowed):
    if r.get("public_key") not in allowed:
        return False, "signed by a key outside the trusted issuer chain"
    return check_receipt(r, r["public_key"])


def check_bundle(bundle, key):
    """Verify one bundle's original + review chain. Returns (ok, detail, n_reviews).

    ``key`` is either a single pinned issuer key (str) or the trusted-key set
    returned by trusted_keys() — a pack written across a key rotation
    legitimately mixes issuer keys."""
    # ReviewBundle is extra="forbid": honest files carry exactly kind,
    # original, reviews. Any other top-level key (e.g. a forged
    # countersign_status) is unsigned attacker content — fail, don't render it.
    allowed = {key} if isinstance(key, str) else set(key)
    if bundle.get("kind") != "attest.review_bundle/1":
        return False, "unrecognized bundle kind", 0
    extra = set(bundle) - {"kind", "original", "reviews"}
    if extra:
        return False, f"unsigned extra field in bundle: {sorted(extra)[0]}", 0
    original = bundle["original"]
    ok, why = _member_check(original, allowed)
    if not ok:
        return False, f"original: {why}", 0
    prev = original["payload_hash"]
    n = 0
    for n, entry in enumerate(bundle.get("reviews", []), 1):
        r = entry["receipt"]
        ok, why = _member_check(r, allowed)
        if not ok:
            return False, f"review {n}: {why}", n
        if (
            entry["id"] != r["id"]
            or entry["visit_id"] != original["visit_id"]
            or r["visit_id"] != original["visit_id"]
        ):
            return False, f"review {n}: identity does not match original", n
        if entry["revision"] != n or r["sequence"] != n or r["prev_hash"] != prev:
            return False, f"review {n}: sequence or previous hash mismatch", n
        anchor = r["payload"].get("original_receipt") or {}
        if (
            r["payload"].get("record_type") != "review"
            or anchor.get("id") != original["id"]
            or anchor.get("hash") != original["payload_hash"]
        ):
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
    signed = {
        e.get("media_sha256")
        for e in bundle["original"]["payload"].get("evidence", [])
        if e.get("media_sha256")
    }
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
    if media_dir.exists():
        # A media file whose bytes don't hash to a signed digest is smuggled
        # content riding inside a "VERIFIED" pack — fail it, don't skip it.
        for p in sorted(media_dir.rglob("*")):
            if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() not in signed:
                return checked, held, f"smuggled:{p.name}"
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
    file. Older packs without a signature are reported, not failed. ``key``
    is a single pinned key or the trusted_keys() set — the signature receipt
    must verify under a key inside the trusted issuer chain."""
    sig = manifest.get("signature_receipt")
    if sig is None:
        return True, "unsigned manifest (pre-signature pack)"
    allowed = {key} if isinstance(key, str) else set(key)
    ok, why = _member_check(sig, allowed)
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


def _adoption_consent(receipts, rotation, new_key):
    """Whether the SUCCESSOR key countersigned the rotation via a
    key_adoption receipt naming it (id + payload hash). A retiring key's
    endorsement is self-serve — any key can claim any successor — so consent
    is what separates a real handoff from a grafted "predecessor"."""
    for r in receipts:
        p = r.get("payload", {})
        link = p.get("rotation_receipt") or {}
        if (
            p.get("record_type") == "key_adoption"
            and link.get("id") == rotation.get("id")
            and link.get("hash") == rotation.get("payload_hash")
            and r.get("public_key") == new_key
        ):
            ok, _ = check_receipt(r, new_key)
            if ok:
                return True
    return False


def trusted_keys(issuer_key, rotation_receipts, max_hops=32):
    """The keys a pack verification may trust: the manifest issuer plus every
    ancestor reachable through signed key_rotation receipts. Each hop must be
    a valid receipt signed by the retiring key endorsing its successor AND
    countersigned by that successor via key_adoption — a forged or
    unconsented rotation never lands in the set."""
    trusted = {issuer_key}
    cur = issuer_key
    for _ in range(max_hops):
        nxt = None
        for r in rotation_receipts:
            p = r.get("payload", {})
            if (
                p.get("record_type") == "key_rotation"
                and p.get("new_key") == cur
                and r.get("public_key") == p.get("previous_key")
            ):
                ok, _ = check_receipt(r, r["public_key"])
                if ok and _adoption_consent(rotation_receipts, r, cur):
                    nxt = p["previous_key"]
                    break
        if nxt is None:
            break
        cur = nxt
        trusted.add(cur)
    return trusted


def descendant_keys(root_key, rotation_receipts, max_hops=32):
    """The mirror walk for single-visit bundles: reviews append forward in
    time, so a bundle legitimately carries keys AFTER its original — every
    successor reachable through signed rotations. Each hop needs BOTH
    signatures: the retiring key's endorsement and the successor's
    key_adoption consent — an orphaned rotation (crashed before adoption)
    is a dead branch, not a trusted descendant."""
    trusted = {root_key}
    cur = root_key
    for _ in range(max_hops):
        nxt = None
        for r in rotation_receipts:
            p = r.get("payload", {})
            if (
                p.get("record_type") == "key_rotation"
                and p.get("previous_key") == cur
                and r.get("public_key") == cur
            ):
                ok, _ = check_receipt(r, cur)
                if ok and _adoption_consent(rotation_receipts, r, p["new_key"]):
                    nxt = p["new_key"]
                    break
        if nxt is None:
            break
        cur = nxt
        trusted.add(cur)
    return trusted


def revoked_keys(key_receipts):
    """Key -> suspect_after ISO for valid key_revocation receipts signed by
    the in-effect issuer at their position. Only the live key can revoke —
    a retired key revoking its successor would let a compromised key smear
    the healthy one, and position alone can't name the tip: a forged
    high-sequence revocation would make itself the tip and self-authorize.
    Authority is therefore tracked through the same consented pivots
    verify_chain uses."""
    ordered = sorted(key_receipts, key=lambda x: x.get("sequence", 0))
    revoked = {}
    in_effect = None
    for r in ordered:
        ok, _ = check_receipt(r, in_effect or r.get("public_key"))
        if not ok:
            continue
        if in_effect is None:
            in_effect = r.get("public_key")
        p = r.get("payload", {})
        if (
            p.get("record_type") == "key_rotation"
            and p.get("previous_key") == in_effect
            and p.get("new_key")
            and _adoption_consent(ordered, r, p["new_key"])
        ):
            in_effect = p["new_key"]
            continue
        if (
            p.get("record_type") == "key_revocation"
            and p.get("revoked_key")
            and r.get("public_key") == in_effect
        ):
            revoked[p["revoked_key"]] = p.get("suspect_after") or ""
    return revoked


def suspect_records(receipts, revoked):
    """Receipts signed by a revoked key inside its declared suspect window —
    cryptographically valid, annotated suspect. Integrity never depends on
    this; it's what a compromised key's history deserves."""
    from datetime import datetime

    def _instant(s):
        try:
            return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        except ValueError:
            return None

    out = []
    for r in receipts:
        after = _instant(revoked.get(r.get("public_key"), ""))
        at = _instant(r.get("issued_at", ""))
        if after is not None and at is not None and at > after:
            out.append(r)
    return out
'''

# verify_bundle.py — verifies one pack's bundle.json (and media/ next to it).
_BUNDLE_MAIN = """\
def main():
    args = sys.argv[1:]
    key = None
    if "--key" in args:
        i = args.index("--key")
        if i + 1 >= len(args):
            sys.exit("FAIL --key requires a base64 public key value")
        key = args[i + 1]
        del args[i : i + 2]
    bundle = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    pack_dir = Path(args[0]).resolve().parent
    key = key or bundle["original"]["public_key"]
    # Reviews appended after a key rotation verify under the successor —
    # legitimate only through the signed rotation links in key_rotations.json.
    # Revocation receipts ride the same file: the overlay annotates suspect
    # windows without touching the integrity verdict.
    trusted = {key}
    rotations = []
    rot_path = pack_dir / "key_rotations.json"
    if rot_path.is_file():
        try:
            rj = json.loads(rot_path.read_text(encoding="utf-8"))
            rotations = rj.get("rotations") if isinstance(rj, dict) else None
        except Exception:
            rotations = None
        if not isinstance(rotations, list):
            sys.exit("FAIL key_rotations.json: malformed")
        trusted = trusted_keys(key, rotations) | descendant_keys(key, rotations)
    revoked = revoked_keys(rotations)
    ok, why, n = check_bundle(bundle, trusted)
    if not ok:
        sys.exit(f"FAIL {why}")
    try:
        withheld = redaction_for(bundle)
    except ValueError as exc:
        sys.exit(f"FAIL {exc}")
    checked, held, bad = check_media(bundle, Path("media"), withheld)
    if bad:
        if str(bad).startswith("smuggled:"):
            sys.exit(f"FAIL media file not named by the signed evidence: {bad[9:]}")
        sys.exit(f"FAIL media digest not found in pack: {bad[:16]}...")
    # Fail closed on files the pack format doesn't name — but only when the
    # directory looks like an extracted pack (README/media/pack pages present).
    # A bare bundle.json shared alone has no pack around it to smuggle into.
    allowed_top = {
        "bundle.json",
        "README.txt",
        "verify_bundle.py",
        "verify.html",
        "index.html",
        "redaction.json",
        "key_rotations.json",
    }
    markers = ("README.txt", "media", "verify.html", "index.html")
    if any((pack_dir / m).exists() for m in markers):
        for p in sorted(pack_dir.iterdir()):
            if p.is_file() and p.name not in allowed_top:
                sys.exit(f"FAIL {p.name}: present but not part of the pack format")
            if p.is_dir() and p.name != "media":
                sys.exit(f"FAIL {p.name}/: directory not part of the pack format")
    redact_note = f", {held} withheld by redaction" if held else ""
    print(f"OK: {n} receipt(s) verified; {checked} media digests matched{redact_note}.")
    if len(trusted) > 1:
        print(f"    ({len(trusted)} issuer keys linked via the signed rotation chain)")
    suspect = suspect_records(
        [bundle["original"]] + [e["receipt"] for e in bundle.get("reviews", [])], revoked)
    if suspect:
        print(f"    ({len(suspect)} record(s) signed by a revoked issuer inside its suspect window)")
    print("Signature proves record integrity under the issuer key - not identity,")
    print("attendance, or absence.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        # Never die with a traceback — the vocabulary of this tool is OK/FAIL.
        sys.exit(f"FAIL verifier error: {exc}")
"""

_VERIFIER = _VERIFIER_LIB + _BUNDLE_MAIN

# verify_case.py — verifies every visit bundle in a site case pack plus the
# manifest's receipt hashes, under one pinned issuer key.
_CASE_MAIN = """\
def main():
    args = sys.argv[1:]
    key = None
    if "--key" in args:
        i = args.index("--key")
        if i + 1 >= len(args):
            sys.exit("FAIL --key requires a base64 public key value")
        key = args[i + 1]
        del args[i : i + 2]
    root = Path(args[0]) if args else Path(".")
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except Exception as exc:
        sys.exit(f"FAIL manifest.json unreadable: {exc}")
    declared = manifest.get("issuer_key")
    if not declared:
        sys.exit("FAIL manifest: missing issuer_key")
    # The trusted issuer set: the manifest issuer plus every ancestor the
    # pack's signed key_rotation receipts endorse — post-rotation packs mix
    # keys legitimately. Rotation receipts that don't parse or don't verify
    # are ignored here and fail in the attestation loop below.
    rotations = []
    for a in manifest.get("attestations", []):
        rid = a.get("receipt_id")
        if not isinstance(rid, str) or "/" in rid or chr(92) in rid or ".." in rid:
            continue  # a receipt_id that walks out of attestations/ is malformed
        try:
            r = json.loads((root / "attestations" / f"{rid}.json").read_text(encoding="utf-8"))
        except Exception:
            continue
        if r.get("payload", {}).get("record_type") in ("key_rotation", "key_adoption", "key_revocation"):
            rotations.append(r)
    trusted = trusted_keys(declared, rotations)
    revoked = revoked_keys(rotations)
    suspect_n = 0
    if key is not None and key not in trusted:
        sys.exit(
            "FAIL manifest: issuer_key disagrees with the pinned --key "
            "(no signed key_rotation links them)"
        )
    # Without --key the issuer is self-declared by the pack — the signatures
    # still verify, but 'who signed' is only as trustworthy as the source of
    # this file. Pin --key to rule out a whole-pack forgery under another key.
    key = key or declared
    if manifest.get("schema") != "attest.case-pack/1":
        sys.exit(f"FAIL manifest: unsupported schema {manifest.get('schema')!r}")
    visits = manifest.get("visits")
    if not isinstance(visits, list):
        sys.exit("FAIL manifest: visits is missing or not a list")
    failed = 0
    listed_vids = set()
    for v in visits:
        vid = v.get("visit_id", "?")
        listed_vids.add(vid)
        try:
            bundle = json.loads((root / "visits" / vid / "bundle.json").read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"FAIL {vid}: bundle listed but missing or unreadable ({exc})")
            failed += 1
            continue
        ok, why, n = check_bundle(bundle, trusted)
        if not ok:
            print(f"FAIL {vid}: {why}")
            failed += 1
            continue
        suspect_n += len(suspect_records(
            [bundle["original"]] + [e["receipt"] for e in bundle.get("reviews", [])], revoked))
        if bundle["original"]["payload_hash"] != v.get("payload_hash"):
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
            if str(bad).startswith("smuggled:"):
                print(f"FAIL {vid}: media file not named by the signed evidence: {bad[9:]}")
            else:
                print(f"FAIL {vid}: media digest not found: {bad[:16]}...")
            failed += 1
            continue
        redact_note = f", {held} withheld" if held else ""
        cs = (v.get("countersign") or {}).get("state", "?")
        print(f"OK   {vid}: {v.get('state', '?')} — {cs}"
              f" ({n} receipt(s), {checked} media digest(s){redact_note})")
    for a in manifest.get("attestations", []):
        rid = a.get("receipt_id", "?")
        if not isinstance(rid, str) or "/" in rid or chr(92) in rid or ".." in rid:
            print(f"FAIL attestation: malformed receipt_id {rid!r}")
            failed += 1
            continue
        apath = root / "attestations" / f"{rid}.json"
        if not apath.exists():
            print(f"FAIL attestation {rid}: manifest lists it but the file is missing")
            failed += 1
            continue
        try:
            ar = json.loads(apath.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"FAIL attestation {rid}: unreadable ({exc})")
            failed += 1
            continue
        if ar.get("public_key") not in trusted:
            print(f"FAIL attestation {rid}: issued under a key outside the rotation chain")
            failed += 1
            continue
        aok, awhy = check_receipt(ar, ar["public_key"])
        if not aok:
            print(f"FAIL attestation {rid}: {awhy}")
            failed += 1
        elif ar["payload_hash"] != a.get("payload_hash") or ar["visit_id"] != a.get("visit_id"):
            print(f"FAIL attestation {rid}: disagrees with the signed manifest")
            failed += 1
        else:
            print(f"OK   attestation {a.get('record_type') or 'record'} ({rid[:20]}...)")
    adir = root / "attestations"
    if adir.exists():
        listed = {f"{a.get('receipt_id')}.json" for a in manifest.get("attestations", [])}
        extra = {p.name for p in adir.glob("*.json")} - listed
        if extra:
            print(f"FAIL {len(extra)} attestation file(s) present but not in the signed manifest")
            failed += 1
    vdir = root / "visits"
    if vdir.exists():
        extra_v = {p.name for p in vdir.iterdir() if p.is_dir()} - listed_vids
        if extra_v:
            print(f"FAIL {len(extra_v)} visit dir(s) present but not in the signed manifest")
            failed += 1
    # Fail closed on any file the pack format doesn't name — a smuggled
    # top-level file or extra member inside a visit dir would otherwise ride
    # inside a "VERIFIED" pack. Media members are digest-checked by
    # check_media against the signed evidence.
    allowed_top = {"manifest.json", "README.txt", "verify_case.py", "verify.html", "index.html"}
    for p in sorted(root.iterdir()):
        if p.is_file() and p.name not in allowed_top:
            print(f"FAIL {p.name}: present but not in the signed manifest")
            failed += 1
        elif p.is_dir() and p.name not in ("visits", "attestations"):
            print(f"FAIL {p.name}/: directory not in the signed manifest")
            failed += 1
    if vdir.exists():
        for vd in sorted(p for p in vdir.iterdir() if p.is_dir()):
            for p in sorted(vd.iterdir()):
                if p.is_file() and p.name not in ("bundle.json", "redaction.json"):
                    print(f"FAIL {vd.name}/{p.name}: present but not in the signed manifest")
                    failed += 1
                elif p.is_dir() and p.name != "media":
                    print(f"FAIL {vd.name}/{p.name}/: directory not in the signed manifest")
                    failed += 1
    mok, mwhy = check_manifest(manifest, trusted)
    print(f"{'OK  ' if mok else 'FAIL'} manifest: {mwhy}")
    if not mok:
        failed += 1
    if failed:
        sys.exit(f"{failed} record(s) failed verification")
    print(f"OK: {len(visits)} visit records verified under issuer key")
    print(f"    {key[:16]}...")
    if len(trusted) > 1:
        # The pack spans a signed key rotation — the lineage is the pivot, not
        # a weaker check; say so plainly rather than hiding it behind one key.
        print(f"    ({len(trusted)} issuer keys linked via the signed rotation chain)")
    if suspect_n:
        print(f"    ({suspect_n} record(s) signed by a revoked issuer inside its suspect window)")
    if declared == key and "--key" not in sys.argv:
        print("    (issuer self-declared by the pack — pass --key to pin it)")
    print("Integrity only — not identity, attendance, or absence.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        # Never die with a traceback — the vocabulary of this tool is OK/FAIL.
        sys.exit(f"FAIL verifier error: {exc}")
"""

_CASE_VERIFIER = _VERIFIER_LIB + _CASE_MAIN

_CASE_README = """\
ATTEST CASE PACK — a site's signed visit records for third-party review
=======================================================================

index.html          START HERE — a self-contained offline record browser. It
                    verifies every signed record in your browser, opens with a
                    day-by-day strip of the whole exported window (coverage,
                    interruptions, observations), and renders each visit's
                    timeline. No install, no network.
manifest.json       Every visit's receipt hash, state, and worker stance.
visits/<id>/        Per-visit bundle.json + the media bytes it references.
attestations/       Site-level signed receipts: coverage certificates, period
                    digests, prior exports — and any key_rotation pivots, each
                    signed by the retiring key endorsing its successor.
verify_case.py      Offline verifier. Run:  python verify_case.py .
                    Pass --key <base64> to pin the expected issuer key —
                    without it the issuer is self-declared by the pack. A
                    pinned pre-rotation key still verifies: the signed
                    rotation chain links it to the manifest's issuer.
verify.html         Zero-install verifier — open in any browser and drop the
                    pack files in. Same checks, pure JavaScript, works offline.
                    Also checks the media bytes index.html can only list.

WHAT A VALID VERIFICATION PROVES
- Each bundle.json is byte-identical to what was signed, and every appended
  review is hash-anchored to its original receipt.
- manifest.json's receipt hashes match the signed originals — the case summary
  cannot quietly describe different records than the signed ones.
- Media files match the sha256 digests in each record's evidence list.
- If the deployment rotated its signing key, the rotation receipts are signed
  pivots: the retiring key endorsed each successor, so records on both sides
  of the transition verify under one signed chain — a key that appears in
  the pack without a signed endorsement link is rejected, never trusted.

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
        ensure_ascii=False,
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
    from .verifyjs import VERIFY_HTML, case_index_html

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        bundle_text = bundle.model_dump_json(indent=2)
        # Rotation receipts the review chain may span — a review appended
        # after a key rotation verifies under the successor, and this member
        # is the signed link that makes that legitimate instead of "different
        # key". Only written when rotations exist.
        rotations = [r.model_dump(mode="json") for r in store.receipts() if r.visit_id.startswith("key:")]
        z.writestr("bundle.json", bundle_text)
        z.writestr("README.txt", _README)
        z.writestr("verify_bundle.py", _VERIFIER)
        z.writestr("verify.html", VERIFY_HTML)
        from datetime import UTC, datetime

        z.writestr(
            "index.html",
            case_index_html(
                {
                    "schema": "attest.dispute-pack/1",
                    "site": bundle.original.payload.get("site") or {},
                    "generated_at": datetime.now(tz=UTC).isoformat(),
                    "issuer_key": bundle.original.public_key,
                    "media_redacted": redact_media,
                },
                [(bundle.original.visit_id, bundle_text)],
                attestations=[(r["id"], json.dumps(r, indent=2, ensure_ascii=False)) for r in rotations],
            ),
        )
        if rotations:
            z.writestr(
                "key_rotations.json",
                json.dumps(
                    {"schema": "attest.key-rotations/1", "rotations": rotations},
                    indent=2,
                    ensure_ascii=False,
                ),
            )
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
    issuer_key: str | None = None,
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

    # Site-level chain events — coverage attestations ("was anyone watching?"),
    # period digests, prior exports, source disconnect — travel in the pack so
    # the evidence segment is complete, not just the visit receipts. `verify:*`
    # receipts are deployment-scoped provenance (a signed official-API sweep)
    # and travel with every pack: they evidence the issuer, not the site.
    # Collected before signing: this export's own manifest receipt cannot
    # reference its own hash, so it is the one attestation the pack cannot carry.
    # ``key:*`` receipts are deployment-scoped trust anchors (a signed
    # key_rotation extends pinned-key trust across an issuer change) and
    # travel with every pack like the verify:* provenance receipts.
    attestations = [
        r
        for r in store.receipts()
        if r.visit_id == f"source:{site.id}"
        or r.visit_id.startswith(f"coverage:{site.id}:")
        or r.visit_id.startswith(f"digest:{site.id}:")
        or r.visit_id.startswith(f"export:{site.id}:")
        or r.visit_id.startswith("verify:")
        or r.visit_id.startswith("key:")
    ]
    manifest = {
        "schema": "attest.case-pack/1",
        "site": {
            "id": site.id,
            "name": site.name,
            "source_disconnected_at": (site.disconnected_at.isoformat() if site.disconnected_at else None),
        },
        "generated_at": datetime.now(tz=UTC).isoformat(),
        # The issuer is the deployment's CURRENT signing key — verifiers walk
        # ancestors from here through signed key_rotation receipts. Falling
        # back to a visit's original key would strand post-rotation packs:
        # a retired key has no ancestors to walk to.
        "issuer_key": issuer_key or (entries[0][1].original.public_key if entries else None),
        "media_redacted": redact_media,
        "attestations": [
            {
                "visit_id": r.visit_id,
                "receipt_id": r.id,
                "payload_hash": r.payload_hash,
                "record_type": r.payload.get("record_type"),
            }
            for r in attestations
        ],
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
    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False)
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
                attestations=[(r.id, r.model_dump_json(indent=2)) for r in attestations],
            ),
        )
        for r in attestations:
            z.writestr(f"attestations/{r.id}.json", r.model_dump_json(indent=2))
        for (vid, text), (visit, bundle, _) in zip(bundle_texts, entries, strict=True):
            base = f"visits/{vid}"
            z.writestr(f"{base}/bundle.json", text)
            if redact_media:
                z.writestr(f"{base}/redaction.json", _redaction_marker(bundle))
            elif include_media:
                for p, rel in _media_files(store, media_root, visit.id):
                    z.write(p, f"{base}/media/{rel}")
    return buf.getvalue()


def write_verifiers(directory) -> tuple[Path, Path]:
    """Emit the standalone verifier scripts next to a verifier deployment —
    e.g. the AWS Lambda handler in ``extras/lambda/``, which runs these pinned
    copies so a pack's own embedded verify script is never executed."""
    directory = Path(directory)
    case = directory / "verifier_case.py"
    bundle = directory / "verifier_bundle.py"
    case.write_text(_CASE_VERIFIER, encoding="utf-8")
    bundle.write_text(_VERIFIER, encoding="utf-8")
    return case, bundle
