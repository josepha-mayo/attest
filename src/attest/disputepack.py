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

from .models import ReviewBundle
from .store import Store

_README = """\
ATTEST DISPUTE PACK — what this is and is not
============================================

bundle.json    The signed visit record plus every appended review, hash-chained.
media/         The media bytes the record references (when included).
verify_bundle.py  Offline verifier. Run:  python verify_bundle.py bundle.json

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

# stdlib-only RFC 8032 verifier, generated into every pack. Kept in sync with
# ledger.py's canonicalization (json sort_keys, compact separators) and receipt
# checks (payload hash, envelope agreement, Ed25519 signature, chain links).
_VERIFIER = '''\
#!/usr/bin/env python3
"""Verify an Attest bundle offline. Stdlib only — no pip, no attest install.

Usage: python verify_bundle.py bundle.json [--key BASE64_ISSUER_KEY]
Checks: payload sha256, envelope/payload agreement, Ed25519 signatures,
revision ordering, and anchoring to the original receipt. Media digests are
checked when media/ sits next to this script.
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
    if not ed25519_verify(
        base64.b64decode(r["signature"]), bytes.fromhex(r["payload_hash"]), base64.b64decode(key)
    ):
        return False, "signature invalid"
    return True, "ok"


def main():
    args = sys.argv[1:]
    key = None
    if "--key" in args:
        i = args.index("--key")
        key = args[i + 1]
        del args[i : i + 2]
    bundle = json.loads(Path(args[0]).read_text())
    key = key or bundle["original"]["public_key"]

    original = bundle["original"]
    ok, why = check_receipt(original, key)
    if not ok:
        sys.exit(f"FAIL original: {why}")
    prev = original["payload_hash"]
    n = 0
    for n, entry in enumerate(bundle.get("reviews", []), 1):
        r = entry["receipt"]
        ok, why = check_receipt(r, key)
        if not ok:
            sys.exit(f"FAIL review {n}: {why}")
        if entry["revision"] != n or r["prev_hash"] != prev:
            sys.exit(f"FAIL review {n}: broken chain")
        anchor = r["payload"].get("original_receipt") or {}
        if anchor.get("hash") != original["payload_hash"]:
            sys.exit(f"FAIL review {n}: not anchored to this original")
        prev = r["payload_hash"]

    checked = 0
    for e in original["payload"].get("evidence", []):
        digest = e.get("media_sha256")
        if not digest:
            continue
        for p in Path("media").rglob("*"):
            if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() == digest:
                checked += 1
                break
        else:
            sys.exit(f"FAIL media digest not found in pack: {digest[:16]}...")
    print(f"OK: original + {n} reviews verified; {checked} media digests matched.")
    print("Signature proves record integrity under the issuer key - not identity,")
    print("attendance, or absence.")


if __name__ == "__main__":
    main()
'''


def build_pack(store: Store, media_root: Path, bundle: ReviewBundle, *, include_media: bool = True) -> bytes:
    """Assemble the zip. Media is matched to evidence digests, not filenames."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bundle.json", bundle.model_dump_json(indent=2))
        z.writestr("README.txt", _README)
        z.writestr("verify_bundle.py", _VERIFIER)
        if include_media:
            root = Path(media_root).resolve()
            for e in store.evidence_for(bundle.original.visit_id):
                if not e.media_path:
                    continue
                p = Path(e.media_path)
                p = p.resolve() if p.is_absolute() else (root / p).resolve()
                if p.is_relative_to(root) and p.is_file():
                    rel = p.relative_to(root).as_posix()
                    z.write(p, f"media/{rel}")
    return buf.getvalue()
