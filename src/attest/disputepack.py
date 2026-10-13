"""Dispute pack: a single portable artifact for third-party review.

One zip containing the signed bundle, the media bytes referenced by evidence,
a plain-language README of exactly what the record does and does not establish,
and ``verify_bundle.py`` — a *zero-dependency* verifier implementing RFC 8032
Ed25519 verification with the standard library alone. Anyone can check the pack
on any machine with plain Python; no attest install, no pip, no trust in us.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

from .models import Receipt, ReviewBundle, Site, Visit
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
verifier_manifest.json  A signed receipt pinning the sha256 of every verifier
               shipped in this pack (verify_bundle.py, verify.html, index.html,
               README.txt). A forged pack that doctors its own verifier to
               print VERIFIED is caught: the manifest names the real bytes,
               and only the deployment's key can sign one.
log_checkpoint.json   Present when the deployment publishes a transparency
               log: a signed Merkle tree head plus an inclusion proof for
               every receipt in this pack — cryptographic evidence that these
               receipts were committed to the deployment's published append-
               only log, in this order. A receipt with a valid signature but
               no log membership still fails: signing a record is not the
               same as committing it.

WHAT A VALID VERIFICATION PROVES
- Every receipt in bundle.json is byte-identical to what was signed: the payload
  hashes to payload_hash, and the Ed25519 signature covers that hash.
- Reviews are anchored to the original receipt's hash and ordered by revision.
- If the deployment rotated keys, the rotation receipts prove the retiring
  key endorsed each successor — records on both sides of the transition
  verify under one signed chain.
- If log_checkpoint.json is present, every issuer-signed receipt in the pack
  proves inclusion in the deployment's transparency log at the checkpoint's
  committed size — the pack cannot carry receipts the log never saw.
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
import re
import sys
from pathlib import Path

# Verdict text carries — and …; make the byte stream UTF-8 no matter the
# console codepage so piped/redirected output never arrives as cp1252 mojibake.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


def _loads(s):
    """``json.loads`` minus the bare NaN/Infinity/-Infinity literals CPython
    accepts — no other verifier surface parses them; one payload, one
    verdict."""
    return json.loads(
        s,
        parse_constant=lambda x: (_ for _ in ()).throw(
            ValueError("non-JSON literal: " + x)
        ),
    )


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
    # Canonicality (browser decodePoint parity): y >= q is a second spelling
    # of y - q — and under a small-order point the encoding forgery
    # S=0,R=identity satisfies the equation without the private key.
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= q:
        raise ValueError("non-canonical encoding")
    x = _xrecover(y)
    # Negative-zero x: y in {1, q-1} has x == 0, and the sign bit on it is a
    # second (rejected) encoding — same gate the browser applies.
    if x == 0 and (s[31] & 0x80):
        raise ValueError("negative-zero x encoding")
    if bool(x & 1) != bool(s[31] & 0x80):
        x = q - x
    if (-x * x + y * y - 1 - d * x * x * y * y) % q != 0:
        raise ValueError("point not on curve")
    return (x, y)


def ed25519_verify(sig, msg, pk):
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        R = _point(sig[:32])
        A = _point(pk)
    except ValueError:
        return False
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


# The instant spelling every verifier surface agrees on — identical grammar
# to models.ISO_INSTANT_RE and the browser's ISO gate. (Digit/dot classes
# spelled out because this source ships inside a non-raw string literal.)
_ISO_INSTANT = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}"
    r"([T ]([01][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9]([.][0-9]+)?)?"
    r"(Z|[+-]([01][0-9]|2[0-3]):?[0-5][0-9])?)?$"
)


def _iso_instant(v):
    """Shared-grammar instant parse; returns a datetime or None. Naive vs
    aware inequality falls out of datetime.__eq__ (mirrors the browser's
    explicit awareness flag)."""
    from datetime import datetime as _d

    if isinstance(v, _d):
        return v
    if not isinstance(v, str) or not _ISO_INSTANT.fullmatch(v):
        return None
    try:
        return _d.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def _py_model_int(v):
    """Strict JSON-int gate for model-typed envelope fields — mirrors
    ``models._json_int`` / ``Number.isInteger``: int non-bool or finite
    integral float; strings and bools reject."""
    import math

    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v) if math.isfinite(v) and v.is_integer() else None
    return None


def _unb64(s):
    """``atob``-parity base64 for envelope fields: ASCII whitespace
    tolerated, non-alphabet bytes fatal, missing padding forgiven — bare
    ``b64decode`` silently drops junk where the browser throws."""
    ws = frozenset(" " + chr(9) + chr(10) + chr(12) + chr(13))
    s = "".join(c for c in s if c not in ws)
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def check_receipt(r, key):
    if not isinstance(r, dict):
        return False, "malformed receipt"
    if r.get("public_key") != key:
        return False, "signed by a different key than this issuer"
    # Envelope fields must carry their model types — a pool member spelling
    # `sequence` as a dict or `visit_id` as a number is malformed on the
    # native surface (model_validate rejects), never a lenient pass here.
    if (
        not isinstance(r.get("id"), str)
        or not isinstance(r.get("visit_id"), str)
        or not isinstance(r.get("public_key"), str)
        or not isinstance(r.get("payload_hash"), str)
        or not isinstance(r.get("signature"), str)
        # prev_hash is required-nullable: absent fails the model (and the
        # JS guard — undefined !== null), explicit null is the chain head.
        or "prev_hash" not in r
        or not (r["prev_hash"] is None or isinstance(r["prev_hash"], str))
    ):
        return False, "malformed receipt"
    # issued_at is model-gated at intake on native surfaces: key absent →
    # default_factory fills it; present → must be an ISO-grammar instant
    # (Receipt's BeforeValidator raises on anything else — including null).
    # This applies on EVERY schema, not just the /2 instant-compare below.
    if "issued_at" in r and _iso_instant(r["issued_at"]) is None:
        return False, "malformed receipt"
    env_seq = _py_model_int(r.get("sequence"))
    if env_seq is None:
        return False, "malformed receipt"
    payload = r.get("payload")
    if not isinstance(payload, dict):
        return False, "malformed receipt"
    digest = hashlib.sha256(canonical(payload)).hexdigest()
    if digest != r["payload_hash"]:
        return False, "payload hash mismatch (payload was altered)"
    if payload.get("sequence") != env_seq or payload.get("prev_hash") != r["prev_hash"]:
        return False, "envelope fields disagree with signed payload"
    if payload.get("visit_id") != r["visit_id"]:
        return False, "visit id disagrees with signed payload"
    if payload.get("schema") == "attest.receipt/2":
        # issued_at serializes as "...Z" in the envelope but "+00:00" in the signed
        # payload — compare parsed instants under the shared ISO grammar.
        p_issued = _iso_instant(payload.get("issued_at", ""))
        e_issued = _iso_instant(r.get("issued_at"))
        same_instant = p_issued is not None and e_issued is not None and p_issued == e_issued
        if payload.get("receipt_id") != r["id"] or not same_instant:
            return False, "receipt envelope identity disagrees with signed payload"
    elif payload.get("schema") != "attest.receipt/1":
        return False, "unsupported receipt schema"
    # Malformed base64/hex in the envelope must be a clean "signature
    # invalid", not a crash — verify_receipt's except-ValueError returns the
    # same verdict, and pool members are attacker-controlled.
    try:
        sig_ok = ed25519_verify(
            _unb64(r["signature"]), bytes.fromhex(r["payload_hash"]), _unb64(key)
        )
    except ValueError:
        return False, "signature invalid"
    if not sig_ok:
        return False, "signature invalid"
    return True, "ok"


def _member_check(r, allowed):
    if not isinstance(r, dict):
        return False, "malformed receipt"
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
    if not isinstance(bundle, dict):
        return False, "bundle is not an object", 0
    allowed = {key} if isinstance(key, str) else set(key)
    if bundle.get("kind") != "attest.review_bundle/1":
        return False, "unrecognized bundle kind", 0
    extra = set(bundle) - {"kind", "original", "reviews"}
    if extra:
        return False, f"unsigned extra field in bundle: {sorted(extra)[0]}", 0
    original = bundle.get("original")
    ok, why = _member_check(original, allowed)
    if not ok:
        return False, f"original: {why}", 0
    prev = original["payload_hash"]
    n = 0
    reviews = bundle.get("reviews", [])
    # ReviewBundle caps at max_length=500 and requires a list — malformed
    # shape is a clean fail here exactly as model_validate fails natively.
    if not isinstance(reviews, list):
        return False, "reviews is not a list", n
    if len(reviews) > 500:
        return False, "review chain exceeds the 500-entry cap", n
    for n, entry in enumerate(reviews, 1):
        if not isinstance(entry, dict):
            return False, f"review {n}: malformed entry", n
        r = entry.get("receipt")
        ok, why = _member_check(r, allowed)
        if not ok:
            return False, f"review {n}: {why}", n
        if (
            not isinstance(entry.get("id"), str)
            or not isinstance(entry.get("visit_id"), str)
            or entry["id"] != r["id"]
            or entry["visit_id"] != original["visit_id"]
            or r["visit_id"] != original["visit_id"]
        ):
            return False, f"review {n}: identity does not match original", n
        if (
            _py_model_int(entry.get("revision")) != n
            or _py_model_int(r.get("sequence")) != n
            or r.get("prev_hash") != prev
        ):
            return False, f"review {n}: sequence or previous hash mismatch", n
        # reviews.py requires original_receipt to be exactly {"id","hash"} —
        # extra keys mean a payload the signer committed that no surface may
        # silently accept; non-dict anchors reject by inequality, not a crash.
        if r["payload"].get("record_type") != "review" or r["payload"].get(
            "original_receipt"
        ) != {"id": original["id"], "hash": original["payload_hash"]}:
            return False, f"review {n}: not anchored to this original", n
        prev = r["payload_hash"]
    return True, "ok", n + 1


_VERIFIER_TOOLS = ("verify_case.py", "verify_bundle.py", "verify.html", "index.html", "README.txt")


def check_tools(pack_dir, trusted, scope):
    """Enforce the signed verifier_manifest.json pin: the pack's tooling
    members must byte-match the issuer-signed sha256 set. Without it a forged
    always-green verifier script can ride a genuine pack — pack membership
    whitelists names, never bytes. ``scope`` binds the receipt to this pack
    (``visit:{id}`` or ``site:{id}``). Older packs without the member are
    reported, not failed. Returns the pinned tool count or None."""
    vm_path = Path(pack_dir) / "verifier_manifest.json"
    if not vm_path.is_file():
        return None
    try:
        vm = _loads(vm_path.read_text(encoding="utf-8"))
    except Exception:
        sys.exit("FAIL verifier_manifest.json: not readable JSON")
    payload = vm.get("payload") if isinstance(vm, dict) else None
    if not isinstance(payload, dict) or payload.get("record_type") != "verifier_manifest":
        sys.exit("FAIL verifier_manifest.json: not a verifier_manifest receipt")
    if payload.get("scope") != scope:
        sys.exit("FAIL verifier_manifest.json: signed for a different pack — grafted pin")
    if vm.get("public_key") not in trusted:
        sys.exit("FAIL verifier_manifest.json: signed outside the trusted issuer chain")
    ok, why = check_receipt(vm, vm["public_key"])
    if not ok:
        sys.exit(f"FAIL verifier_manifest.json: {why}")
    tools = payload.get("tools")
    if not isinstance(tools, dict) or not tools:
        sys.exit("FAIL verifier_manifest.json: tools map missing or malformed")
    for name, want in tools.items():
        if (
            not isinstance(name, str)
            or not isinstance(want, str)
            or name not in _VERIFIER_TOOLS
        ):
            sys.exit(f"FAIL verifier_manifest.json: unsafe or unknown member {name!r}")
        fp = Path(pack_dir) / name
        if not fp.is_file():
            sys.exit(f"FAIL {name}: pinned verifier tool missing from the pack")
        if hashlib.sha256(fp.read_bytes()).hexdigest() != want:
            sys.exit(
                f"FAIL {name}: bytes differ from the issuer-signed pin — "
                "a verifier script modified after export cannot be trusted"
            )
    for fp in Path(pack_dir).iterdir():
        # A tool member that ISN'T pinned by the manifest is as suspect as a
        # mismatched one — otherwise the forger just ships a doctored index.html.
        if fp.is_file() and fp.name in _VERIFIER_TOOLS and fp.name not in tools:
            sys.exit(f"FAIL {fp.name}: verifier tooling present but not covered by the signed pin")
    return len(tools)


def _is_int(x):
    """A JSON int per JS Number.isInteger parity — the browser verifier
    cannot tell `5` from `5.0` post-parse, so every surface accepts an
    integral float; bools and strings are never ints on either side. A
    bool-shaped proof is a crafted doc, not a proof."""
    if isinstance(x, bool):
        return False
    if isinstance(x, int):
        return True
    return isinstance(x, float) and x.is_integer()


def _hex32(s):
    """Strict 32-byte hex decode — bytes.fromhex tolerates ASCII whitespace
    the browser verifier's regex rejects; identical bytes must get identical
    verdicts on every surface, so the strictest spelling wins."""
    if not isinstance(s, str):
        return None
    try:
        b = bytes.fromhex(s)
    except (TypeError, ValueError):
        return None
    if len(b) != 32 or b.hex() != s.lower():
        return None
    return b


_HEXANY_RE = re.compile(r"[0-9a-fA-F]+")


def _hexany(s):
    """transparency.hex_bytes without a length pin — contiguous hex of any
    even length. Extends-bridge material takes it: verify_extends calls
    hex_bytes unbounded, so the bridge fields must too."""
    if not isinstance(s, str) or not _HEXANY_RE.fullmatch(s):
        return None
    try:
        return bytes.fromhex(s)
    except (TypeError, ValueError):
        return None


_WS_COERCE = "".join(
    chr(c)
    for c in (
        [0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C, 0xA0]
        + list(range(0x1680, 0x200B))
        + [0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
    )
)


def _coerce_int(v):
    """transparency.coerce_int mirror: bools -> 0/1, floats truncate,
    whitespace-padded digit strings parse; anything else raises. Used where
    signed material is evaluated (extends), not schema-checked."""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError("not a finite number")
        return int(v)
    if isinstance(v, str):
        t = v.strip(_WS_COERCE)
        if t and re.fullmatch(r"[+-]?[0-9]+", t):
            return int(t)
    raise ValueError("not a coercible integer")


def _merkle_consistency(old_root, old_size, new_root, new_size, nodes):
    """RFC 6962 sec. 2.1.2 consistency-proof verification — the
    transparency.verify_consistency mirror, stdlib-only."""
    if not isinstance(nodes, list):
        return False  # a dict proof would iterate keys — never a proof
    if old_size > 2147483647 or new_size > 2147483647:
        return False
    if old_size == new_size:
        return nodes == [] and old_root == new_root
    if not (0 < old_size < new_size) or not nodes:
        return False
    path = list(nodes)
    # RFC 9162 sec. 2.1.4.2 step 2: a power-of-two older size omits the old
    # root itself — the verifier knows it, so it is prepended here.
    if old_size & (old_size - 1) == 0:
        path = [old_root] + path
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = hashlib.sha256(b"\\x01" + c + fr).digest()
            sr = hashlib.sha256(b"\\x01" + c + sr).digest()
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = hashlib.sha256(b"\\x01" + sr + c).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


def _extends_ok(payload):
    """transparency.verify_extends(payload) mirror — the checkpoint's
    self-contained continuity claim with no caller expectations. True/False
    when the embedded bridge resolves; None when absent or malformed (the
    head's own signature still authenticates, so callers treat None as
    absent rather than failed)."""
    ext = payload.get("extends")
    if not isinstance(ext, dict) or not isinstance(ext.get("proof"), list):
        return None
    try:
        ext_first = _coerce_int(ext["first"])
        ext_first_root = _hexany(ext["first_root_sha256"])
        size = _coerce_int(payload["tree_size"])
        root = _hexany(payload["root_sha256"])
        if ext_first_root is None or root is None:
            return None
        nodes = [_hexany(h) for h in ext["proof"]]
        if any(n is None for n in nodes):
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return _merkle_consistency(ext_first_root, ext_first, root, size, nodes)


def _merkle_inclusion(leaf_hex, size, index, path_hex, root_hex):
    """RFC 6962 audit-path verification, stdlib-only (see transparency.py)."""
    leaf = _hex32(leaf_hex)
    root_b = _hex32(root_hex)
    if leaf is None or root_b is None:
        return False
    if not isinstance(path_hex, list):
        return False  # a dict path would iterate keys — never a proof
    if not _is_int(size) or not _is_int(index):
        return False
    size, index = int(size), int(index)
    if index < 0 or index >= size or size < 1 or size > 2147483647:
        return False  # 2**31-1: the JS verifier's bitwise-op bound
    r = hashlib.sha256(b"\\x00" + leaf).digest()
    if size == 1:
        return not path_hex and r == root_b
    fn, sn = index, size - 1
    for ph in path_hex:
        p = _hex32(ph)
        if p is None or sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = hashlib.sha256(b"\\x01" + p + r).digest()
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = hashlib.sha256(b"\\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root_b


def check_log(pack_dir, trusted, receipts):
    """Verify the pack's transparency checkpoint: ``log_checkpoint.json``
    carries a signed Merkle Tree Head (a ``log_checkpoint`` receipt) plus an
    RFC 6962 inclusion path for every receipts-table member the pack holds —
    'this receipt was in the deployment's published log' becomes provable in
    O(log n) instead of trusting enumeration. Review-chain entries are not
    leaves: they anchor to the original's hash (verified by check_bundle), so
    the proven original transitively commits them. Absent → a pre-checkpoint
    pack, reported not failed; present → every listed receipt must carry a
    working proof, so a receipt never committed to the log fails closed.
    Returns (proven_count, tree_size) or None."""
    cp_path = Path(pack_dir) / "log_checkpoint.json"
    if not cp_path.is_file():
        return None
    try:
        doc = _loads(cp_path.read_text(encoding="utf-8"))
    except Exception:
        sys.exit("FAIL log_checkpoint.json: not readable JSON")
    cp = doc.get("checkpoint") if isinstance(doc, dict) else None
    proofs = doc.get("proofs") if isinstance(doc, dict) else None
    if not isinstance(cp, dict) or not isinstance(proofs, dict):
        sys.exit("FAIL log_checkpoint.json: malformed checkpoint document")
    payload = cp.get("payload")
    if not isinstance(payload, dict) or payload.get("record_type") != "log_checkpoint":
        sys.exit("FAIL log_checkpoint.json: not a log_checkpoint receipt")
    if cp.get("public_key") not in trusted:
        sys.exit("FAIL log_checkpoint.json: signed outside the trusted issuer chain")
    ok, why = check_receipt(cp, cp["public_key"])
    if not ok:
        sys.exit(f"FAIL log_checkpoint.json: {why}")
    size = payload.get("tree_size")
    root_hex = payload.get("root_sha256")
    if (
        not _is_int(size)
        or size < 1
        or size > 2147483647  # MAX_TREE_SIZE — JS bitwise-op bound
        or not isinstance(root_hex, str)
    ):
        sys.exit("FAIL log_checkpoint.json: malformed tree head")
    # The checkpoint's own signed continuity claim: a head whose embedded
    # bridge fails is attesting a history it cannot prove — verify_extends
    # self-check parity with the standalone checkpoint path (convicts
    # False, absent/malformed bridges pass through as None).
    if _extends_ok(payload) is False:
        sys.exit(
            "FAIL log_checkpoint.json: extends bridge attests a history it cannot prove"
        )
    proven = 0
    verified_ph = set()
    for r in receipts:
        ph = r.get("payload_hash") if isinstance(r, dict) else None
        # Only issuer-lineage receipts owe proofs: a foreign-signed pool
        # entry is inert (it can't join the trust walk) and never claimed
        # log membership — requiring its proof would let a graft kill packs.
        if not ph or r.get("public_key") not in trusted:
            continue
        # The checkpoint receipt IS the signed tree head — it cannot sit
        # inside its own tree, and needs no proof.
        if ph == cp.get("payload_hash"):
            continue
        p = proofs.get(ph)
        if not isinstance(p, dict):
            sys.exit(
                f"FAIL log_checkpoint.json: receipt {r.get('id') or ph[:16]} has no "
                "inclusion proof — never committed to the deployment log"
            )
        if not _merkle_inclusion(ph, size, p.get("leaf_index", -1), p.get("path") or [], root_hex):
            sys.exit(
                f"FAIL log_checkpoint.json: inclusion proof for receipt "
                f"{r.get('id') or ph[:16]} does not reach the signed tree head"
            )
        verified_ph.add(ph)
        proven += 1
    # Embedded evidence receipts (`attest checkpoint --include monitor:`):
    # each must verify under the issuer lineage AND carry a proof that
    # reaches the signed head — CLI _verify_log_doc parity, fail closed.
    embedded = doc.get("receipts")
    if embedded is not None:
        if not isinstance(embedded, list) or len(embedded) > 2048:
            sys.exit("FAIL log_checkpoint.json: 'receipts' must be a list of at most 2048")
        seen_ids = set()
        for raw in embedded:
            if not isinstance(raw, dict):
                sys.exit("FAIL log_checkpoint.json: embedded receipt malformed")
            rid = str(raw.get("id") or "?")
            if rid in seen_ids:
                sys.exit(f"FAIL log_checkpoint.json: embedded receipt {rid[:24]}… listed twice")
            seen_ids.add(rid)
            if raw.get("public_key") not in trusted:
                sys.exit(
                    f"FAIL log_checkpoint.json: embedded receipt {rid[:24]}… "
                    "signed outside the issuer lineage"
                )
            try:
                ok, why = check_receipt(raw, raw["public_key"])
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                sys.exit(
                    f"FAIL log_checkpoint.json: embedded receipt {rid[:24]}… malformed: {exc}"
                )
            if not ok:
                sys.exit(f"FAIL log_checkpoint.json: embedded receipt {rid[:24]}… invalid: {why}")
            p = proofs.get(raw.get("payload_hash"))
            if not isinstance(p, dict) or not _merkle_inclusion(
                raw.get("payload_hash"),
                size,
                p.get("leaf_index", -1),
                p.get("path") or [],
                root_hex,
            ):
                sys.exit(
                    f"FAIL log_checkpoint.json: embedded receipt {rid[:24]}… "
                    "carries no working inclusion proof"
                )
            verified_ph.add(raw.get("payload_hash"))
            proven += 1
    # CLI _verify_log_doc parity: every proofs entry must verify — a junk
    # entry referencing nothing is a lie, not decoration.
    for ph, p in proofs.items():
        if ph in verified_ph:
            continue
        if not isinstance(p, dict) or not _merkle_inclusion(
            ph, size, p.get("leaf_index", -1), p.get("path") or [], root_hex
        ):
            sys.exit(
                f"FAIL log_checkpoint.json: unreferenced inclusion proof for "
                f"{str(ph)[:16]}… does not reach the signed tree head"
            )
    cosigs, _ = _cosig_count(doc, cp, size, root_hex, issuer_keys=trusted)
    # Packed self-anchors: the witness's own signed head + the cosig's
    # inclusion path. Auxiliary like the cosig count — but a present one
    # that fails is a lie, not a downgrade (logmonitor parity).
    anchored = _cosig_anchors(doc)
    return proven, size, cosigs, anchored


def _cosig_anchors(doc):
    """Verify each ``cosig_anchors`` entry: an anchor only means 'inside
    the witness's own log' when its head is signed by the cosig's own
    signer, and the cosig's payload hash must reach that head. Present-
    and-broken is a lie indicator — exits FAIL like a bad proof."""
    anchors = doc.get("cosig_anchors")
    if not isinstance(anchors, dict):
        return 0
    cosigs = {}
    cosig_list = doc.get("cosignatures")
    for raw in cosig_list if isinstance(cosig_list, list) else []:
        if isinstance(raw, dict) and isinstance(raw.get("id"), str):
            cosigs.setdefault(raw["id"], raw)  # first-wins: the counting path counts the first id
    anchored = 0
    for cid, anchor in anchors.items():
        scid = str(cid)[:24]
        cosig = cosigs.get(cid)
        if cosig is None:
            sys.exit(f"FAIL log_checkpoint.json: cosig_anchors {scid}… "
                     "anchors a cosignature the doc doesn't carry")
        if not isinstance(anchor, dict):
            sys.exit(f"FAIL log_checkpoint.json: cosig_anchors {scid}… "
                     "anchor is not an object")
        acp = anchor.get("checkpoint")
        ap = (acp or {}).get("payload") if isinstance(acp, dict) else None
        if not isinstance(ap, dict) or ap.get("record_type") != "log_checkpoint":
            sys.exit(f"FAIL log_checkpoint.json: cosig_anchors {scid}… "
                     "anchor is not a log_checkpoint receipt")
        if (
            not isinstance(acp.get("public_key"), str)
            or not isinstance(cosig.get("public_key"), str)
            or acp["public_key"] != cosig["public_key"]
        ):
            sys.exit(f"FAIL log_checkpoint.json: cosig_anchors {scid}… "
                     "anchor head not signed by the cosig's own witness key")
        ok, why = check_receipt(acp, acp["public_key"])
        if not ok:
            sys.exit(f"FAIL log_checkpoint.json: cosig_anchors {scid}… {why}")
        asize = ap.get("tree_size")
        aroot = ap.get("root_sha256")
        aroot_b = _hex32(aroot)
        if not _is_int(asize) or asize < 1 or asize > 2147483647 or aroot_b is None:
            sys.exit(f"FAIL log_checkpoint.json: cosig_anchors {scid}… "
                     "anchor checkpoint carries a malformed tree head")
        proof = anchor.get("proof")
        if not isinstance(proof, dict):
            sys.exit(f"FAIL log_checkpoint.json: cosig_anchors {scid}… "
                     "anchor proof is not an object")
        if not _is_int(proof.get("leaf_index")) or not _merkle_inclusion(
            cosig.get("payload_hash"),
            asize,
            proof["leaf_index"],
            proof.get("path") or [],
            aroot,
        ):
            sys.exit(f"FAIL log_checkpoint.json: cosig_anchors {scid}… "
                     "the cosig does not reach the anchor's signed tree head")
        anchored += 1
    return anchored


def _cosig_count(doc, cp, size, root_hex, issuer_keys=None):
    """Count the checkpoint document's witness counter-signatures whose
    subject binds THIS head — each verified under its own signer's key;
    a cosig about a different head or one that fails its signature counts
    as absent, never as a verdict against the checkpoint. The count tracks
    INDEPENDENT witnesses: duplicate receipts count once, repeat cosigs
    from one signer count once, and a cosig from the issuer's own key
    lineage (self-vouching) never counts."""
    n, keys = 0, []
    self_keys = set(issuer_keys or ()) | {cp.get("public_key")}
    seen_ids, seen_keys = set(), set()
    cosig_list = doc.get("cosignatures")
    for raw in cosig_list if isinstance(cosig_list, list) else []:
        p = raw.get("payload") if isinstance(raw, dict) else None
        if not isinstance(p, dict) or p.get("record_type") != "witness_cosignature":
            continue
        if (
            p.get("subject_checkpoint") != cp.get("id")
            or not _is_int(p.get("subject_tree_size"))
            or p.get("subject_tree_size") != size
            or p.get("subject_root_sha256") != root_hex
        ):
            continue
        # The cosig must name THIS issuer — one attesting another
        # deployment's head never counts here (logmonitor parity). The
        # members below are set-membership tests: a crafted non-string
        # subject_issuer/id/public_key is unhashable and would TypeError,
        # so require strings before any `in` check.
        si = p.get("subject_issuer")
        if issuer_keys and (not isinstance(si, str) or si not in self_keys):
            continue
        pk = raw.get("public_key")
        if (
            not isinstance(raw.get("id"), str)
            or not isinstance(pk, str)
            or raw["id"] in seen_ids
            or pk in seen_keys
            or pk in self_keys
        ):
            continue
        try:
            ok, _why = check_receipt(raw, pk)
        except (KeyError, TypeError, ValueError, AttributeError):
            continue  # malformed envelope — it can't vouch, it just doesn't count
        if ok:
            seen_ids.add(raw["id"])
            seen_keys.add(pk)
            n += 1
            keys.append(pk)
    return n, keys


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
    data = _loads(marker.read_text(encoding="utf-8"))
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
    # A malformed visit entry must fail the comparison, never raise out of
    # the verifier — the unsigned manifest cannot name a trusted shape.
    listed = {
        v["visit_id"]: v["payload_hash"]
        for v in manifest.get("visits", [])
        if isinstance(v, dict) and "visit_id" in v and "payload_hash" in v
    }
    # Homogeneous types before comparing: JSON receipt_hashes is always
    # str->str, so a non-str listed key (JS stringifies int keys — 5 vs "5")
    # or a cross-type value (Python True==1 bridges where === never can)
    # must fail, not silently collide.
    if (
        not isinstance(signed_hashes, dict)
        or any(
            not isinstance(k, str) or not isinstance(h, str)
            for k, h in signed_hashes.items()
        )
        or any(
            not isinstance(k, str) or not isinstance(h, str) for k, h in listed.items()
        )
        or listed != signed_hashes
    ):
        return False, "manifest visit list disagrees with the signed export"
    return True, f"export signed: {len(listed)} record(s)"


def _adoption_consent(receipts, rotation, new_key):
    """Whether the SUCCESSOR key countersigned the rotation via a
    key_adoption receipt naming it (id + payload hash). A retiring key's
    endorsement is self-serve — any key can claim any successor — so consent
    is what separates a real handoff from a grafted "predecessor"."""
    for r in receipts:
        if not isinstance(r, dict):
            continue
        p = r.get("payload", {})
        if not isinstance(p, dict):
            continue
        link = p.get("rotation_receipt")
        if not isinstance(link, dict):
            link = {}
        if (
            p.get("record_type") == "key_adoption"
            and link.get("id") == rotation.get("id")
            and link.get("hash") == rotation.get("payload_hash")
            and r.get("public_key") == new_key
        ):
            try:
                ok, _ = check_receipt(r, new_key)
            except Exception:  # noqa: BLE001 — unverifiable material can't consent
                continue
            if ok:
                return True
    return False


def _ancestor_hop(key_receipts, cur):
    """The predecessor hop the main ledger picks for ancestor/root walks:
    EVERY consented rotation endorsing ``cur``, then min(previous_key) —
    the pool order is attacker-controlled, so only a key-ordered pick is
    deterministic across verifier surfaces."""
    cands = []
    for r in key_receipts:
        if not isinstance(r, dict):
            continue
        p = r.get("payload", {})
        if not isinstance(p, dict) or not isinstance(r.get("public_key"), str):
            continue
        if (
            p.get("record_type") == "key_rotation"
            and p.get("new_key") == cur
            and r.get("public_key") == p.get("previous_key")
            and isinstance(p.get("previous_key"), str)
        ):
            try:
                ok, _ = check_receipt(r, r["public_key"])
            except Exception:  # noqa: BLE001 — unverifiable can't hop
                continue
            if ok and _adoption_consent(key_receipts, r, cur):
                cands.append(p["previous_key"])
    return min(cands) if cands else None


def trusted_keys(issuer_key, rotation_receipts, max_hops=32):
    """The keys a pack verification may trust: the manifest issuer plus every
    ancestor reachable through signed key_rotation receipts. Each hop must be
    a valid receipt signed by the retiring key endorsing its successor AND
    countersigned by that successor via key_adoption — a forged or
    unconsented rotation never lands in the set."""
    trusted = {issuer_key}
    cur = issuer_key
    for _ in range(max_hops):
        nxt = _ancestor_hop(rotation_receipts, cur)
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
    is a dead branch, not a trusted descendant. Competing rotations resolve
    deterministically — the highest-sequence CONSENTED hop wins, matching
    the main verifier exactly."""
    trusted = {root_key}
    cur = root_key
    for _ in range(max_hops):
        cands = []
        for r in rotation_receipts:
            if not isinstance(r, dict):
                continue
            p = r.get("payload", {})
            if (
                not isinstance(p, dict)
                or not isinstance(p.get("new_key"), str)
                or not _is_int(r.get("sequence"))
            ):
                continue
            if (
                p.get("record_type") == "key_rotation"
                and p.get("previous_key") == cur
                and r.get("public_key") == cur
            ):
                try:
                    ok, _ = check_receipt(r, cur)
                except Exception:  # noqa: BLE001 — unverifiable can't hop
                    continue
                if ok:
                    cands.append(r)
        nxt = None
        for r in sorted(cands, key=lambda x: x["sequence"], reverse=True):
            if _adoption_consent(rotation_receipts, r, r["payload"]["new_key"]):
                nxt = r["payload"]["new_key"]
                break
        if nxt is None:
            break
        cur = nxt
        trusted.add(cur)
    return trusted


def _lineage_root(issuer_key, key_receipts):
    """The oldest ancestor the consented pivots reach from ``issuer_key`` —
    where a revocation-authority walk must seed. In a pack the receipt pool
    is attacker-controlled, so pool position can never confer authority:
    a self-signed key_revocation at sequence 0 must not make itself the
    root. Anchoring inside the verified lineage keeps that graft inert."""
    cur = issuer_key
    for _ in range(32):
        nxt = _ancestor_hop(key_receipts, cur)
        if nxt is None:
            break
        cur = nxt
    return cur


def revoked_keys(key_receipts, issuer_key=None):
    """Key -> suspect_after ISO for valid key_revocation receipts signed by
    the in-effect issuer at their position. Only the live key can revoke —
    a retired key revoking its successor would let a compromised key smear
    the healthy one, and position alone can't name the tip: a forged
    high-sequence revocation would make itself the tip and self-authorize.

    ``issuer_key`` anchors the walk at the lineage root — pass it always in
    pack verification, where the pool is attacker-controlled. A revocation
    also counts only for a key the lineage has already produced: a retired
    key smearing a successor that hasn't pivoted in yet is just as inert
    as a foreign key."""
    def _seq(r):
        s = r.get("sequence") if isinstance(r, dict) else None
        return int(s) if _is_int(s) else -1

    ordered = sorted(key_receipts, key=_seq)
    revoked = {}
    if issuer_key is not None:
        in_effect = _lineage_root(issuer_key, ordered)
    else:
        in_effect = None
    seen = {in_effect} if in_effect is not None else set()
    for r in ordered:
        if not isinstance(r, dict):
            continue
        try:
            ok, _ = check_receipt(r, in_effect or r.get("public_key"))
        except Exception:  # noqa: BLE001 — unverifiable material can't pivot
            continue
        if not ok:
            continue
        if in_effect is None:
            in_effect = r.get("public_key")
        seen.add(r.get("public_key"))
        p = r.get("payload", {})
        if (
            p.get("record_type") == "key_rotation"
            and p.get("previous_key") == in_effect
            and p.get("new_key")
            and _adoption_consent(ordered, r, p["new_key"])
        ):
            in_effect = p["new_key"]
            seen.add(in_effect)
            continue
        if (
            p.get("record_type") == "key_revocation"
            and isinstance(p.get("revoked_key"), str)
            and p["revoked_key"] in seen
            and r.get("public_key") == in_effect
        ):
            revoked[p["revoked_key"]] = p.get("suspect_after") or ""
    return revoked


def suspect_records(receipts, revoked):
    """Receipts signed by a revoked key inside its declared suspect window —
    cryptographically valid, annotated suspect. Integrity never depends on
    this; it's what a compromised key's history deserves."""
    from datetime import UTC, datetime

    def _instant(s):
        try:
            at = s if isinstance(s, datetime) else datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        # Naive spellings read as UTC: a forged or sloppy timestamp must not
        # crash the comparison, only compare conservatively.
        return at.replace(tzinfo=UTC) if at.tzinfo is None else at

    out = []
    for r in receipts:
        if not isinstance(r, dict):
            continue
        after = _instant(revoked.get(r.get("public_key"), ""))
        at = _instant(r.get("issued_at", ""))
        if after is not None and at is not None and at > after:
            out.append(r)
    return out


def load_issuer_doc(path):
    """Load an attest.issuer/1 discovery document — the file written by
    `attest issuer --out` or fetched from /.well-known/attest-issuer.json.
    Returns (issuer_key, key_receipts); anything else fails closed. The doc
    pins verification to a DEPLOYMENT rather than a key fingerprint, and its
    signed lifecycle receipts extend trust to packs exported before a
    rotation. Its authenticity is only as strong as how you got the file —
    --key remains the out-of-band pin."""
    try:
        doc = _loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        sys.exit(f"FAIL issuer document unreadable: {exc}")
    if (
        not isinstance(doc, dict)
        or doc.get("schema") != "attest.issuer/1"
        or not isinstance(doc.get("issuer_key"), str)
        or not doc["issuer_key"]
    ):
        sys.exit("FAIL issuer document is not attest.issuer/1")
    receipts = doc.get("key_receipts") or []
    if not isinstance(receipts, list):
        sys.exit("FAIL issuer document: key_receipts is not a list")
    # Same bound the CLI puts on the served document — the lineage walk is
    # one signature verification per candidate per hop.
    if len(receipts) > 64:
        sys.exit("FAIL issuer document: key_receipts exceeds the 64-entry bound")
    return doc["issuer_key"], receipts
'''

# verify_bundle.py — verifies one pack's bundle.json (and media/ next to it).
_BUNDLE_MAIN = """\
def main():
    args = sys.argv[1:]
    key = None
    issuer_receipts = []
    if "--key" in args:
        i = args.index("--key")
        if i + 1 >= len(args):
            sys.exit("FAIL --key requires a base64 public key value")
        key = args[i + 1]
        del args[i : i + 2]
    if "--issuer" in args:
        i = args.index("--issuer")
        if i + 1 >= len(args):
            sys.exit("FAIL --issuer requires an issuer-document path")
        if key is not None:
            sys.exit("FAIL pass --key or --issuer, not both")
        key, issuer_receipts = load_issuer_doc(args[i + 1])
        del args[i : i + 2]
    bundle = _loads(Path(args[0]).read_text(encoding="utf-8"))
    pack_dir = Path(args[0]).resolve().parent
    key = key or bundle["original"]["public_key"]
    # Reviews appended after a key rotation verify under the successor —
    # legitimate only through the signed rotation links in key_rotations.json
    # (or an --issuer document's own lifecycle receipts: they pin this bundle
    # to a DEPLOYMENT and bridge exports made before a rotation).
    # Revocation receipts ride the same file: the overlay annotates suspect
    # windows without touching the integrity verdict.
    trusted = {key}
    rotations = list(issuer_receipts)
    pack_lifecycle = []
    rot_path = pack_dir / "key_rotations.json"
    if rot_path.is_file():
        try:
            rj = _loads(rot_path.read_text(encoding="utf-8"))
            extra = rj.get("rotations") if isinstance(rj, dict) else None
        except Exception:
            extra = None
        if not isinstance(extra, list):
            sys.exit("FAIL key_rotations.json: malformed")
        rotations += extra
        pack_lifecycle = extra
    if rotations:
        trusted = trusted_keys(key, rotations) | descendant_keys(key, rotations)
    revoked = revoked_keys(rotations, key)
    ok, why, n = check_bundle(bundle, trusted)
    if not ok:
        sys.exit(f"FAIL {why}")
    try:
        withheld = redaction_for(bundle, pack_dir)
    except ValueError as exc:
        sys.exit(f"FAIL {exc}")
    checked, held, bad = check_media(bundle, pack_dir / "media", withheld)
    if bad:
        if str(bad).startswith("smuggled:"):
            sys.exit(f"FAIL media file not named by the signed evidence: {bad[9:]}")
        sys.exit(f"FAIL media digest not found in pack: {bad[:16]}...")
    # Fail closed on files the pack format doesn't name — the zip surfaces
    # sweep every member, so the extracted dir must too: a bare bundle.json +
    # evil.txt would otherwise pass where the same zip fails.
    allowed_top = {
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
    for p in sorted(pack_dir.iterdir()):
        if p.is_file() and p.name not in allowed_top:
            sys.exit(f"FAIL {p.name}: present but not part of the pack format")
        if p.is_dir() and p.name != "media":
            sys.exit(f"FAIL {p.name}/: directory not part of the pack format")
    pinned_tools = check_tools(pack_dir, trusted, f'visit:{bundle["original"]["visit_id"]}')
    # Transparency checkpoint: the log's leaves are the receipts-table chain
    # — originals, lifecycle, manifests. Review-chain entries anchor to the
    # original's hash (verified above) instead of sitting in the log, so the
    # proven original transitively commits them.
    logged = check_log(
        pack_dir,
        trusted,
        [bundle["original"]]
        + pack_lifecycle
        + ([_loads((pack_dir / "verifier_manifest.json").read_text(encoding="utf-8"))]
           if (pack_dir / "verifier_manifest.json").is_file() else []),
    )
    redact_note = f", {held} withheld by redaction" if held else ""
    print(f"OK: {n} receipt(s) verified; {checked} media digests matched{redact_note}.")
    if len(trusted) > 1:
        print(f"    ({len(trusted)} issuer keys linked via the signed rotation chain)")
    suspect = suspect_records(
        [bundle["original"]] + [e["receipt"] for e in bundle.get("reviews", [])], revoked)
    if suspect:
        print(f"    ({len(suspect)} record(s) signed by a revoked issuer inside its suspect window)")
    # A rotation signed by a key later declared suspect means the handoff
    # itself may be attacker-authored — the lineage carries the doubt.
    pivots = suspect_records(rotations, revoked)
    if pivots:
        print(f"    ({len(pivots)} key-lifecycle receipt(s) signed inside a suspect window —")
        print("     the trust pivot itself inherits the doubt)")
    if issuer_receipts:
        print(f"    (pinned via a deployment issuer document — {len(issuer_receipts)} "
              "lifecycle receipt(s); its authenticity rides on how it reached you)")
    if pinned_tools:
        print(f"    ({pinned_tools} verifier tool(s) pinned by issuer-signed manifest — "
              "the pack's own scripts are proven unmodified)")
    if logged:
        w = f" · cosigned by {logged[2]} witness(es)" if logged[2] else ""
        if logged[3]:
            w += f" ({logged[3]} anchored in the witness's own published log)"
        print(f"    ({logged[0]} receipt(s) proven inside the deployment's transparency"
              f" log at checkpoint size {logged[1]}{w})")
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
    issuer_receipts = []
    if "--key" in args:
        i = args.index("--key")
        if i + 1 >= len(args):
            sys.exit("FAIL --key requires a base64 public key value")
        key = args[i + 1]
        del args[i : i + 2]
    if "--issuer" in args:
        i = args.index("--issuer")
        if i + 1 >= len(args):
            sys.exit("FAIL --issuer requires an issuer-document path")
        if key is not None:
            sys.exit("FAIL pass --key or --issuer, not both")
        key, issuer_receipts = load_issuer_doc(args[i + 1])
        del args[i : i + 2]
    root = Path(args[0]) if args else Path(".")
    try:
        manifest = _loads((root / "manifest.json").read_text(encoding="utf-8"))
    except Exception as exc:
        sys.exit(f"FAIL manifest.json unreadable: {exc}")
    declared = manifest.get("issuer_key")
    if not declared:
        sys.exit("FAIL manifest: missing issuer_key")
    # The trusted issuer set: the manifest issuer plus every ancestor the
    # pack's signed key_rotation receipts endorse — post-rotation packs mix
    # keys legitimately. Rotation receipts that don't parse or don't verify
    # are ignored here and fail in the attestation loop below.
    rotations = list(issuer_receipts)
    attestations = manifest.get("attestations", [])
    if not isinstance(attestations, list):
        sys.exit("FAIL manifest: attestations is not a list")
    for a in attestations:
        rid = a.get("receipt_id") if isinstance(a, dict) else None
        if not isinstance(rid, str) or not rid or "/" in rid or chr(92) in rid or ".." in rid:
            continue  # a receipt_id that walks out of attestations/ is malformed
        try:
            r = _loads((root / "attestations" / f"{rid}.json").read_text(encoding="utf-8"))
        except Exception:
            continue
        if r.get("payload", {}).get("record_type") in ("key_rotation", "key_adoption", "key_revocation"):
            rotations.append(r)
    trusted = trusted_keys(declared, rotations)
    revoked = revoked_keys(rotations, declared)
    suspect_n = 0
    if key is not None and key not in trusted and key not in descendant_keys(declared, rotations):
        sys.exit(
            "FAIL manifest: issuer_key disagrees with the pinned --key/--issuer "
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
    # Every receipt the pack carries — the transparency checkpoint must prove
    # each one sat in the deployment's log, not merely verify its signature.
    log_receipts = []
    for v in visits:
        vid = v.get("visit_id") if isinstance(v, dict) else None
        if not isinstance(vid, str) or not vid or "/" in vid or chr(92) in vid or ".." in vid:
            # Same guard as attestation receipt_id: a visit_id that walks out
            # of visits/ would verify an unrelated on-disk bundle as a pack
            # member — an unsigned manifest cannot name a path.
            print(f"FAIL manifest: malformed visit_id {vid!r}")
            failed += 1
            continue
        if vid in listed_vids:
            # packdiff flags a duplicate listing — a vid that names the same
            # bundle twice double-counts on every surface, so all reject it
            print(f"FAIL manifest: visit_id {vid} listed twice")
            failed += 1
            continue
        listed_vids.add(vid)
        try:
            bundle = _loads((root / "visits" / vid / "bundle.json").read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"FAIL {vid}: bundle listed but missing or unreadable ({exc})")
            failed += 1
            continue
        ok, why, n = check_bundle(bundle, trusted)
        if not ok:
            print(f"FAIL {vid}: {why}")
            failed += 1
            continue
        log_receipts.append(bundle["original"])
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
        rid = a.get("receipt_id") if isinstance(a, dict) else None
        if not isinstance(rid, str) or not rid or "/" in rid or chr(92) in rid or ".." in rid:
            print(f"FAIL attestation: malformed receipt_id {rid!r}")
            failed += 1
            continue
        apath = root / "attestations" / f"{rid}.json"
        if not apath.exists():
            print(f"FAIL attestation {rid}: manifest lists it but the file is missing")
            failed += 1
            continue
        try:
            ar = _loads(apath.read_text(encoding="utf-8"))
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
        elif ar.get("id") != rid:
            print(f"FAIL attestation {rid}: filename disagrees with the signed receipt id")
            failed += 1
        elif ar["payload_hash"] != a.get("payload_hash") or ar["visit_id"] != a.get("visit_id"):
            print(f"FAIL attestation {rid}: disagrees with the signed manifest")
            failed += 1
        else:
            print(f"OK   attestation {a.get('record_type') or 'record'} ({rid[:20]}...)")
            log_receipts.append(ar)
    adir = root / "attestations"
    if adir.exists():
        # Any member that isn't exactly a listed "<receipt_id>.json" file is
        # smuggled — non-.json files and whole subdirectories too, so sweep
        # every member rather than glob("*.json").
        listed = {
            f"{a.get('receipt_id')}.json"
            for a in attestations
            if isinstance(a, dict) and a.get("receipt_id")
        }
        for p in sorted(adir.iterdir()):
            if p.is_file() and p.name not in listed:
                print(f"FAIL attestations/{p.name}: present but not in the signed manifest")
                failed += 1
            elif p.is_dir():
                print(f"FAIL attestations/{p.name}/: directory not in the signed manifest")
                failed += 1
    vdir = root / "visits"
    if vdir.exists():
        # Plain files directly under visits/ are smuggled members too — only
        # directories named for a listed visit_id are legal.
        for p in sorted(vdir.iterdir()):
            if p.is_dir() and p.name not in listed_vids:
                print(f"FAIL visits/{p.name}/: directory not in the signed manifest")
                failed += 1
            elif p.is_file():
                print(f"FAIL visits/{p.name}: present but not in the signed manifest")
                failed += 1
    # Fail closed on any file the pack format doesn't name — a smuggled
    # top-level file or extra member inside a visit dir would otherwise ride
    # inside a "VERIFIED" pack. Media members are digest-checked by
    # check_media against the signed evidence.
    allowed_top = {
        "manifest.json",
        "README.txt",
        "verify_case.py",
        "verify.html",
        "index.html",
        "verifier_manifest.json",
        "log_checkpoint.json",
    }
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
    _site = manifest.get("site")
    # A non-dict site (e.g. 5) has no .get — the browser computes "site:"
    # for the same input, so degrade to "" rather than crash.
    site_id = (_site.get("id") if isinstance(_site, dict) else None) or ""
    pinned_tools = check_tools(root, trusted, f"site:{site_id}")
    sr = manifest.get("signature_receipt")
    if isinstance(sr, dict):
        log_receipts.append(sr)
    if (root / "verifier_manifest.json").is_file():
        try:
            log_receipts.append(
                _loads((root / "verifier_manifest.json").read_text(encoding="utf-8")))
        except Exception:
            pass  # a malformed pin already failed in check_tools
    logged = check_log(root, trusted, log_receipts)
    if failed:
        sys.exit(f"{failed} record(s) failed verification")
    print(f"OK: {len(visits)} visit records verified under issuer key")
    print(f"    {key[:16]}...")
    if pinned_tools:
        print(f"    ({pinned_tools} verifier tool(s) pinned by issuer-signed manifest — "
              "the pack's own scripts are proven unmodified)")
    if logged:
        w = f" · cosigned by {logged[2]} witness(es)" if logged[2] else ""
        if logged[3]:
            w += f" ({logged[3]} anchored in the witness's own published log)"
        print(f"    ({logged[0]} receipt(s) proven inside the deployment's transparency"
              f" log at checkpoint size {logged[1]}{w})")
    if len(trusted) > 1:
        # The pack spans a signed key rotation — the lineage is the pivot, not
        # a weaker check; say so plainly rather than hiding it behind one key.
        print(f"    ({len(trusted)} issuer keys linked via the signed rotation chain)")
    if suspect_n:
        print(f"    ({suspect_n} record(s) signed by a revoked issuer inside its suspect window)")
    # A rotation/adoption signed by a key later declared suspect means the
    # handoff itself may be attacker-authored — the lineage carries the doubt.
    pivots = len(suspect_records(rotations, revoked))
    if pivots:
        print(f"    ({pivots} key-lifecycle receipt(s) signed inside a suspect window —")
        print("     the trust pivot itself inherits the doubt)")
    if issuer_receipts:
        print(f"    (pinned to the deployment's issuer document — {len(issuer_receipts)} "
              "lifecycle receipt(s) extended the lineage; the pin's authenticity")
        print("     rides on how that document reached you)")
    elif declared == key and "--key" not in sys.argv:
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
verifier_manifest.json  A signed receipt pinning the sha256 of every verifier
                    shipped in this pack. A forged pack that doctors its own
                    verifier to print VERIFIED is caught — only the
                    deployment's key can sign the real manifest.
log_checkpoint.json   Present when the deployment publishes a transparency
                    log: a signed Merkle tree head plus an inclusion proof
                    for every issuer-signed receipt in this pack — evidence
                    that these records were committed to the deployment's
                    published append-only log.

WHAT A VALID VERIFICATION PROVES
- Each bundle.json is byte-identical to what was signed, and every appended
  review is hash-anchored to its original receipt.
- manifest.json's receipt hashes match the signed originals — the case summary
  cannot quietly describe different records than the signed ones.
- If log_checkpoint.json is present, every issuer-signed receipt in the pack
  proves inclusion in the deployment's transparency log at the checkpoint's
  committed size — a valid signature on an uncommitted receipt still fails.
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
    tools_receipt_fn=None,
    log_fn=None,
) -> bytes:
    """Assemble the zip. Media is matched to evidence digests, not filenames.
    With ``redact_media`` the bytes are withheld and a redaction.json marker is
    written — the signed digests stay verifiable, the footage stays private.
    ``tools_receipt_fn`` receives the sha256 map of the pack's verifier tooling
    and returns a signed ``verifier_manifest`` receipt — the pin that proves
    the pack's own scripts are byte-identical to what the issuer shipped."""
    from .verifyjs import VERIFY_HTML, case_index_html

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        bundle_text = bundle.model_dump_json(indent=2)
        # Rotation receipts the review chain may span — a review appended
        # after a key rotation verifies under the successor, and this member
        # is the signed link that makes that legitimate instead of "different
        # key". Only written when rotations exist.
        rotations = [r.model_dump(mode="json") for r in store.receipts() if r.visit_id.startswith("key:")]
        from datetime import UTC, datetime

        index_html = case_index_html(
            {
                "schema": "attest.dispute-pack/1",
                "site": bundle.original.payload.get("site") or {},
                "generated_at": datetime.now(tz=UTC).isoformat(),
                "issuer_key": bundle.original.public_key,
                "media_redacted": redact_media,
            },
            [(bundle.original.visit_id, bundle_text)],
            attestations=[(r["id"], json.dumps(r, indent=2, ensure_ascii=False)) for r in rotations],
        )
        z.writestr("bundle.json", bundle_text)
        z.writestr("README.txt", _README)
        z.writestr("verify_bundle.py", _VERIFIER)
        z.writestr("verify.html", VERIFY_HTML)
        z.writestr("index.html", index_html)
        vm_receipt = None
        if tools_receipt_fn is not None:
            tools = {
                name: hashlib.sha256(body.encode()).hexdigest()
                for name, body in {
                    "verify_bundle.py": _VERIFIER,
                    "verify.html": VERIFY_HTML,
                    "index.html": index_html,
                    "README.txt": _README,
                }.items()
            }
            vm_receipt = tools_receipt_fn(tools)
            if vm_receipt is not None:
                z.writestr("verifier_manifest.json", vm_receipt.model_dump_json(indent=2))
        if log_fn is not None:
            rot_receipts = [r for r in store.receipts() if r.visit_id.startswith("key:")]
            doc = log_fn([bundle.original] + rot_receipts + ([vm_receipt] if vm_receipt is not None else []))
            if doc is not None:
                z.writestr("log_checkpoint.json", json.dumps(doc, indent=2, ensure_ascii=False))
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


def _newest_issuer_key(entries, attestations) -> str | None:
    """The lineage tip to declare when no issuer_key is given: the signer of
    the newest packed receipt. Verifiers trust ancestors OF the declared key,
    so the declaration must sit at the live end of the rotation chain. Order
    by ``sequence`` — the chain's own position, which cannot regress — never
    the signed wall-clock claim: a stepped-back clock could otherwise declare
    a retired key while successor-signed records ride in the same pack, and
    the whole export then fails verification for honest bytes."""
    newest = None
    for receipt in (
        [e[1].original for e in entries]
        + [r.receipt for e in entries for r in e[1].reviews]
        + list(attestations)
    ):
        if newest is None or receipt.sequence > newest.sequence:
            newest = receipt
    return newest.public_key if newest is not None else None


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
    tools_receipt_fn=None,
    log_fn=None,
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
        or r.visit_id.startswith("monitor:")
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
        # a retired key has no ancestors to walk to. With no explicit issuer
        # the tip is the newest packed receipt's signer — the key still live
        # at export time.
        "issuer_key": issuer_key or _newest_issuer_key(entries, attestations),
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
    index_html = case_index_html(
        {
            "site": manifest["site"],
            "generated_at": manifest["generated_at"],
            "issuer_key": manifest["issuer_key"],
            "media_redacted": redact_media,
        },
        bundle_texts,
        manifest_text,
        attestations=[(r.id, r.model_dump_json(indent=2)) for r in attestations],
    )
    # The verifier_manifest receipt pins the tooling BYTES — it can't ride in
    # the manifest (index.html embeds the manifest, a circularity), so it is a
    # signed member of its own, issued after every pinned byte exists.
    vm = None
    if tools_receipt_fn is not None:
        tools = {
            name: hashlib.sha256(body.encode()).hexdigest()
            for name, body in {
                "verify_case.py": _CASE_VERIFIER,
                "verify.html": VERIFY_HTML,
                "index.html": index_html,
                "README.txt": _CASE_README,
            }.items()
        }
        vm = tools_receipt_fn(tools)
    # The transparency checkpoint is issued LAST among signed members: its
    # tree must already contain the export manifest and the tool pin for
    # their inclusion proofs to exist.
    log_doc = None
    if log_fn is not None:
        mrcpt = manifest.get("signature_receipt")
        log_doc = log_fn(
            list(attestations)
            + [b.original for _, b, _ in entries]
            + ([Receipt.model_validate(mrcpt)] if isinstance(mrcpt, dict) else [])
            + ([vm] if vm is not None else [])
        )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", manifest_text)
        z.writestr("README.txt", _CASE_README)
        z.writestr("verify_case.py", _CASE_VERIFIER)
        z.writestr("verify.html", VERIFY_HTML)
        z.writestr("index.html", index_html)
        if vm is not None:
            z.writestr("verifier_manifest.json", vm.model_dump_json(indent=2))
        if log_doc is not None:
            z.writestr("log_checkpoint.json", json.dumps(log_doc, indent=2, ensure_ascii=False))
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


TAMPER_ATTACKS = ("duration", "missing-record", "smuggled-file", "forged-verifier")


def tamper_twin(pack: bytes, attack: str = "duration", visit: str | None = None) -> tuple[bytes, str]:
    """A hostile copy of a pack: byte-identical except one deliberate attack,
    so the copy must FAIL verification. Each ``attack`` exercises a different
    verification layer — ``duration`` doctors a signed payload field,
    ``missing-record`` deletes a record the manifest commits to,
    ``smuggled-file`` injects a member no signed content names, and
    ``forged-verifier`` swaps the embedded checker for an always-green stub.
    ``visit`` names the record the ``duration`` attack doctors — default is
    the bundle with the shortest observed stay; passing the contested visit
    makes the twin hit the record the story is about.
    Used for demos and verifier QA — ``export --tamper-twin`` writes one, and
    the ``docs/sample-pack-*`` twins are built this way.
    Returns ``(zip_bytes, description_of_the_attack)``."""
    if attack not in TAMPER_ATTACKS:
        raise ValueError(f"unknown attack {attack!r} — pick one of {', '.join(TAMPER_ATTACKS)}")
    with zipfile.ZipFile(io.BytesIO(pack)) as src:
        names = src.namelist()
        bundles = sorted(
            n
            for n in names
            if n == "bundle.json"
            or (n.startswith("visits/") and n.endswith("/bundle.json") and n.count("/") == 2)
        )
        mutated: dict[str, bytes] = {}
        added: dict[str, bytes] = {}
        dropped: set[str] = set()
        desc = ""

        if attack == "duration":
            # The demo story: the *shortest* recorded stay inflated toward the
            # scheduled expectation — "she was there most of the window". Older
            # packs carry `duration_minutes`; the eight-day demo story instead
            # signs `observed_span_minutes` (first→last camera observation),
            # so doctor whichever numeric stay-field exists.
            best: tuple[float, str, bytes, bytes, int, int, bytes] | None = None
            ordered = (
                [f"visits/{visit}/bundle.json"]
                if visit and f"visits/{visit}/bundle.json" in bundles
                else bundles
            )
            for field in (b'"duration_minutes": ', b'"observed_span_minutes": '):
                if best is not None:
                    break
                for name in ordered:
                    raw = src.read(name)
                    i = raw.find(field)
                    if i < 0:
                        continue
                    j = i + len(field)
                    k = j
                    while k < len(raw) and raw[k] in b"0123456789.-":
                        k += 1
                    try:
                        val = float(raw[j:k])
                    except ValueError:
                        continue
                    if best is None or (visit is None and val < best[0]):
                        best = (val, name, raw, raw[j:k], j, k, field)
            if best is not None:
                val, name, raw, span, j, k, field = best
                new = repr(val + 70.0)
                mutated[name] = raw[:j] + new.encode() + raw[k:]
                vid = name.split("/")[1] if "/" in name else "bundle"
                fname = field.decode().strip('": ')
                desc = f"{vid}: {fname} {span.decode()} -> {new}"
            else:
                for name in ordered:
                    raw = src.read(name)
                    wmark = b'"worker": "'
                    i = raw.find(wmark)
                    if i < 0:
                        continue
                    j = i + len(wmark)
                    k = raw.find(b'"', j)
                    worker = raw[j:k].decode()
                    new = worker[:-1] + ("X" if not worker.endswith("X") else "Y")
                    mutated[name] = raw[:j] + new.encode() + raw[k:]
                    vid = name.split("/")[1] if "/" in name else "bundle"
                    desc = f"{vid}: worker '{worker}' -> '{new}'"
                    break
                if not mutated:
                    raise ValueError("no doctorable field found in any visit bundle")
        elif attack == "missing-record":
            if not bundles:
                raise ValueError("no visit bundle to delete")
            dropped.add(bundles[0])
            vid = bundles[0].split("/")[1] if "/" in bundles[0] else "bundle"
            desc = f"{vid}: record deleted — the signed manifest still commits to its receipt"
        elif attack == "smuggled-file":
            if not bundles:
                raise ValueError("no visit bundle to smuggle beside")
            vid = bundles[0].split("/")[1] if "/" in bundles[0] else ""
            member = f"visits/{vid}/extra-evidence.json" if vid else "extra-evidence.json"
            added[member] = b'{"planted": true, "note": "injected after signing"}\n'
            desc = f"{member} injected — a member no signed content commits to"
        else:  # forged-verifier
            tool = next((t for t in ("verify_case.py", "verify_bundle.py") if t in names), None)
            if tool is None:
                raise ValueError("pack carries no embedded verifier to forge")
            mutated[tool] = b'import sys\nprint("VERIFIED - nothing was checked")\nsys.exit(0)\n'
            desc = f"{tool} replaced with an always-green stub — the tooling pin names its bytes"

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
            for n in names:
                if n in dropped:
                    continue
                dst.writestr(n, mutated.get(n) or src.read(n))
            for n, data in added.items():
                dst.writestr(n, data)
    return buf.getvalue(), desc


def log_member(engine, receipts, cosign_fn=None) -> dict:
    """Build ``log_checkpoint.json`` for an export: a signed Merkle Tree Head
    over the deployment's whole receipt log plus an RFC 6962 inclusion path
    for every receipt this pack carries. Issuing the checkpoint must run
    *after* the pack's other signed members (export manifest, tool pin) so
    they are inside the tree; the checkpoint receipt itself is the tree head
    and by definition postdates it — the one member that carries no proof.
    Proofs are computed against the tree AT the checkpoint's size — the
    checkpoint's own append grows the tree past its STH, so paths against
    the grown tree would not reach the signed root. ``cosign_fn`` is called
    with the fresh checkpoint to collect witness counter-signatures — it
    returns ``(cosigs, anchors)`` where anchors maps each cosig's id to the
    witness's self-anchor (its own signed head + the cosig's inclusion
    proof), so the pack proves the attestation was committed to the
    witness's published log, not just signed and handed over."""
    cp = engine.issue_log_checkpoint()
    n = cp.payload["tree_size"]
    # One leaf-list build for every proof — per-receipt log_leaves() calls
    # would rescan the whole receipts table O(n²) times on a large export.
    from .transparency import inclusion_path

    leaves = engine.log_leaves()[:n]
    proofs = {}
    for r in receipts:
        try:
            idx = leaves.index(bytes.fromhex(r.payload_hash))
        except ValueError:
            continue  # not inside the committed tree — the pack fails verification
        proofs[r.payload_hash] = {
            "leaf_index": idx,
            "path": [p.hex() for p in inclusion_path(leaves, idx)],
        }
    doc = {
        "schema": "attest.log-checkpoint/1",
        "checkpoint": cp.model_dump(mode="json"),
        "proofs": proofs,
    }
    if cosign_fn:
        cosigs, anchors = cosign_fn(cp)
        if cosigs:
            doc["cosignatures"] = cosigs
        if anchors:
            doc["cosig_anchors"] = anchors
    return doc


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
