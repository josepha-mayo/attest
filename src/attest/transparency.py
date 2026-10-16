"""Merkle transparency log over the receipt chain (RFC 6962 §2.1 semantics).

The receipt chain proves *order and continuity* — every receipt links its
predecessor's payload hash — but two questions remain enumerative: "is this
receipt actually in the deployment's log?" and "is this new state a strict
extension of the one I saw before?". A Merkle tree over the ordered payload
hashes answers both in O(log n):

- ``root(leaves)`` — the Merkle Tree Head (MTH), the signed tree head (STH)
  a ``log_checkpoint`` receipt commits to.
- ``inclusion_path`` / ``verify_inclusion`` — a compact audit path proving a
  single receipt sits inside the committed log without replaying the chain.
- ``consistency_nodes`` / ``verify_consistency`` — a proof that the tree at
  size ``n`` contains every leaf the tree at size ``m < n`` contained,
  unchanged and in the same order — "append-only" as a cryptographic claim
  rather than a promise a verifier must re-enumerate.

Leaf input is the receipt's ``payload_hash`` (raw bytes, not hex) — the leaf
commits to exactly the digest the issuer already signed. Domain separation
follows RFC 6962: leaves hash with a 0x00 prefix, interior nodes with 0x01,
so a leaf can never collide with an interior node.

This proves membership and append-only inside one log. It does not prevent a
deployer from keeping two divergent logs (split-view) — that is what the
external anchors (S3 object custody, OpenTimestamps notarization) bound: a
fork must still be published in public time.
"""

from __future__ import annotations

import hashlib
import json
import re

_LEAF = b"\x00"
_NODE = b"\x01"
_EMPTY_ROOT = hashlib.sha256(b"").digest()

# The largest tree size any verifier surface will process: the browser
# verifier's proof arithmetic uses 32-bit bitwise ops (fn >>= 1), exact
# only below 2**31 — a signed head claiming a bigger tree would verify
# in Python and miscompute in JS, one payload two verdicts. 2**31 - 1
# receipts is ~2 billion, far beyond any real deployment; a head beyond
# it is malformed on every surface identically.
MAX_TREE_SIZE = 0x7FFFFFFF

# A real consistency/inclusion path for a 2^31-1-leaf tree needs at most
# ~62 hashes; 64 bounds it with headroom. Enforced pre-decode so a body
# carrying a quarter-million hex strings can't spin the verifier on an
# allocation the Merkle walk would reject at node ~32 anyway.
MAX_PROOF_NODES = 64

_STRICT_HEX = re.compile(r"[0-9a-fA-F]+")


def json_loads(s):
    """``json.loads`` minus the bare ``NaN``/``Infinity``/``-Infinity``
    literals — CPython accepts them but neither the browser parser nor a
    strict reader does, so a signed payload spelling ``NaN`` could hash-
    verify here and fail to parse there. ``parse_constant`` is the only
    gate those three tokens flow through."""
    return json.loads(
        s,
        parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"non-JSON literal: {x}")),
    )


def json_is_int(v) -> bool:
    """The JSON-integer check every verifier surface can agree on.

    ``Number.isInteger(5.0)`` is true — after ``JSON.parse`` the spelling
    ``5.0`` is indistinguishable from ``5``, so the browser verifier CANNOT
    reject integral floats; for the same bytes to get the same verdict,
    Python must accept them too. Bools stay out on both surfaces
    (``isinstance(True, float)`` is False, ``Number.isInteger(true)`` is
    false)."""
    return (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, float) and v.is_integer())


# ASCII digits only — Python's \d accepts Unicode digits (int("٥") == 5)
# where the JS mirror's \d does not; one signed string, two verdicts.
# Whitespace is the JS-\s ∩ int()-strippable intersection: JS \s adds
# ﻿ (which int() won't strip) and Python \s adds \x1c-\x1f/\x85 (which
# JS \s won't match) — spelling the class out pins both sides identical.
_COERCIBLE_INT = re.compile(
    r"[ \t\n\r\x0b\f\xa0\u1680-\u200a\u2028\u2029\u202f\u205f\u3000]*[+-]?[0-9]+"
    r"[ \t\n\r\x0b\f\xa0\u1680-\u200a\u2028\u2029\u202f\u205f\u3000]*"
)


def coerce_int(v) -> int:
    """``int()`` with the JS mirror's exact acceptance — used where signed
    material is *evaluated* rather than schema-checked (``verify_extends``):
    numbers truncate (``Math.trunc``), bools become 0/1, digit strings
    (signed, whitespace-padded) parse; anything else raises. Python's bare
    ``int()`` is looser on strings (``"5_0"`` parses) and explodes on
    inf — both would diverge from the browser path."""
    import math

    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        if not math.isfinite(v):
            raise ValueError("not a finite number")
        return int(v)
    if isinstance(v, str) and _COERCIBLE_INT.fullmatch(v):
        # Significant digits decide the bound: int()'s ~4300-digit ceiling
        # counts zero-padding where parseInt does not — "0"*5000 must read 0
        # here like it does in the browser, not saturate.
        s = v.strip()
        neg = s[:1] == "-"
        digits = s.lstrip("+-").lstrip("0")
        if not digits:
            return 0
        try:
            return -int(digits) if neg else int(digits)
        except ValueError:
            # CPython's int() refuses strings past ~4300 digits while the
            # JS mirror's parseInt saturates to Infinity — every downstream
            # gate rejects Infinity as "not an integer". Saturate here the
            # same way: an absurd-but-parseable size must convict on all
            # surfaces, not read as unparseable/absent on some.
            return -(MAX_TREE_SIZE + 1) if neg else MAX_TREE_SIZE + 1
    raise ValueError("not a coercible integer")


def hex_bytes(s, *, length: int | None = None) -> bytes:
    """``bytes.fromhex`` at the JS verifier's strictness: contiguous hex only.

    Python's ``fromhex`` silently skips ASCII whitespace, so a spaced
    spelling (``"aa bb…"``) decodes here while the browser verifier's regex
    rejects it — one signed payload, two verdicts. Every served/packed hex
    field on every surface must spell the same way, so whitespace is
    rejected rather than skipped."""
    if not isinstance(s, str) or not _STRICT_HEX.fullmatch(s):
        raise ValueError("not contiguous hex")
    b = bytes.fromhex(s)
    if length is not None and len(b) != length:
        raise ValueError(f"hex decodes to {len(b)} bytes, expected {length}")
    return b


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE + left + right).digest()


def root(leaves: list[bytes]) -> bytes:
    """RFC 6962 MTH: k = largest power of two < n, split there."""
    n = len(leaves)
    if n == 0:
        return _EMPTY_ROOT
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_pow2_lt(n)
    return _node_hash(root(leaves[:k]), root(leaves[k:]))


def _mth_of_hashes(leaf_hashes: list[bytes]) -> bytes:
    """MTH given pre-hashed leaves (internal — proofs carry sibling hashes)."""
    n = len(leaf_hashes)
    if n == 0:
        return _EMPTY_ROOT
    if n == 1:
        return leaf_hashes[0]
    k = _largest_pow2_lt(n)
    return _node_hash(_mth_of_hashes(leaf_hashes[:k]), _mth_of_hashes(leaf_hashes[k:]))


def inclusion_path(leaves: list[bytes], index: int) -> list[bytes]:
    """RFC 6962 §2.1.1 audit path for leaf ``index`` in the tree over ``leaves``."""
    return _path_hashes(leaves, index)


def _path_hashes(leaves: list[bytes], index: int) -> list[bytes]:
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(index)
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if index < k:
        return _path_hashes(leaves[:k], index) + [_mth_of_hashes([leaf_hash(d) for d in leaves[k:]])]
    return _path_hashes(leaves[k:], index - k) + [_mth_of_hashes([leaf_hash(d) for d in leaves[:k]])]


def verify_inclusion(
    leaf_data: bytes, tree_size: int, leaf_index: int, path: list[bytes], expected_root: bytes
) -> bool:
    """RFC 6962 §2.1.1 audit-path verification."""
    if not isinstance(path, (list, tuple)) or len(path) > MAX_PROOF_NODES:
        # a dict "path" would iterate keys — a non-list shape never proves;
        # over-bound is malformed, not just slow
        return False
    if (
        not isinstance(tree_size, int)
        or isinstance(tree_size, bool)
        or not isinstance(leaf_index, int)
        or isinstance(leaf_index, bool)
    ):
        return False  # callers gate via json_is_int — a float reaching the
        # bitwise walk must never silently alias an integer step
    if leaf_index >= tree_size or leaf_index < 0 or tree_size < 1 or tree_size > MAX_TREE_SIZE:
        return False
    if tree_size == 1:
        return path == [] and leaf_hash(leaf_data) == expected_root
    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash(leaf_data)
    for p in path:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = _node_hash(p, r)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root


def consistency_nodes(leaves: list[bytes], old_size: int) -> list[bytes]:
    """RFC 6962 §2.1.2 proof that ``leaves[:old_size]`` prefixes ``leaves``.

    ``leaves`` is the full (newer) tree; ``old_size`` is the size of the
    older tree being proved consistent. Equal sizes prove root equality.
    """
    n = len(leaves)
    if not 0 < old_size <= n:
        raise IndexError(old_size)
    if old_size == n:
        return []
    return _subproof(leaves, old_size, n, True)


def _subproof(leaves: list[bytes], m: int, n: int, exact: bool) -> list[bytes]:
    """SUBPROOF(m, D[n], exact) from RFC 6962 §2.1.2."""
    if m == n:
        return [] if exact else [_mth_of_hashes([leaf_hash(d) for d in leaves[:m]])]
    k = _largest_pow2_lt(n)
    if m <= k:
        return _subproof(leaves[:k], m, k, exact) + [_mth_of_hashes([leaf_hash(d) for d in leaves[k:n]])]
    return _subproof(leaves[k:], m - k, n - k, False) + [_mth_of_hashes([leaf_hash(d) for d in leaves[:k]])]


def verify_consistency(
    old_root: bytes,
    old_size: int,
    new_root: bytes,
    new_size: int,
    proof: list[bytes],
) -> bool:
    """RFC 6962 §2.1.2 consistency-proof verification."""
    if old_size > MAX_TREE_SIZE or new_size > MAX_TREE_SIZE:
        return False
    if not isinstance(proof, (list, tuple)) or len(proof) > MAX_PROOF_NODES:
        return False
    if (
        not isinstance(old_size, int)
        or isinstance(old_size, bool)
        or not isinstance(new_size, int)
        or isinstance(new_size, bool)
    ):
        return False  # callers gate via json_is_int; a float/str reaching
        # here must never alias into a proof step's bitwise arithmetic
    if old_size == new_size:
        # size 0 is not a head — equal sizes still require a live tree
        return old_size >= 1 and proof == [] and old_root == new_root
    if not 0 < old_size < new_size or not proof:
        return False
    path = list(proof)
    # RFC 9162 §2.1.4.2 step 2: when the older size is an exact power of
    # two the minimal proof omits the old root itself — the verifier
    # knows it, so it is prepended.
    if old_size & (old_size - 1) == 0:
        path = [old_root] + path
    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = path[0]
    sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = _node_hash(c, fr)
            sr = _node_hash(c, sr)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = _node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


def leaf_hashes(receipts) -> list[bytes]:
    """Ordered ``payload_hash`` bytes of every non-checkpoint receipt —
    the transparency log's leaf input in committed (sequence) order."""
    return [
        bytes.fromhex(r.payload_hash) for r in receipts if r.payload.get("record_type") != "log_checkpoint"
    ]


def inclusion_proof(leaves: list[bytes], payload_hash: str, *, size: int | None = None) -> dict | None:
    """Wire-format audit path proving ``payload_hash`` sits in the tree.

    ``size`` bounds the proof to the tree a signed checkpoint committed
    to — receipts appended after that head have no proof under it."""
    size = len(leaves) if size is None else size
    if size > len(leaves):
        # never emit a doc claiming a head the caller doesn't have the
        # leaves for — the emitted tree_size could never verify
        return None
    leaves = leaves[:size]
    try:
        index = leaves.index(bytes.fromhex(payload_hash))
    except ValueError:
        return None  # never committed (or a checkpoint — not a leaf)
    return {
        "tree_size": size,
        "leaf_index": index,
        "leaf": payload_hash,
        "path": [p.hex() for p in inclusion_path(leaves, index)],
    }


def consistency_proof(leaves: list[bytes], old_size: int, size: int | None = None) -> dict | None:
    """Wire-format node list proving the tree extends ``old_size`` leaves,
    bounded at ``size`` — a monitor holds a checkpoint at a size BEHIND the
    live tip, so the bridge must close on the checkpoint's tree, not the
    newest one."""
    size = len(leaves) if size is None else size
    if not 0 < old_size <= size <= len(leaves):
        return None
    return {
        "tree_size": size,
        "first": old_size,
        "proof": [p.hex() for p in consistency_nodes(leaves[:size], old_size)],
    }


def verify_extends(
    payload: dict,
    first: int | None = None,
    first_root: bytes | None = None,
) -> bool | None:
    """Verify the ``extends`` bridge a checkpoint embeds in its signed
    payload, if present — the issuer's own attestation that this head
    provably extends the previous one it names.

    Returns ``True``/``False`` when an applicable bridge resolves, ``None``
    when no usable bridge applies — the payload carries none (a pre-
    chaining checkpoint), the bridge is malformed, or it bridges a
    different starting size than the caller asks about (``first`` given,
    ``extends.first`` differs — that checkpoint bridges some other
    ancestry and proves nothing about ours). ``first_root`` pins the
    earlier head the bridge must start from: a checkpoint claiming to
    bridge from the caller's expected root but starting elsewhere is a
    ``False`` — the signed payload itself attests a different history.
    Malformed bridge material counts as absent — the head itself still
    authenticates; only the self-contained continuity claim is lost, and
    callers fall back to the serving API's consistency endpoint.
    """
    ext = payload.get("extends")
    if (
        not isinstance(ext, dict)
        or not isinstance(ext.get("proof"), list)
        or len(ext["proof"]) > MAX_PROOF_NODES
    ):
        return None
    try:
        ext_first = coerce_int(ext["first"])
        ext_first_root = hex_bytes(ext["first_root_sha256"])
        size = coerce_int(payload["tree_size"])
        root = hex_bytes(payload["root_sha256"])
        nodes = [hex_bytes(h) for h in ext["proof"]]
    except (KeyError, TypeError, ValueError):
        return None
    if first is not None and ext_first != first:
        return None
    if first_root is not None and ext_first_root != first_root:
        return False
    return verify_consistency(ext_first_root, ext_first, root, size, nodes)
