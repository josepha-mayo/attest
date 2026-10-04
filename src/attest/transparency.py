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

_LEAF = b"\x00"
_NODE = b"\x01"
_EMPTY_ROOT = hashlib.sha256(b"").digest()


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
    if leaf_index >= tree_size or leaf_index < 0 or tree_size < 1:
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
    if old_size == new_size:
        return proof == [] and old_root == new_root
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
