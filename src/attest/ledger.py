"""Tamper-evident receipts: canonical JSON -> SHA-256 -> Ed25519 signature, hash-chained.

Each receipt's payload embeds ``prev_hash`` (the previous receipt's payload hash), so the
sequence of receipts for a deployment forms a chain. Anyone holding the public key can
verify a single receipt offline; anyone holding the whole export can verify the chain.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import Receipt, utcnow


def canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()


def payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._sk = private_key
        self.public_key_b64 = _b64(
            self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )

    @classmethod
    def load_or_create(cls, path: Path) -> Signer:
        if path.exists():
            sk = serialization.load_pem_private_key(path.read_bytes(), password=None)
            assert isinstance(sk, Ed25519PrivateKey)
            return cls(sk)
        sk = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            sk.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        # Owner-only permissions where the OS honors chmod; on Windows the file
        # inherits the data dir's ACLs (THREATMODEL.md states this honestly).
        if os.name == "posix":
            os.chmod(path, 0o600)
        return cls(sk)

    @classmethod
    def ephemeral(cls) -> Signer:
        return cls(Ed25519PrivateKey.generate())

    def sign_hash(self, hex_digest: str) -> str:
        """Sign a payload hash directly — used by the attack demo to forge a
        receipt under a different key."""
        return _b64(self._sk.sign(bytes.fromhex(hex_digest)))

    def issue(self, *, visit_id: str, sequence: int, prev_hash: str | None, facts: dict[str, Any]) -> Receipt:
        if {"schema", "sequence", "prev_hash", "receipt_id", "issued_at"} & facts.keys():
            raise ValueError("facts contain reserved receipt fields")
        if "visit_id" in facts and facts["visit_id"] != visit_id:
            raise ValueError("facts contain a different visit id")
        receipt_id = f"rcpt_{uuid.uuid4().hex}"
        issued_at = utcnow()
        payload = {
            **facts,
            "schema": "attest.receipt/2",
            "sequence": sequence,
            "prev_hash": prev_hash,
            "visit_id": visit_id,
            "receipt_id": receipt_id,
            "issued_at": issued_at.isoformat(),
        }
        h = payload_hash(payload)
        sig = self._sk.sign(bytes.fromhex(h))
        return Receipt(
            id=receipt_id,
            issued_at=issued_at,
            visit_id=visit_id,
            sequence=sequence,
            prev_hash=prev_hash,
            payload=payload,
            payload_hash=h,
            signature=_b64(sig),
            public_key=self.public_key_b64,
        )


def verify_receipt(receipt: Receipt | dict[str, Any], *, public_key: str | None = None) -> tuple[bool, str]:
    """Verify hash and signature of one receipt. Returns (ok, reason).

    Pass the issuer's ``public_key`` (base64) whenever you have it. A receipt carries its own
    key for convenience, so without pinning you only learn that *someone* signed it.
    """
    r = receipt if isinstance(receipt, Receipt) else Receipt.model_validate(receipt)
    if public_key is not None and r.public_key != public_key:
        return False, "signed by a different key than this issuer"
    if payload_hash(r.payload) != r.payload_hash:
        return False, "payload hash mismatch (payload was altered)"
    if r.payload.get("sequence") != r.sequence or r.payload.get("prev_hash") != r.prev_hash:
        return False, "envelope fields disagree with signed payload"
    if r.payload.get("visit_id") != r.visit_id:
        return False, "visit id disagrees with signed payload"
    if r.payload.get("schema") == "attest.receipt/2":
        # issued_at serializes "+00:00" in the signed payload but may spell
        # "Z" or another offset in the unsigned envelope — compare instants.
        from datetime import datetime

        raw_issued = r.payload.get("issued_at")
        try:
            payload_issued = (
                raw_issued
                if isinstance(raw_issued, datetime)
                else datetime.fromisoformat(str(raw_issued).replace("Z", "+00:00"))
            )
        except ValueError:
            return False, "receipt envelope identity disagrees with signed payload"
        if r.payload.get("receipt_id") != r.id or payload_issued != r.issued_at:
            return False, "receipt envelope identity disagrees with signed payload"
    elif r.payload.get("schema") != "attest.receipt/1":
        return False, "unsupported receipt schema"
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(r.public_key)).verify(
            _unb64(r.signature), bytes.fromhex(r.payload_hash)
        )
    except (InvalidSignature, ValueError):
        return False, "signature invalid"
    return True, "ok"


def _adoption_consent(receipts: list[Receipt], rotation: Receipt, new_key: str) -> bool:
    """Whether the SUCCESSOR key countersigned ``rotation``.

    A ``key_rotation`` endorsement is self-serve — any key can sign "I retire
    in favor of your key" and graft attacker-signed history onto a trusted
    issuer's chain. An ancestor hop therefore only counts when the successor
    also signed a ``key_adoption`` receipt naming this exact rotation (id and
    payload hash): consent the attacker cannot forge."""
    for r in receipts:
        p = r.payload
        link = p.get("rotation_receipt") or {}
        if (
            p.get("record_type") == "key_adoption"
            and link.get("id") == rotation.id
            and link.get("hash") == rotation.payload_hash
            and r.public_key == new_key
            and verify_receipt(r, public_key=new_key)[0]
        ):
            return True
    return False


def _rotation_hop(receipts: list[Receipt], new_key: str) -> Receipt | None:
    """The successor-consented ``key_rotation`` receipt endorsing ``new_key``.

    Only a receipt signed by the retiring key counts — a forged rotation
    naming itself as successor has no pivot power because its signature
    verifies under nobody trusted. And endorsement alone is self-serve, so
    the hop additionally requires a ``key_adoption`` receipt countersigned by
    ``new_key`` naming this exact rotation — without successor consent a
    claimed predecessor is a graft, not a handoff."""
    for r in receipts:
        p = r.payload
        if (
            p.get("record_type") == "key_rotation"
            and p.get("new_key") == new_key
            and p.get("previous_key") == r.public_key
            and verify_receipt(r, public_key=r.public_key)[0]
            and _adoption_consent(receipts, r, new_key)
        ):
            return r
    return None


def trusted_issuer_keys(issuer_key: str, key_receipts: list[Receipt], *, max_hops: int = 32) -> set[str]:
    """The keys a pack verification may trust: the manifest issuer plus every
    ancestor reachable through signed ``key_rotation`` receipts. Each hop must
    be a valid receipt signed by the retiring key endorsing its successor AND
    countersigned by the successor via ``key_adoption`` — endorsement alone is
    self-serve (any key may claim any successor), so a forged rotation never
    lands in the set. Pass every ``key:*`` receipt, rotations and adoptions
    alike; the pool is filtered by record_type."""
    trusted = {issuer_key}
    cur = issuer_key
    for _ in range(max_hops):
        hop = _rotation_hop(key_receipts, cur)
        if hop is None:
            break
        cur = hop.payload["previous_key"]
        trusted.add(cur)
    return trusted


def descendant_issuer_keys(root_key: str, rotations: list[Receipt], *, max_hops: int = 32) -> set[str]:
    """The forward walk for single-visit bundles: reviews append after the
    original, so a bundle legitimately carries issuer keys the rotations
    endorse — the original's key plus every verified successor.

    A hop requires the successor's ``key_adoption`` consent, same as the
    chain pivot and ancestor walk: a rotation whose successor key was never
    persisted is a dead branch, not a trusted descendant — without the gate
    an orphaned rotation would strand every later legitimate receipt into
    "outside the rotation chain". Competing rotations from one predecessor
    resolve deterministically: consented hops first, then highest sequence."""
    trusted = {root_key}
    cur = root_key
    for _ in range(max_hops):
        candidates = [
            r
            for r in rotations
            if r.payload.get("record_type") == "key_rotation"
            and r.payload.get("previous_key") == cur
            and r.public_key == cur
            and verify_receipt(r, public_key=cur)[0]
        ]
        hop = next(
            (
                r
                for r in sorted(candidates, key=lambda x: x.sequence, reverse=True)
                if _adoption_consent(rotations, r, r.payload["new_key"])
            ),
            None,
        )
        if hop is None:
            break
        cur = hop.payload["new_key"]
        trusted.add(cur)
    return trusted


def verify_chain(receipts: list[Receipt], *, public_key: str | None = None) -> tuple[bool, str]:
    """Verify every receipt and the ``prev_hash`` links.

    The issuer key may rotate mid-chain: a ``key_rotation`` receipt signed by
    the current key AND countersigned by the successor's ``key_adoption`` is
    the pivot — every receipt after it must verify under the named successor.
    Endorsement alone has no pivot power: a rotation orphaned between its
    signature and the successor's persist/adoption (a mid-rotation crash)
    leaves the chain under the retiring key, verifiable and retryable.
    With ``public_key`` pinned, the chain's root key must be the pin itself
    or an ancestor of it reachable through consented rotations (pinning
    today's key still validates receipts the retired key wrote; an
    uncountersigned "rotation" is a graft attempt, not a handoff)."""
    if not receipts:
        return True, "0 receipts"
    ordered = sorted(receipts, key=lambda x: x.sequence)
    first_key = ordered[0].public_key
    if public_key is not None and first_key != public_key:
        cur, reached = public_key, False
        for _ in range(32):
            hop = _rotation_hop(ordered, cur)
            if hop is None:
                break
            cur = hop.payload["previous_key"]
            if cur == first_key:
                reached = True
                break
        if not reached:
            return False, "chain root was signed by a key the pinned issuer key does not descend from"
    key = first_key
    prev: str | None = None
    expected_seq = 1
    pivots = 0
    for r in ordered:
        ok, why = verify_receipt(r, public_key=key)
        if not ok:
            return False, f"receipt #{r.sequence}: {why}"
        if r.sequence != expected_seq:
            return False, f"receipt #{r.sequence}: gap in sequence (expected #{expected_seq})"
        if r.prev_hash != prev:
            return False, f"receipt #{r.sequence}: chain broken (prev_hash mismatch)"
        prev = r.payload_hash
        expected_seq += 1
        p = r.payload
        if (
            p.get("record_type") == "key_rotation"
            and p.get("previous_key") == key
            and p.get("new_key")
            # The pivot needs BOTH signatures: endorsement alone would let a
            # rotation that crashed before the successor was persisted strand
            # every later receipt. An unconsented rotation is inert history —
            # the chain stays under the retiring key, and a later rotation can
            # still pivot (retrying rotate-key after a crash is safe).
            and _adoption_consent(ordered, r, p["new_key"])
        ):
            key = p["new_key"]
            pivots += 1
    detail = f"{len(receipts)} receipts, chain intact"
    if pivots:
        detail += f" across {pivots} signed key rotation{'s' if pivots > 1 else ''}"
    return True, detail


def revoked_issuer_keys(receipts: list[Receipt]) -> dict[str, str]:
    """Keys declared suspect by a ``key_revocation`` receipt → suspect_after ISO.

    Only the chain's TIP issuer can revoke: a retired key revoking its
    successor would let a compromised key smear the healthy one, so
    revocations signed by anything but the final in-effect key are ignored
    (not errors — they simply carry no authority). Revocation is a trust
    overlay on top of integrity — records still verify; the flag is for
    humans and tools to weight them."""
    ordered = sorted(receipts, key=lambda x: x.sequence)
    revoked: dict[str, str] = {}
    in_effect: str | None = None
    for r in ordered:
        # Walk the in-effect issuer like verify_chain: a receipt verifies under
        # the key in force at its position, and only a consented rotation moves
        # that authority. "Tip" can never be derived from position alone — a
        # forged high-sequence revocation would make itself the tip and
        # self-authorize (the compromised-key smear this check exists to stop).
        ok, _ = verify_receipt(r, public_key=in_effect or r.public_key)
        if not ok:
            continue
        if in_effect is None:
            in_effect = r.public_key
        p = r.payload
        if (
            p.get("record_type") == "key_rotation"
            and p.get("previous_key") == in_effect
            and p.get("new_key")
            and _adoption_consent(ordered, r, p["new_key"])
        ):
            in_effect = p["new_key"]
            continue
        if p.get("record_type") == "key_revocation" and p.get("revoked_key") and r.public_key == in_effect:
            revoked[p["revoked_key"]] = p.get("suspect_after") or ""
    return revoked


def suspect_receipts(receipts: list[Receipt], revoked: dict[str, str] | None = None) -> list[Receipt]:
    """Receipts signed by a revoked key INSIDE its suspect window —
    cryptographically valid, declared untrustworthy. Integrity verdicts
    never depend on this; it's the annotation surfaces report. Pass a
    precomputed ``revoked_issuer_keys`` map when the revocation receipts
    live in a separate pool (packs carry them beside the bundles)."""
    if revoked is None:
        revoked = revoked_issuer_keys(receipts)
    if not revoked:
        return []
    from datetime import UTC, datetime

    def _instant(s) -> datetime | None:
        try:
            at = s if isinstance(s, datetime) else datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        # Naive spellings read as UTC: a forged or sloppy timestamp must not
        # crash the comparison, only compare conservatively.
        return at.replace(tzinfo=UTC) if at.tzinfo is None else at

    out = []
    for r in receipts:
        after = _instant(revoked.get(r.public_key) or "")
        at = _instant(r.issued_at)
        # compare instants, not spellings — 'Z' and '+00:00' sort differently
        if after is not None and at is not None and at > after:
            out.append(r)
    return out


def issuer_document(issuer_key: str, receipts: list[Receipt]) -> dict[str, Any]:
    """The ``attest.issuer/1`` discovery document — a JWKS analogue served at
    ``/.well-known/attest-issuer.json`` and exported by ``attest issuer``.

    Carries the current issuer key plus every signed key-lifecycle receipt
    (rotation/adoption/revocation) so a remote verifier can pin a pack to
    THIS deployment and walk the lineage itself — the receipts are
    self-verifying crypto that already travels in every exported pack. The
    issuer_key's authenticity rides on the channel serving the document:
    over the deployment's own HTTPS it is trust-on-first-use; for higher
    assurance pin ``--key`` out of band instead."""
    key_receipts = [
        r.model_dump(mode="json")
        for r in sorted(receipts, key=lambda x: x.sequence)
        if r.visit_id.startswith("key:")
    ]
    tip = max(receipts, key=lambda r: r.sequence, default=None)
    return {
        "schema": "attest.issuer/1",
        "issuer_key": issuer_key,
        "key_receipts": key_receipts,
        "chain_tip": (
            {"receipt_id": tip.id, "sequence": tip.sequence, "payload_hash": tip.payload_hash}
            if tip
            else None
        ),
        "served_at": utcnow().isoformat(),
        "boundary": (
            "issuer_key's authenticity is only as strong as the channel that "
            "served this document — over the deployment's own HTTPS it is "
            "trust-on-first-use; pin --key for out-of-band assurance"
        ),
    }
