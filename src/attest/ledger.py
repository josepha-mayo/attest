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


def verify_chain(receipts: list[Receipt], *, public_key: str | None = None) -> tuple[bool, str]:
    """Verify every receipt and the ``prev_hash`` links. All receipts must share one issuer key."""
    if not receipts:
        return True, "0 receipts"
    key = public_key or receipts[0].public_key
    prev: str | None = None
    expected_seq = 1
    for r in sorted(receipts, key=lambda x: x.sequence):
        ok, why = verify_receipt(r, public_key=key)
        if not ok:
            return False, f"receipt #{r.sequence}: {why}"
        if r.sequence != expected_seq:
            return False, f"receipt #{r.sequence}: gap in sequence (expected #{expected_seq})"
        if r.prev_hash != prev:
            return False, f"receipt #{r.sequence}: chain broken (prev_hash mismatch)"
        prev = r.payload_hash
        expected_seq += 1
    return True, f"{len(receipts)} receipts, chain intact"
