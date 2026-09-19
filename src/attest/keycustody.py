"""AWS KMS envelope encryption for the Ed25519 signing key.

With ``ATTEST_KMS_KEY_ID`` set, the signing key never touches disk in
plaintext: a KMS data key wraps the PEM via AES-256-GCM, and the wrapped
blob plus the KMS ciphertext sit in ``attest-ed25519.key.kms.json``.
Unwrapping requires a live KMS ``Decrypt`` call with the same encryption
context — so a stolen data directory yields nothing signable, and every
key use is an auditable KMS event.

Without the setting nothing changes: the PEM is written as before. This
is honest key custody — it protects the key at rest; it does not make a
compromised host safe while the server is running.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .ledger import Signer

_CONTEXT_PURPOSE = "attest-signing-key"


def _context(key_id: str) -> dict[str, str]:
    return {"app": "attest", "purpose": _CONTEXT_PURPOSE, "key": key_id}


@dataclass
class KmsBox:
    """Wrap/unwrap arbitrary key bytes under a KMS data key."""

    key_id: str
    client: Any  # boto3 kms client (or a test double)

    def wrap(self, plaintext: bytes) -> dict[str, str]:
        resp = self.client.generate_data_key(
            KeyId=self.key_id, KeySpec="AES_256", EncryptionContext=_context(self.key_id)
        )
        data_key = resp["Plaintext"]
        blob = resp["CiphertextBlob"]
        nonce = os.urandom(12)
        ct = AESGCM(data_key).encrypt(nonce, plaintext, json.dumps(_context(self.key_id)).encode())
        # Drop our references promptly — CPython can't guarantee erasure of
        # immutable bytes, but keeping the window small is the honest best.
        del data_key, resp
        return {
            "schema": "attest.kms-wrapped-key/1",
            "key_id": self.key_id,
            "ciphertext_blob": base64.b64encode(blob).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }

    def unwrap(self, record: dict[str, str]) -> bytes:
        if record.get("schema") != "attest.kms-wrapped-key/1":
            raise ValueError("not a kms-wrapped key record")
        blob = base64.b64decode(record["ciphertext_blob"])
        resp = self.client.decrypt(CiphertextBlob=blob, EncryptionContext=_context(self.key_id))
        data_key = resp["Plaintext"]
        return AESGCM(data_key).decrypt(
            base64.b64decode(record["nonce"]),
            base64.b64decode(record["ciphertext"]),
            json.dumps(_context(self.key_id)).encode(),
        )


def _kms_client(region: str):
    import boto3  # optional dependency — only needed when KMS custody is configured

    return boto3.client("kms", region_name=region)


def load_or_create_signer(
    path: Path,
    *,
    kms_key_id: str | None = None,
    kms_client: Any | None = None,
    aws_region: str = "us-east-1",
) -> Signer:
    """Load the deployment signing key, creating it on first run.

    ``kms_key_id`` switches the on-disk format to the KMS envelope described
    above; ``kms_client`` is injectable for tests. A configured KMS path that
    cannot reach KMS fails loudly — silently falling back to a plaintext key
    file would be a downgrade the operator never asked for.
    """
    if not kms_key_id:
        return Signer.load_or_create(path)

    box = KmsBox(kms_key_id, kms_client or _kms_client(aws_region))
    wrapped_path = path.with_suffix(path.suffix + ".kms.json")

    if wrapped_path.exists():
        record = json.loads(wrapped_path.read_text(encoding="utf-8"))
        pem = box.unwrap(record)
    else:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pem = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        record = box.wrap(pem)
        path.parent.mkdir(parents=True, exist_ok=True)
        wrapped_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(sk, Ed25519PrivateKey)
    return Signer(sk)
