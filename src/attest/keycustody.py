"""Key custody for the Ed25519 signing key: AWS KMS envelope or Windows DPAPI.

With ``ATTEST_KMS_KEY_ID`` set, the signing key never touches disk in
plaintext: a KMS data key wraps the PEM via AES-256-GCM, and the wrapped
blob plus the KMS ciphertext sit in ``attest-ed25519.key.kms.json``.
Unwrapping requires a live KMS ``Decrypt`` call with the same encryption
context — so a stolen data directory yields nothing signable, and every
key use is an auditable KMS event.

With ``ATTEST_KEY_CUSTODY=dpapi`` (Windows only), the PEM instead wraps
under the OS user's DPAPI master key via CryptProtectData — bound to this
account on this machine, no AWS dependency, stored as
``attest-ed25519.key.dpapi``. The two postures are mutually exclusive.

Without either setting nothing changes: the PEM is written as before. This
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


def _dpapi_types():
    """Build the ctypes plumbing lazily so non-Windows imports stay clean."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    return ctypes, wintypes, DATA_BLOB


class DpapiBox:
    """Wrap/unwrap key bytes under the Windows DPAPI user master key.

    CryptProtectData binds the blob to the OS user account and machine — a
    stolen ``attest-ed25519.key.dpapi`` is inert anywhere else, with no AWS
    dependency and no shipped secret. Like the KMS path this is honest key
    custody *at rest*: it does not make a compromised host safe while the
    server is running. Only available on Windows — requesting it elsewhere
    fails loudly rather than silently falling back to plaintext.
    """

    _ENTROPY = b"attest-ed25519-signing-key"
    _UI_FORBIDDEN = 0x1  # CRYPTPROTECT_UI_FORBIDDEN — services must never prompt

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError(
                "DPAPI key custody is only available on Windows — unset ATTEST_KEY_CUSTODY or use KMS instead"
            )
        self._ct, self._wt, self._BLOB = _dpapi_types()
        self._crypt32 = self._ct.windll.crypt32
        self._kernel32 = self._ct.windll.kernel32

    def _make_blob(self, data: bytes):
        ct, BLOB = self._ct, self._BLOB
        buf = ct.create_string_buffer(data, len(data))
        blob = BLOB(len(data), ct.cast(buf, ct.POINTER(ct.c_char)))
        return blob, buf  # buf must stay alive for the duration of the call

    def wrap(self, plaintext: bytes) -> bytes:
        ct = self._ct
        in_blob, _keep1 = self._make_blob(plaintext)
        ent_blob, _keep2 = self._make_blob(self._ENTROPY)
        out_blob = self._BLOB()
        if not self._crypt32.CryptProtectData(
            ct.byref(in_blob),
            None,
            ct.byref(ent_blob),
            None,
            None,
            self._UI_FORBIDDEN,
            ct.byref(out_blob),
        ):
            raise ct.WinError()
        try:
            return ct.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            self._kernel32.LocalFree(out_blob.pbData)

    def unwrap(self, blob: bytes) -> bytes:
        ct = self._ct
        in_blob, _keep1 = self._make_blob(blob)
        ent_blob, _keep2 = self._make_blob(self._ENTROPY)
        out_blob = self._BLOB()
        if not self._crypt32.CryptUnprotectData(
            ct.byref(in_blob),
            None,
            ct.byref(ent_blob),
            None,
            None,
            self._UI_FORBIDDEN,
            ct.byref(out_blob),
        ):
            raise ct.WinError()
        try:
            return ct.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            self._kernel32.LocalFree(out_blob.pbData)


def _dpapi_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".dpapi")


def _check_custody_combo(kms_key_id: str | None, custody: str | None) -> None:
    if kms_key_id and custody:
        raise ValueError("KMS and DPAPI custody are mutually exclusive — pick one protection posture")
    if custody not in (None, "dpapi"):
        raise ValueError(f"unknown key custody {custody!r} — supported: dpapi")


def _check_stray_custody_artifact(path: Path, kms_key_id: str | None, custody: str | None) -> None:
    """Refuse to proceed when a custody artifact doesn't match the configured
    posture — a dropped or swapped setting means minting/persisting a fresh
    key would silently rotate the issuer identity and strand the wrapped one.
    Restore the artifact's env, or remove it for a deliberate unsigned pivot."""
    configured = "dpapi" if custody == "dpapi" else ("kms" if kms_key_id else None)
    for artifact, posture, env in (
        (path.with_suffix(path.suffix + ".kms.json"), "kms", "ATTEST_KMS_KEY_ID"),
        (_dpapi_path(path), "dpapi", "ATTEST_KEY_CUSTODY=dpapi"),
    ):
        if posture != configured and artifact.exists():
            raise RuntimeError(
                f"custody artifact {artifact.name} exists but custody is "
                f"{configured or 'not configured'} — set {env} to keep the "
                "issuer identity, or remove the artifact for a deliberate "
                "unsigned pivot; refusing to silently strand it"
            )


def load_or_create_signer(
    path: Path,
    *,
    kms_key_id: str | None = None,
    kms_client: Any | None = None,
    aws_region: str = "us-east-1",
    custody: str | None = None,
) -> Signer:
    """Load the deployment signing key, creating it on first run.

    ``kms_key_id`` switches the on-disk format to the KMS envelope described
    above; ``kms_client`` is injectable for tests. ``custody="dpapi"`` wraps
    the PEM under the Windows DPAPI user master key (``.dpapi`` blob) with no
    external dependency. A configured custody path that cannot unwrap fails
    loudly — silently falling back to a plaintext key file would be a
    downgrade the operator never asked for.
    """
    _check_custody_combo(kms_key_id, custody)
    _check_stray_custody_artifact(path, kms_key_id, custody)
    if not kms_key_id and custody != "dpapi":
        return Signer.load_or_create(path)

    if custody == "dpapi":
        box = DpapiBox()
        blob_path = _dpapi_path(path)
        if blob_path.exists():
            pem = box.unwrap(blob_path.read_bytes())
        elif path.exists():
            # Enabling custody on a plaintext deployment must wrap THAT key —
            # minting a new one silently rotates the issuer identity and
            # strands every signed record. Order matters: only remove the
            # plaintext after the blob is durably written.
            pem = path.read_bytes()
            blob_path.parent.mkdir(parents=True, exist_ok=True)
            blob_path.write_bytes(box.wrap(pem))
            path.unlink()
        else:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            pem = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            blob_path.parent.mkdir(parents=True, exist_ok=True)
            blob_path.write_bytes(box.wrap(pem))

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        sk = serialization.load_pem_private_key(pem, password=None)
        assert isinstance(sk, Ed25519PrivateKey)
        return Signer(sk)

    box = KmsBox(kms_key_id, kms_client or _kms_client(aws_region))
    wrapped_path = path.with_suffix(path.suffix + ".kms.json")

    if wrapped_path.exists():
        record = json.loads(wrapped_path.read_text(encoding="utf-8"))
        pem = box.unwrap(record)
    elif path.exists():
        # Enabling KMS on a deployment that already has a plaintext signing
        # key must wrap THAT key — minting a new one silently rotates the
        # issuer identity and strands every signed record (chain verify under
        # the old key fails, review links die). Order matters: only remove the
        # plaintext after the wrapped record is durably written; if KMS is
        # unreachable the wrap raises first and the PEM stays put.
        pem = path.read_bytes()
        record = box.wrap(pem)
        path.parent.mkdir(parents=True, exist_ok=True)
        wrapped_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        path.unlink()  # plaintext key no longer needed — KMS can re-unwrap
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


def persist_signer_key(
    path: Path,
    pem: bytes,
    *,
    kms_key_id: str | None = None,
    kms_client: Any | None = None,
    aws_region: str = "us-east-1",
    custody: str | None = None,
) -> None:
    """Atomically replace the deployment signing key with new PEM bytes.

    Used by ``attest rotate-key`` AFTER the old key has already signed the
    ``key_rotation`` receipt — write order matters: the endorsement must be
    durable in the ledger before the new key materializes on disk. Under KMS
    custody the new key wraps to the ``.kms.json`` envelope and any plaintext
    PEM is removed; under DPAPI it wraps to the ``.dpapi`` blob the same way —
    custody parity with ``load_or_create_signer``. A crash mid-write can leave
    the old key in place (rotation re-runs idempotently) but never a
    half-written key."""
    _check_custody_combo(kms_key_id, custody)
    _check_stray_custody_artifact(path, kms_key_id, custody)
    path.parent.mkdir(parents=True, exist_ok=True)
    if custody == "dpapi":
        blob_path = _dpapi_path(path)
        tmp = blob_path.with_suffix(blob_path.suffix + ".tmp")
        tmp.write_bytes(DpapiBox().wrap(pem))
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, blob_path)
        path.unlink(missing_ok=True)  # no plaintext should remain under custody
    elif kms_key_id:
        box = KmsBox(kms_key_id, kms_client or _kms_client(aws_region))
        wrapped_path = path.with_suffix(path.suffix + ".kms.json")
        tmp = wrapped_path.with_suffix(wrapped_path.suffix + ".tmp")
        tmp.write_text(json.dumps(box.wrap(pem), indent=2), encoding="utf-8")
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, wrapped_path)
        path.unlink(missing_ok=True)  # no plaintext should remain under custody
    else:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(pem)
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
