"""KMS envelope encryption of the signing key — tested against a fake KMS
client, because the contract that matters is local: the PEM never touches
disk, unwrap requires a Decrypt call with the right context, and a missing
or foreign data key fails loudly."""

import json
import os

import pytest

from attest.keycustody import KmsBox, load_or_create_signer
from attest.ledger import Signer, verify_receipt


class FakeKms:
    """A minimal KMS double: CiphertextBlob is just the data key, and Decrypt
    enforces the encryption context like real KMS does."""

    def __init__(self, data_key: bytes = b"\x11" * 32):
        self.data_key = data_key
        self.decrypt_calls = 0
        self.contexts = []

    def generate_data_key(self, KeyId, KeySpec, EncryptionContext):
        assert KeySpec == "AES_256"
        self.contexts.append(EncryptionContext)
        return {"Plaintext": self.data_key, "CiphertextBlob": b"blob:" + self.data_key}

    def decrypt(self, CiphertextBlob, EncryptionContext):
        self.decrypt_calls += 1
        if not CiphertextBlob.startswith(b"blob:"):
            raise ValueError("InvalidCiphertext")
        if EncryptionContext.get("purpose") != "attest-signing-key":
            raise ValueError("InvalidEncryptionContextException")
        return {"Plaintext": CiphertextBlob[5:], "KeyId": "k"}


def test_wrapped_key_never_writes_plaintext_pem(tmp_path):
    kms = FakeKms()
    signer = load_or_create_signer(tmp_path / "k.pem", kms_key_id="key-1", kms_client=kms)
    wrapped = tmp_path / "k.pem.kms.json"
    assert wrapped.exists() and not (tmp_path / "k.pem").exists()
    record = json.loads(wrapped.read_text())
    assert record["key_id"] == "key-1"
    # the PEM must not appear anywhere in the on-disk record
    assert b"PRIVATE KEY" not in wrapped.read_bytes()
    assert signer.public_key_b64


def test_unwrap_roundtrip_and_decrypt_audit(tmp_path):
    kms = FakeKms()
    s1 = load_or_create_signer(tmp_path / "k.pem", kms_key_id="key-1", kms_client=kms)
    kms2 = FakeKms()  # a fresh "boot" — same KMS data key behind the blob
    s2 = load_or_create_signer(tmp_path / "k.pem", kms_key_id="key-1", kms_client=kms2)
    assert s1.public_key_b64 == s2.public_key_b64  # same unwrapped key
    assert kms2.decrypt_calls == 1  # unwrap required a live Decrypt

    receipt = s2.issue(visit_id="v", sequence=1, prev_hash=None, facts={"x": 1})
    assert verify_receipt(receipt, public_key=s2.public_key_b64)[0]


def test_wrong_encryption_context_is_rejected(tmp_path):
    kms = FakeKms()
    load_or_create_signer(tmp_path / "k.pem", kms_key_id="key-1", kms_client=kms)
    record = json.loads((tmp_path / "k.pem.kms.json").read_text())
    box = KmsBox("key-1", kms)
    kms.contexts.clear()
    with pytest.raises(ValueError, match="InvalidEncryptionContext"):
        kms.decrypt(b"blob:" + kms.data_key, EncryptionContext={"purpose": "other"})
    # but the real context still unwraps
    assert box.unwrap(record).startswith(b"-----BEGIN")


def test_plaintext_path_unchanged_without_kms(tmp_path):
    signer = load_or_create_signer(tmp_path / "k.pem")
    assert (tmp_path / "k.pem").exists()
    assert not (tmp_path / "k.pem.kms.json").exists()
    assert isinstance(signer, Signer)


def test_enabling_kms_wraps_the_existing_pem_instead_of_rotating(tmp_path):
    """Turning on KMS on a deployed plaintext key must wrap THAT key — minting
    a new one silently rotates the issuer identity and strands every signed
    record (the audit chain verifies under the old key)."""
    pem_path = tmp_path / "attest-ed25519.key"
    plain = load_or_create_signer(pem_path)
    pem = pem_path.read_bytes()
    kms = FakeKms()
    migrated = load_or_create_signer(pem_path, kms_key_id="key-1", kms_client=kms)
    assert migrated.public_key_b64 == plain.public_key_b64  # same identity
    assert not pem_path.exists()  # plaintext gone — that's the point of KMS
    wrapped = json.loads((tmp_path / "attest-ed25519.key.kms.json").read_text())
    # unwrap returns the ORIGINAL pem
    assert KmsBox("key-1", FakeKms()).unwrap(wrapped) == pem
    assert KmsBox("key-1", FakeKms()).unwrap(wrapped).startswith(b"-----BEGIN")


def test_kms_migration_fails_loudly_when_kms_unreachable(tmp_path):
    class DeadKms:
        def generate_data_key(self, **kw):
            raise RuntimeError("KMS unreachable")

    pem_path = tmp_path / "attest-ed25519.key"
    plain = load_or_create_signer(pem_path)
    with pytest.raises(RuntimeError, match="unreachable"):
        load_or_create_signer(pem_path, kms_key_id="key-1", kms_client=DeadKms())
    assert pem_path.exists()  # migration failed BEFORE touching the PEM
    assert not (tmp_path / "attest-ed25519.key.kms.json").exists()
    # and the plaintext signer still works — nothing was silently rotated
    again = load_or_create_signer(pem_path)
    assert again.public_key_b64 == plain.public_key_b64


dpapi = pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")


@dpapi
def test_dpapi_blob_never_writes_plaintext_pem(tmp_path):
    signer = load_or_create_signer(tmp_path / "k.pem", custody="dpapi")
    blob = tmp_path / "k.pem.dpapi"
    assert blob.exists() and not (tmp_path / "k.pem").exists()
    assert b"PRIVATE KEY" not in blob.read_bytes()
    assert signer.public_key_b64


@dpapi
def test_dpapi_unwrap_roundtrip(tmp_path):
    s1 = load_or_create_signer(tmp_path / "k.pem", custody="dpapi")
    s2 = load_or_create_signer(tmp_path / "k.pem", custody="dpapi")  # a "reboot"
    assert s1.public_key_b64 == s2.public_key_b64  # same unwrapped key
    receipt = s2.issue(visit_id="v", sequence=1, prev_hash=None, facts={"x": 1})
    assert verify_receipt(receipt, public_key=s2.public_key_b64)[0]


@dpapi
def test_enabling_dpapi_wraps_the_existing_pem_instead_of_rotating(tmp_path):
    """Like KMS migration: turning on DPAPI on a plaintext deployment must
    wrap THAT key — minting a new one strands the audit chain."""
    pem_path = tmp_path / "attest-ed25519.key"
    plain = load_or_create_signer(pem_path)
    migrated = load_or_create_signer(pem_path, custody="dpapi")
    assert migrated.public_key_b64 == plain.public_key_b64
    assert not pem_path.exists()  # plaintext gone under custody
    assert (tmp_path / "attest-ed25519.key.dpapi").exists()


@dpapi
def test_dpapi_tampered_blob_fails_loudly(tmp_path):
    load_or_create_signer(tmp_path / "k.pem", custody="dpapi")
    blob = tmp_path / "k.pem.dpapi"
    blob.write_bytes(blob.read_bytes()[:-8] + b"\x00" * 8)
    with pytest.raises(OSError):
        load_or_create_signer(tmp_path / "k.pem", custody="dpapi")


@dpapi
def test_dpapi_persist_writes_blob_and_removes_plaintext(tmp_path):
    """rotate-key persists the successor under the same custody posture — the
    .dpapi blob lands atomically and no plaintext PEM survives."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from attest.keycustody import persist_signer_key

    path = tmp_path / "k.pem"
    old = load_or_create_signer(path, custody="dpapi")
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    persist_signer_key(path, pem, custody="dpapi")
    assert not path.exists()
    assert b"PRIVATE KEY" not in (tmp_path / "k.pem.dpapi").read_bytes()
    new = load_or_create_signer(path, custody="dpapi")
    assert new.public_key_b64 != old.public_key_b64


def test_kms_and_dpapi_custody_are_mutually_exclusive(tmp_path):
    with pytest.raises(ValueError, match="mutually exclusive"):
        load_or_create_signer(tmp_path / "k.pem", kms_key_id="key-1", custody="dpapi")


def test_unknown_custody_fails_loudly(tmp_path):
    with pytest.raises(ValueError, match="unknown key custody"):
        load_or_create_signer(tmp_path / "k.pem", custody="tpm")
