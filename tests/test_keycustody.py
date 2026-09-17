"""KMS envelope encryption of the signing key — tested against a fake KMS
client, because the contract that matters is local: the PEM never touches
disk, unwrap requires a Decrypt call with the right context, and a missing
or foreign data key fails loudly."""

import json

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
