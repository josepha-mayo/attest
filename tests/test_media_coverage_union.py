"""Synthetic media coverage must count distinct signed digests, not labels."""

import hashlib
import io
import json
import zipfile

import pytest

from attest.app import _verify_pack
from attest.ledger import Signer
from attest.models import ReviewBundle
from attest.packdiff import load_artifact


@pytest.mark.parametrize(
    ("references", "present", "withheld", "expected"),
    [
        ((0, 1), (0,), (0,), False),  # Overlap cannot hide the missing second digest.
        ((0, 1), (0, 1), (0,), True),  # Redundant markers do not reject complete media.
        ((0, 1), (0,), (1,), True),
        ((0, 1), (), (0, 1), True),
        ((0, 1), (0,), (), False),
        ((0, 1), (0, 2), (), False),  # Unrelated present bytes cannot substitute.
        ((0, 1), (0,), (2,), False),  # Neither can an unrelated withheld digest.
        ((), (), (), True),
        ((), (0,), (), False),
        ((), (), (0,), False),
        ((0, 0, 1), (0, 1), (), True),  # Repeated evidence may share a media digest.
        ((0, 1), (0,), (1, 1), True),
        ((0, 1), (0,), (0, 0), False),
    ],
)
def test_pack_media_coverage_uses_union(tmp_path, references, present, withheld, expected):
    # Ephemeral synthetic key and tiny ASCII media only; no runtime records.
    signer = Signer.ephemeral()
    media = (b"synthetic first observation", b"synthetic second observation", b"unrelated bytes")
    digests = [hashlib.sha256(data).hexdigest() for data in media]
    receipt = signer.issue(
        visit_id="synthetic-coverage",
        sequence=1,
        prev_hash=None,
        facts={"evidence": [{"media_sha256": digests[i]} for i in references]},
    )
    bundle = ReviewBundle(kind="attest.review_bundle/1", original=receipt)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("bundle.json", bundle.model_dump_json())
        archive.writestr("redaction.json", json.dumps({"withheld_digests": [digests[i] for i in withheld]}))
        for i in present:
            archive.writestr(f"media/{i}.txt", media[i])
    data = output.getvalue()
    path = tmp_path / "synthetic.zip"
    path.write_bytes(data)
    # Independent existing verifier already uses per-digest membership.
    failures = load_artifact(path, key=signer.public_key_b64)["verify_failures"]
    assert (not failures) is expected, failures
    ok, detail = _verify_pack(data, signer.public_key_b64)
    assert ok is expected, detail
    if expected and present == (0, 1):
        assert "withheld by redaction" not in detail
