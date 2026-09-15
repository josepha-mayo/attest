import json

from attest import ledger
from attest.ledger import Signer
from attest.models import Receipt


def test_sign_and_verify_single():
    s = Signer.ephemeral()
    r = s.issue(
        visit_id="vis_1",
        sequence=1,
        prev_hash=None,
        facts={"arrived_at": "t", "duration_minutes": 88},
    )
    assert ledger.verify_receipt(r) == (True, "ok")
    # round-trips through JSON (what an agency would receive)
    again = Receipt.model_validate(json.loads(r.model_dump_json()))
    assert ledger.verify_receipt(again)[0]


def test_tamper_detected():
    s = Signer.ephemeral()
    r = s.issue(visit_id="vis_1", sequence=1, prev_hash=None, facts={"duration_minutes": 12})
    forged = r.model_copy(deep=True)
    forged.payload["duration_minutes"] = 90
    ok, why = ledger.verify_receipt(forged)
    assert not ok and "hash" in why
    # recomputing the hash without the key still fails
    forged.payload_hash = ledger.payload_hash(forged.payload)
    ok, why = ledger.verify_receipt(forged)
    assert not ok and "signature" in why


def test_chain():
    s = Signer.ephemeral()
    chain = []
    prev = None
    for i in range(1, 5):
        r = s.issue(visit_id=f"vis_{i}", sequence=i, prev_hash=prev, facts={"n": i})
        chain.append(r)
        prev = r.payload_hash
    assert ledger.verify_chain(chain)[0]
    assert not ledger.verify_chain(chain[:2] + chain[3:])[0]  # gap
    # a receipt re-signed by someone else's key is rejected once the issuer key is pinned
    other = Signer.ephemeral().issue(
        visit_id="x", sequence=3, prev_hash=chain[1].payload_hash, facts={"n": 3}
    )
    ok, why = ledger.verify_chain(chain[:2] + [other] + chain[3:])
    assert not ok and "different key" in why
    # a replaced receipt with different facts breaks the downstream prev_hash link
    swapped = s.issue(visit_id="x", sequence=3, prev_hash=chain[1].payload_hash, facts={"n": 99})
    ok, why = ledger.verify_chain(chain[:2] + [swapped] + chain[3:])
    assert not ok and "chain broken" in why


def test_key_persistence(tmp_path):
    p = tmp_path / "k.pem"
    a = Signer.load_or_create(p)
    b = Signer.load_or_create(p)
    assert a.public_key_b64 == b.public_key_b64
