"""Round-7 audit regressions — the second adversarial verifier-parity pass.

Same rule as r6: identical bytes must produce identical verdicts on native
Python, the embedded stdlib verifier, and the browser JS (under node). Each
test names the finding it pins.
"""

import io
import json
import shutil
import subprocess
import zipfile
from datetime import timedelta

import pytest
from pydantic import ValidationError
from ring_sandbox import WebhookEvent, webhooks

from attest import disputepack
from attest.ledger import Signer, payload_hash
from attest.models import Receipt, ReviewBundle

NODE = shutil.which("node")


def event(cam, at, kind="motion_detected", account="ava1.ring.account.SANDBOX"):
    return WebhookEvent.model_validate(
        webhooks.build_event(
            event_type=kind,
            device_id=cam.id,
            occurred_at=at,
            sub_type="human" if kind == "motion_detected" else None,
            account_id=account,
        )
    )


def _lib():
    ns = {}
    exec(disputepack._VERIFIER_LIB, ns)
    return ns


def _js(tmp_path):
    """VERIFY_HTML's script body extracted to a file for node eval."""
    import re

    from attest.verifyjs import VERIFY_HTML

    m = re.search(r"<script>(.*)</script>", VERIFY_HTML, re.S)
    (tmp_path / "verify.js").write_text(m.group(1), encoding="utf-8")


def _node(tmp_path, body):
    driver = (
        """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
eval(src + `"""
        + body
        + """`);
"""
    )
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js"], cwd=tmp_path, capture_output=True, text=True, timeout=300
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _signed_receipt(signer, sequence, payload_facts, **env):
    """A receipt whose PAYLOAD is crafted raw (not engine-built), signed for
    real — lets tests produce byte-shapes the issuer would never mint."""
    payload = {"schema": "attest.receipt/1", "sequence": sequence, **payload_facts}
    h = payload_hash(payload)
    base = {
        "id": "rcpt_test",
        "visit_id": payload.get("visit_id", "v"),
        "sequence": sequence,
        "prev_hash": None,
        "payload": payload,
        "payload_hash": h,
        "signature": signer.sign_hash(h),
        "public_key": signer.public_key_b64,
        "issued_at": "2026-03-01T12:00:00Z",
    }
    base.update(env)
    return base


# ---------- F-1/F-8: strict JSON-int envelope fields on every surface -------


def test_sequence_strict_int_all_surfaces():
    """Pydantic's lax int coerced '5'/' 5 '/True to ints; the embedded and
    browser verifiers always required a real JSON integer. _json_int makes
    the model strict too — same bytes, same reject, everywhere."""
    s = Signer.ephemeral()
    good = _signed_receipt(s, 1, {"visit_id": "v", "record_type": "x"})
    ok, _ = disputepack_verifier_check(good, s.public_key_b64)
    assert ok
    for bad_seq in ("5", " 5 ", "5 5", "5_0", "5.0", True, None, {"x": 1}):
        bad = dict(good)
        bad["sequence"] = bad_seq
        # native: the model itself refuses the spelling
        with pytest.raises(ValidationError):
            Receipt.model_validate(bad)
        # embedded: clean malformed, never a pass and never a crash
        ns = _lib()
        ok, why = ns["check_receipt"](bad, s.public_key_b64)
        assert ok is False, f"sequence={bad_seq!r} accepted by embedded verifier"
    # integral floats still pass everywhere (Number.isInteger parity)
    ok, _ = disputepack_verifier_check(dict(good, sequence=1.0), s.public_key_b64)
    assert ok
    assert Receipt.model_validate(dict(good, sequence=1.0)).sequence == 1


def disputepack_verifier_check(r, key):
    ns = _lib()
    return ns["check_receipt"](r, key)


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_pymodelint_rejects_strings_and_bools(tmp_path):
    """_pyModelInt is the strict-int mirror: only int/float literals — the
    '5 5' interior-whitespace and '5'-string acceptances are gone."""
    _js(tmp_path)
    out = _node(
        tmp_path,
        """
(async()=>{
  const mk=r=>({t:'lit',r});
  const mks=s=>({t:'lit',r:JSON.stringify(s),str:s});
  for(const [label,node] of [
    ['int5',mk('5')],['neg',mk('-7')],['float',mk('5.0')],
    ['str5',mks('5')],['str_sp',mks(' 5 ')],['str_inner',mks('5 5')],
    ['str_us',mks('5_0')],['str_dec',mks('5.0')],['bool',mk('true')],
    ['null',mk('null')],['big',mk('99999999999999999999999')],
    ['floatBig',mk('1e300')],['arr',{t:'arr',v:[]}]])
    console.log(label+':'+(function(){try{return String(_pyModelInt(node))}
      catch(e){return 'THROW'}})());
})();""",
    )
    exp = {
        "int5": "5",
        "neg": "-7",
        "float": "5",
        "big": "99999999999999999999999",
        "floatBig": str(int(float("1e300"))),
    }
    for label, want in exp.items():
        assert f"{label}:{want}" in out, (label, out)
    for label in ("str5", "str_sp", "str_inner", "str_us", "str_dec", "bool", "null", "arr"):
        assert f"{label}:null" in out, (label, out)


# ---------- F-3: instant parse parity --------------------------------------


def test_iso_instant_grammar_parity_embedded():
    """_iso_instant (embedded) and the model's ISO_INSTANT_RE agree on
    grammar AND calendar validity — including year 0000 which datetime
    rejects."""
    ns = _lib()
    iso = ns["_iso_instant"]
    for bad in ("0000-01-01", "2026-02-30", "Mar 1, 2026", "2026-13-01", 5, None):
        assert iso(bad) is None, bad
        if isinstance(bad, str):
            base = {"issued_at": bad}
            with pytest.raises(ValidationError):
                Receipt.model_validate(
                    {
                        "visit_id": "v",
                        "sequence": 1,
                        "prev_hash": None,
                        "payload": {},
                        "payload_hash": "h",
                        "signature": "s",
                        "public_key": "k",
                        **base,
                    }
                )
    assert iso("2026-03-01") is not None
    assert iso("2026-03-01T00:00:00.000000Z") is not None


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_pyinstant_is_tz_and_engine_independent(tmp_path):
    """_pyInstant no longer calls Date.parse: year 0 rejects, naive spellings
    compare by calendar fields (not local TZ), offsets normalize to UTC, and
    microseconds compare exactly."""
    _js(tmp_path)
    out = _node(
        tmp_path,
        """
(async()=>{
  const t=(a,b)=>{
    const x=_pyInstant(a),y=_pyInstant(b);
    return x!==null&&y!==null&&x[0]===y[0]&&x[1]===y[1];};
  console.log('y0:'+(_pyInstant('0000-01-01T00:00:00Z')===null));
  console.log('feb30:'+(_pyInstant('2026-02-30')===null));
  console.log('naive_eq:'+t('2026-01-01','2026-01-01T00:00:00'));
  console.log('naive_space:'+t('2026-01-01','2026-01-01 00:00'));
  console.log('naive_vs_aware:'+(t('2026-01-01T00:00:00','2026-01-01T00:00:00Z')===false));
  console.log('offset:'+t('2026-01-01T05:30:00+05:30','2026-01-01T00:00:00Z'));
  console.log('offset_nocolon:'+t('2026-01-01T05:30:00+0530','2026-01-01T00:00:00Z'));
  console.log('frac_eq:'+t('2026-01-01T00:00:00.5Z','2026-01-01T00:00:00.500000Z'));
  console.log('frac_ne:'+(t('2026-01-01T00:00:00.123456Z','2026-01-01T00:00:00.1235Z')===false));
  console.log('year_le:'+t('0026-01-01','0026-01-01T00:00:00'));
})();""",
    )
    for line in (
        "y0:true",
        "feb30:true",
        "naive_eq:true",
        "naive_space:true",
        "naive_vs_aware:true",
        "offset:true",
        "offset_nocolon:true",
        "frac_eq:true",
        "frac_ne:true",
        "year_le:true",
    ):
        assert line in out, (line, out)


# ---------- F-4: original_receipt must be EXACTLY {id,hash} -----------------


def _visit_original(engine, store, household, t0):
    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    return store.receipt_for_visit(visit.id)


def _bundle_with_anchor(engine, original, anchor_extra=None):
    """A real bundle whose first review receipt anchors to the original —
    optionally with an extra key grafted into the signed anchor."""
    anchor = {"id": original.id, "hash": original.payload_hash}
    if anchor_extra:
        anchor.update(anchor_extra)
    review = engine.signer.issue(
        visit_id=original.visit_id,
        sequence=1,  # review-chain position, not global log sequence
        prev_hash=original.payload_hash,
        facts={
            "record_type": "review",
            "actor": {"role": "worker"},
            "review": {"kind": "statement", "decision": "confirm"},
            "original_receipt": anchor,
        },
    )
    return {
        "kind": "attest.review_bundle/1",
        "original": original.model_dump(mode="json"),
        "reviews": [
            {
                "id": review.id,  # entries carry the RECEIPT id (reviews.py:212)
                "visit_id": original.visit_id,
                "revision": 1,
                "receipt": review.model_dump(mode="json"),
            }
        ],
    }


def test_anchor_extra_key_rejected_all_surfaces(engine, store, household, schedule, t0):
    """reviews.verify_bundle compares original_receipt by EXACT dict equality —
    {id,hash,extra} signs bytes the signer committed but no verifier may
    accept (F-4)."""
    from attest.reviews import verify_bundle

    original = _visit_original(engine, store, household, t0)
    bundle = _bundle_with_anchor(engine, original, {"extra": 1})
    # native — exact-dict compare
    ok, why = verify_bundle(ReviewBundle.model_validate(bundle), public_key=engine.signer.public_key_b64)
    assert ok is False and "anchored" in why
    # embedded
    ns = _lib()
    ok, why, _ = ns["check_bundle"](bundle, engine.signer.public_key_b64)
    assert ok is False and "anchored" in why
    # and the clean bundle still passes
    good = _bundle_with_anchor(engine, original)
    ok, why, _ = ns["check_bundle"](good, engine.signer.public_key_b64)
    assert ok, why


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_anchor_extra_key_rejected_js(engine, store, household, schedule, t0, tmp_path):
    _js(tmp_path)
    original = _visit_original(engine, store, household, t0)
    bundle = _bundle_with_anchor(engine, original, {"extra": 1})
    good = _bundle_with_anchor(engine, original)
    (tmp_path / "key.txt").write_text(engine.signer.public_key_b64)
    (tmp_path / "bad.json").write_text(json.dumps(bundle), encoding="utf-8")
    (tmp_path / "good.json").write_text(json.dumps(good), encoding="utf-8")
    out = _node(
        tmp_path,
        """
(async()=>{
  const fs=require('fs'),key=fs.readFileSync('key.txt','utf8');
  const bad=await checkBundle(parseKeep(fs.readFileSync('bad.json','utf8')),key);
  const good=await checkBundle(parseKeep(fs.readFileSync('good.json','utf8')),key);
  console.log('bad:'+bad.ok+' '+bad.why);
  console.log('good:'+good.ok);
})();""",
    )
    assert "bad:false" in out, out
    assert "good:true" in out, out


def test_kind_required_everywhere(engine, store, household, schedule, t0):
    """F-13: a bundle omitting 'kind' fails model_validate (the field is
    required now) — same reject as the embedded and browser gates."""
    original = _visit_original(engine, store, household, t0)
    bundle = _bundle_with_anchor(engine, original)
    bundle.pop("kind")
    with pytest.raises(ValidationError):
        ReviewBundle.model_validate(bundle)
    ns = _lib()
    ok, why, _ = ns["check_bundle"](bundle, engine.signer.public_key_b64)
    assert ok is False and "kind" in why


# ---------- F-5/F-6/F-12: checkpoint document gates -------------------------


def test_checkpoint_doc_gates(engine, store, household, schedule, t0, tmp_path):
    """receipts:null reads as absent on all surfaces; a missing/non-dict
    'proofs' member fails everywhere; a dict 'path' never iterates keys."""
    from attest import packdiff
    from attest.disputepack import log_member

    engine.issue_coverage_attestation(household[0], t0 - timedelta(hours=2), t0 - timedelta(hours=1))
    r = store.receipts()[0]
    engine.issue_log_checkpoint()
    doc = log_member(engine, store.receipts())
    trusted = {engine.signer.public_key_b64}
    member_ids = [(r.id, r.payload_hash, r.public_key)]

    # receipts:null — same as absent on every surface
    d = dict(doc)
    d["receipts"] = None
    res, err = packdiff.check_log_pin(lambda n: json.dumps(d).encode(), member_ids, trusted)
    assert err is None and res is not None, err

    # proofs absent or junk-typed — reject everywhere
    for junk in (None, "x", 5, []):
        d2 = dict(doc)
        if junk is None:
            d2.pop("proofs", None)
        else:
            d2["proofs"] = junk
        res2, err2 = packdiff.check_log_pin(lambda n, doc=d2: json.dumps(doc).encode(), member_ids, trusted)
        assert res2 is None and err2, (junk, res2)


def test_proof_path_never_iterates_dict_keys(tmp_path):
    """path:{} on a size-1 proof must fail, not read as 'empty' — and an
    absent path at size 1 is the empty proof on every surface."""
    from attest.transparency import leaf_hash, verify_consistency, verify_inclusion

    leaf = leaf_hash(b"x")
    assert verify_inclusion(b"x", 1, 0, [], leaf) is True
    assert verify_inclusion(b"x", 1, 0, {}, leaf) is False
    assert verify_inclusion(b"x", 1, 0, "deadbeef", leaf) is False
    assert verify_consistency(leaf, 1, leaf, 1, []) is True
    assert verify_consistency(leaf, 1, leaf, 1, {}) is False
    ns = _lib()
    # leaf_hex decodes to the 32-byte leaf (a payload_hash); the size-1 root
    # is its leaf hash — sha256(b"\x00" + leaf)
    leaf_hex = "ab" * 32
    root32 = leaf_hash(bytes.fromhex(leaf_hex)).hex()
    assert ns["_merkle_inclusion"](leaf_hex, 1, 0, [], root32) is True
    assert ns["_merkle_inclusion"](leaf_hex, 1, 0, {}, root32) is False
    assert ns["_merkle_inclusion"](leaf_hex, 1, 0, "ab", root32) is False
    assert ns["_merkle_consistency"](leaf, 1, leaf, 1, {}) is False
    assert ns["_merkle_consistency"](leaf, 1, leaf, 1, []) is True


# ---------- F-9/F-10/F-14: manifest shape + receipt_hashes typing ----------


def _signed_manifest(engine, site_id, visits, receipt_hashes, extra=None):
    """A manifest plus a genuinely-signed signature_receipt over it."""
    import hashlib
    import json as _json

    manifest = {
        "schema": "attest.case-pack/1",
        "issuer_key": engine.signer.public_key_b64,
        "generated_at": "2026-03-01T00:00:00Z",
        "media_redacted": False,
        "site": {"id": site_id},
        "visits": visits,
        "attestations": [],
    }
    core = _json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(core.encode()).hexdigest()
    facts = {
        "record_type": "case_export",
        "manifest_sha256": digest,
        "visit_count": len(visits) if isinstance(visits, list) else 0,
        "receipt_hashes": receipt_hashes,
    }
    if receipt_hashes == "OMIT":
        facts.pop("receipt_hashes")  # sentinel: sign with the field absent
    if extra:
        facts.update(extra)
    sig = engine.signer.issue(
        visit_id=f"export:{site_id}:{digest[:12]}",
        sequence=store_seq_next(engine),
        prev_hash=None,
        facts=facts,
    )
    manifest["signature_receipt"] = sig.model_dump(mode="json")
    return manifest


def store_seq_next(engine):
    rs = engine.store.receipts()
    return (rs[-1].sequence if rs else 0) + 1


def test_manifest_visit_shape_gates_native(engine, household, tmp_path):
    """F-9: 'visits' must be a list on every surface — absent, null, or a
    dict is a malformed manifest, not an empty pack."""
    from attest.app import _verify_case_pack

    issuer = engine.signer.public_key_b64
    for bad_visits in (None, {}, "x", 5):
        manifest = {
            "schema": "attest.case-pack/1",
            "issuer_key": issuer,
            "site": {"id": "s"},
            "attestations": [],
        }
        if bad_visits is not None:
            manifest["visits"] = bad_visits
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest))
        ok, why = _verify_case_pack(zipfile.ZipFile(io.BytesIO(buf.getvalue())), issuer)
        assert ok is False and "visits" in why, (bad_visits, why)


def test_manifest_receipt_hashes_typing(engine, household):
    """F-10: receipt_hashes is a str->str map — a non-dict body, a non-str
    value, or a manifest entry with a non-str key/value can never equal the
    signed list on ANY surface."""
    from attest import packdiff

    issuer = engine.signer.public_key_b64
    visits = [{"visit_id": "v1", "payload_hash": "ab"}]

    good = _signed_manifest(engine, "s", visits, {"v1": "ab"})
    assert packdiff._verify_manifest_signature(good, issuer, {issuer}) is None
    ns = _lib()
    ok, _ = ns["check_manifest"](good, {issuer})
    assert ok

    # non-str signed value — Python True==1 dict-equality bridged before
    bad1 = _signed_manifest(engine, "s", visits, {"v1": True})
    assert "disagrees" in (packdiff._verify_manifest_signature(bad1, issuer, {issuer}) or "")
    ok, why = ns["check_manifest"](bad1, {issuer})
    assert ok is False and "disagrees" in why

    # receipt_hashes literal null — listed != None on the Python surfaces
    bad2 = _signed_manifest(engine, "s", visits, None)
    assert "disagrees" in (packdiff._verify_manifest_signature(bad2, issuer, {issuer}) or "")
    ok, why = ns["check_manifest"](bad2, {issuer})
    assert ok is False

    # receipt_hashes absent on a non-empty manifest — .get(...,{}) reads it
    # as {} everywhere, and listed != {} → reject
    bad3 = _signed_manifest(engine, "s", visits, "OMIT")
    assert "disagrees" in (packdiff._verify_manifest_signature(bad3, issuer, {issuer}) or "")
    ok, _ = ns["check_manifest"](bad3, {issuer})
    assert ok is False

    # int visit_id in the manifest — JS used to stringify it into a match
    bad4 = _signed_manifest(engine, "s", [{"visit_id": 5, "payload_hash": "ab"}], {"5": "ab"})
    assert "disagrees" in (packdiff._verify_manifest_signature(bad4, issuer, {issuer}) or "")
    ok, _ = ns["check_manifest"](bad4, {issuer})
    assert ok is False


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_manifest_receipt_hashes_typing_js(engine, household, tmp_path):
    _js(tmp_path)
    issuer = engine.signer.public_key_b64
    visits = [{"visit_id": "v1", "payload_hash": "ab"}]
    good = _signed_manifest(engine, "s", visits, {"v1": "ab"})
    intkey = _signed_manifest(engine, "s", [{"visit_id": 5, "payload_hash": "ab"}], {"5": "ab"})
    nullmap = _signed_manifest(engine, "s", visits, None)
    (tmp_path / "issuer.txt").write_text(issuer)
    for name, m in (("good", good), ("intkey", intkey), ("nullmap", nullmap)):
        (tmp_path / f"{name}.json").write_text(json.dumps(m), encoding="utf-8")
    out = _node(
        tmp_path,
        """
(async()=>{
  const fs=require('fs'),issuer=fs.readFileSync('issuer.txt','utf8');
  for(const n of ['good','intkey','nullmap']){
    const r=await checkManifestNode(parseKeep(fs.readFileSync(n+'.json','utf8')),new Set([issuer]));
    console.log(n+':'+r.ok);
  }
})();""",
    )
    assert "good:true" in out, out
    assert "intkey:false" in out, out
    assert "nullmap:false" in out, out


def test_prev_hash_absent_in_payload_is_null_embedded():
    """F-11: payload.get('prev_hash') reads absent as null — an envelope
    prev_hash:null then agrees (Python dict semantics), so embedded accepts
    what JS now accepts too."""
    s = Signer.ephemeral()
    payload = {"schema": "attest.receipt/1", "sequence": 1, "visit_id": "v"}  # no prev_hash key
    h = payload_hash(payload)
    r = {
        "id": "rcpt_x",
        "visit_id": "v",
        "sequence": 1,
        "prev_hash": None,
        "payload": payload,
        "payload_hash": h,
        "signature": s.sign_hash(h),
        "public_key": s.public_key_b64,
        "issued_at": "2026-03-01T00:00:00Z",
    }
    ns = _lib()
    ok, why = ns["check_receipt"](r, s.public_key_b64)
    assert ok, why
    # native Receipt model — prev_hash present-and-null validates, and the
    # payload-vs-envelope compare reads absent as null too
    from attest.ledger import verify_receipt

    ok2, why2 = verify_receipt(r, public_key=s.public_key_b64)
    assert ok2, why2


# ---------- F-16: ZIP64 sentinel fields ------------------------------------


def test_bounded_zip_rejects_zip64_sentinels():
    """A member whose central-directory size fields carry the 0xFFFFFFFF
    sentinels is ZIP64-shaped regardless of extract_version — zipfile would
    decode a smuggled extra field where the browser rejects the sentinel."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", b"hello")
    # Splice sentinel sizes into the central directory entry
    raw = bytearray(buf.getvalue())
    sig = raw.find(b"PK\x01\x02")
    assert sig > 0
    raw[sig + 20 : sig + 28] = b"\xff\xff\xff\xff\xff\xff\xff\xff"  # csize+usize
    from attest.packdiff import BoundedZip

    with pytest.raises(ValueError, match="ZIP64"):
        BoundedZip(zipfile.ZipFile(io.BytesIO(bytes(raw))))
