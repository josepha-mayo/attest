"""Round-5/6 audit regressions — verifier-parity rules proven on the raw
artifact, not just unit logic: native Python, the embedded stdlib verifier
(exec'd from its generated source), and the browser JS under node must all
give the same verdict on the same hostile bytes.
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
from attest.ledger import Signer
from attest.models import Receipt
from attest.packdiff import BoundedZip

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
    """The embedded stdlib verifier, exec'd into a namespace so its internals
    are directly testable — it is a source string, not a module."""
    ns = {}
    exec(disputepack._VERIFIER_LIB, ns)
    return ns


def _zip_rewrite(orig: bytes, replace: dict) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(orig))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n in src.namelist():
            z.writestr(n, replace.pop(n) if n in replace else src.read(n))
        for n, b in replace.items():
            z.writestr(n, b)
    return out.getvalue()


def _bundle_pack(engine, store, household, schedule, t0, tmp_path):
    """A real signed dispute pack (bundle.json + tooling members)."""
    from attest.disputepack import build_pack
    from attest.reviews import ReviewService

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    return build_pack(store, tmp_path / "media", bundle), bundle


# ---------- empty-log checkpoint guard -------------------------------------


def test_empty_log_checkpoint_refused(engine):
    """A size-0 head can never verify (tree_size >= 1 everywhere) — minting
    one would sign a permanently-invalid artifact. The engine refuses even
    though current callers pre-guard."""
    assert engine.store.receipts() == []
    with pytest.raises(ValueError, match="empty log"):
        engine.issue_log_checkpoint()


# ---------- issued_at ISO gate (models + embedded + JS) --------------------


def test_issued_at_envelope_gate_native(engine, store, household, schedule, t0):
    """The envelope's unsigned issued_at is model-typed on intake: absent →
    default; present must be an ISO-grammar instant. 'Mar 1, 2026', epoch
    ints, null, and calendar-invalid dates are all rejected — the embedded
    and JS verifiers must reject the same bytes."""
    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    r = store.receipt_for_visit(visit.id)
    good = r.model_dump(mode="json")
    for bad in ("Mar 1, 2026", "2026-02-30", "2026-03-01T25:00:00Z", 5, None, 1693526400):
        base = dict(good)
        base["issued_at"] = bad
        with pytest.raises(ValidationError):
            Receipt.model_validate(base)
    absent = dict(good)
    absent.pop("issued_at")
    assert Receipt.model_validate(absent).id == r.id  # default_factory fills it
    for ok_s in ("2026-03-01T12:00:00Z", "2026-03-01", "2026-03-01T12:00:00+02:00"):
        base = dict(good)
        base["issued_at"] = ok_s
        assert Receipt.model_validate(base).id == r.id


def test_issued_at_envelope_gate_embedded(engine, store, household, schedule, t0):
    ns = _lib()
    iso_instant, check_receipt = ns["_iso_instant"], ns["check_receipt"]
    assert iso_instant("Mar 1, 2026") is None
    assert iso_instant("2026-02-30") is None  # calendar-invalid, grammar-pass
    assert iso_instant(5) is None
    assert iso_instant(None) is None
    assert iso_instant("2026-03-01T12:00:00Z") is not None
    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    r = store.receipt_for_visit(visit.id).model_dump(mode="json")
    key = r["public_key"]
    ok, _ = check_receipt(r, key)
    assert ok
    bad = dict(r)
    bad["issued_at"] = "Mar 1, 2026"  # unsigned envelope garbage — sig unaffected
    assert check_receipt(bad, key) == (False, "malformed receipt")
    bad["issued_at"] = None  # present-but-null is NOT 'absent' — pydantic rejects
    assert check_receipt(bad, key) == (False, "malformed receipt")


# ---------- embedded shape guards (non-dict members, missing fields) -------


def test_prev_hash_absent_vs_null_all_surfaces(engine, store, household, schedule, t0):
    """prev_hash is required-NULLABLE: absent fails pydantic, explicit null
    is the chain head. The embedded guard must distinguish absence (reject
    cleanly — r["prev_hash"] would KeyError) from null; JS rejects
    undefined outright."""
    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    r = store.receipt_for_visit(visit.id).model_dump(mode="json")
    absent = dict(r)
    absent.pop("prev_hash")
    with pytest.raises(ValidationError):
        Receipt.model_validate(absent)
    ns = _lib()
    assert ns["check_receipt"](absent, r["public_key"]) == (False, "malformed receipt")
    # This receipt IS a chain head — its payload carries prev_hash:null, so
    # explicit null agrees and the (untouched, still-valid) signature passes.
    nul = dict(r)
    nul["prev_hash"] = None
    ok, _ = ns["check_receipt"](nul, r["public_key"])
    assert ok is True
    # A non-null string the payload doesn't carry disagrees — cleanly.
    wrong = dict(r)
    wrong["prev_hash"] = "00" * 32
    ok2, why2 = ns["check_receipt"](wrong, r["public_key"])
    assert ok2 is False and "envelope fields" in why2


def test_embedded_shape_guards_never_crash():
    """Hostile pool members and bundle parts must fail cleanly — a TypeError
    or KeyError escaping the verifier is a crash-vs-clean-fail parity bug."""
    ns = _lib()
    check_receipt, check_bundle = ns["check_receipt"], ns["check_bundle"]
    assert check_receipt(5, "k") == (False, "malformed receipt")
    assert check_receipt("x", "k") == (False, "malformed receipt")
    bare = {
        "public_key": "k",
        "signature": "x",
        "id": "i",
        "visit_id": "v",
        "payload_hash": "h",
        "sequence": 1,
        "prev_hash": None,
    }
    assert check_receipt(bare, "k") == (False, "malformed receipt")  # no payload
    bare2 = dict(bare, payload=5)
    assert check_receipt(bare2, "k") == (False, "malformed receipt")
    assert check_bundle(5, "k")[0] is False
    ok, why, _ = check_bundle({"kind": "attest.review_bundle/1", "original": 5, "reviews": []}, "k")
    assert ok is False
    ok, why, _ = check_bundle({"kind": "attest.review_bundle/1", "original": None, "reviews": [3]}, "k")
    assert ok is False
    ok, why, _ = check_bundle(
        {"kind": "attest.review_bundle/1", "original": {"public_key": "k"}, "reviews": ["x"]},
        "k",
    )
    assert ok is False


# ---------- F7: rotation-pool members are inert-skipped --------------------


def test_rotation_pool_junk_members_are_inert(engine, store, household, schedule, t0, tmp_path):
    """key_rotations.json is unsigned pool content: malformed members can
    never extend trust (they aren't signatures), so they are skipped — but
    a non-list 'rotations' is a malformed document and fails on every
    surface."""
    from attest.app import _verify_pack

    data, bundle = _bundle_pack(engine, store, household, schedule, t0, tmp_path)
    issuer = engine.signer.public_key_b64
    ok, detail = _verify_pack(data, issuer)
    assert ok, detail
    junky = _zip_rewrite(data, {"key_rotations.json": json.dumps({"rotations": [3, "x", {}]}).encode()})
    ok2, _ = _verify_pack(junky, issuer)
    assert ok2, "malformed pool members must be inert-skipped, not fatal"
    broken = _zip_rewrite(data, {"key_rotations.json": json.dumps({"rotations": 5}).encode()})
    ok3, detail3 = _verify_pack(broken, issuer)
    assert not ok3 and "key_rotations.json" in detail3


# ---------- F8: consistency-doc header strictness --------------------------


def test_consistency_response_headers_must_match_request(engine, store, household, schedule, t0):
    """A served consistency proof with string-typed or mismatched first/
    tree_size headers is not an answer to the question asked — check()
    rejects it rather than letting a node list stand in for the wrong
    bridge (the JS live-check now enforces the identical rule)."""
    from attest import logmonitor

    site = household[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=2), t0 - timedelta(hours=1))
    cp1 = engine.issue_log_checkpoint()
    old_size = cp1.payload["tree_size"]
    doc = {
        "schema": "attest.issuer/1",
        "issuer_key": engine.signer.public_key_b64,
        "key_receipts": [],
    }
    head1 = {
        "tree_size": old_size,
        "root_sha256": cp1.payload["root_sha256"],
        "checkpoint": cp1.model_dump(mode="json"),
    }
    state, ok, _ = logmonitor.check(None, doc, head1, lambda f, s: None, "t1")
    assert ok, "first contact pins the signed head"

    # Grow the log, then mint a legacy-shape head (no extends) so check()
    # has to use the consistency endpoint.
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=4), t0 - timedelta(hours=3))
    size, root = engine.log_head()
    cp2 = engine.signer.issue(
        visit_id=f"log:{size}:{root.hex()[:16]}",
        sequence=store.receipts()[-1].sequence + 1,
        prev_hash=store.receipts()[-1].payload_hash,
        facts={"record_type": "log_checkpoint", "tree_size": size, "root_sha256": root.hex()},
    )
    head = {
        "tree_size": size,
        "root_sha256": cp2.payload["root_sha256"],
        "checkpoint": cp2.model_dump(mode="json"),
    }

    def good(first, sz):
        return engine.consistency_proof(first, sz)

    new_state, ok, lines = logmonitor.check(state, doc, head, good, "t2")
    assert ok, lines

    # Header fields as strings — same bytes the JS gate rejects.
    real = engine.consistency_proof(old_size, size) or {}

    def lying(first, sz):
        return {**real, "first": str(old_size)}

    new_state2, ok2, lines2 = logmonitor.check(state, doc, head, lying, "t3")
    assert not ok2 and any("different tree sizes" in ln for ln in lines2)

    # Headers answering a different bridge entirely.
    def off(first, sz):
        return {"first": 1, "tree_size": 1, "proof": []}

    _, ok3, lines3 = logmonitor.check(state, doc, head, off, "t4")
    assert not ok3 and any("different tree sizes" in ln for ln in lines3)


# ---------- F9: extends self-check in pack paths ---------------------------


def _forged_extends_checkpoint(engine, store, cp):
    """Same signed head as ``cp`` but with an extends bridge that cannot
    verify — the payload is genuinely signed, so surfaces that skip the
    self-check would accept it."""
    bad = {
        k: v
        for k, v in cp.payload.items()
        if k not in {"schema", "sequence", "prev_hash", "receipt_id", "issued_at", "visit_id"}
    }
    bad["extends"] = {"first": 1, "first_root_sha256": "00" * 32, "proof": []}
    return engine.signer.issue(
        visit_id="log:forged",
        sequence=cp.sequence + 1,
        prev_hash=cp.payload_hash,
        facts=bad,
    )


def test_log_pin_extends_selfcheck_packdiff(engine, store, household, schedule, t0):
    """packdiff.check_log_pin convicts a checkpoint whose signed extends
    bridge does not verify — the standalone checkpoint path already did;
    the pack path must too."""
    from attest import packdiff
    from attest.disputepack import log_member

    engine.issue_coverage_attestation(household[0], t0 - timedelta(hours=2), t0 - timedelta(hours=1))
    r = store.receipts()[0]
    cp = engine.issue_log_checkpoint()
    doc = log_member(engine, store.receipts())
    trusted = {engine.signer.public_key_b64}
    member_ids = [(r.id, r.payload_hash, r.public_key)]

    raw = json.dumps(doc).encode()
    res, err = packdiff.check_log_pin(lambda n: raw, member_ids, trusted)
    assert err is None and res is not None, err

    forged_doc = dict(doc)
    forged_doc["checkpoint"] = _forged_extends_checkpoint(engine, store, cp).model_dump(mode="json")
    res2, err2 = packdiff.check_log_pin(lambda n: json.dumps(forged_doc).encode(), member_ids, trusted)
    assert res2 is None and "extends bridge" in err2


def test_log_pin_extends_selfcheck_embedded(engine, store, household, schedule, t0, tmp_path):
    """The embedded verifier's check_log must convict the same forged
    checkpoint — identical bytes, identical verdict."""
    from attest.disputepack import log_member

    engine.issue_coverage_attestation(household[0], t0 - timedelta(hours=2), t0 - timedelta(hours=1))
    r = store.receipts()[0]
    cp = engine.issue_log_checkpoint()
    doc = log_member(engine, store.receipts())
    forged_doc = dict(doc)
    forged_doc["checkpoint"] = _forged_extends_checkpoint(engine, store, cp).model_dump(mode="json")
    (tmp_path / "log_checkpoint.json").write_text(json.dumps(forged_doc), encoding="utf-8")
    ns = _lib()
    trusted = {engine.signer.public_key_b64}
    with pytest.raises(SystemExit) as exc:
        ns["check_log"](tmp_path, trusted, [r.model_dump(mode="json")])
    assert "extends bridge" in str(exc.value)


def test_extends_malformed_proof_is_absent_not_crash():
    """A non-list extends.proof is 'no usable bridge', not an exception —
    verify_extends and its embedded mirror agree."""
    from attest.transparency import verify_extends

    ns = _lib()
    extends_ok = ns["_extends_ok"]
    for junk in ("x", 5, {"proof": "nope"}, {"proof": [1, 2]}, None):
        payload = {"tree_size": 1, "root_sha256": "ab" * 32, "extends": junk}
        assert verify_extends(payload) is None
        assert extends_ok(payload) is None


# ---------- F10: zip member bounds -----------------------------------------


def test_bounded_zip_rejects_foreign_compression_zip64_and_oversize(tmp_path):
    """Python's zipfile will happily read bzip2/lzma members and ZIP64 that
    the browser verifier cannot — the shared rule is fail, on the same
    fields, on both surfaces."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_BZIP2) as z:
        z.writestr("a.txt", b"x" * 10)
    with pytest.raises(ValueError, match="compression method"):
        BoundedZip(zipfile.ZipFile(io.BytesIO(buf.getvalue())))

    buf2 = io.BytesIO()
    with zipfile.ZipFile(buf2, "w") as z:
        zi = zipfile.ZipInfo("big.txt")
        with z.open(zi, "w", force_zip64=True) as f:
            f.write(b"x")
    with pytest.raises(ValueError, match="ZIP64"):
        BoundedZip(zipfile.ZipFile(io.BytesIO(buf2.getvalue())))

    buf3 = io.BytesIO()
    with zipfile.ZipFile(buf3, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("blob", b"y" * 32)
    z3 = BoundedZip(zipfile.ZipFile(io.BytesIO(buf3.getvalue())), per_file=8)
    with pytest.raises(ValueError, match="per-file|verification bound"):
        z3.read("blob")


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_zip_reader_bounds_and_strict_literals(tmp_path):
    """The browser zip reader rejects the same members BoundedZip does —
    foreign compression, ZIP64, over-64MB members — and parseKeep rejects
    non-JSON number spellings Python's strict loader rejects."""
    import re

    from attest.verifyjs import VERIFY_HTML

    m = re.search(r"<script>(.*)</script>", VERIFY_HTML, re.S)
    (tmp_path / "verify.js").write_text(m.group(1), encoding="utf-8")

    zips = {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_BZIP2) as z:
        z.writestr("a.txt", b"x")
    zips["bz"] = buf.getvalue()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        with z.open(zipfile.ZipInfo("big.txt"), "w", force_zip64=True) as f:
            f.write(b"x")
    zips["z64"] = buf.getvalue()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("huge", b"\x00" * (65 * 1024 * 1024))  # compresses tiny, inflates >64MB
    zips["fat"] = buf.getvalue()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("fine.txt", b"ok")
    zips["ok"] = buf.getvalue()

    for name, data in zips.items():
        (tmp_path / f"{name}.zip").write_bytes(data)

    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
eval(src + `
(async()=>{
  for(const n of ['bz','z64','fat','ok']){
    const b=fs.readFileSync(process.argv[3]+'/'+n+'.zip');
    const f={arrayBuffer:async()=>b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength)};
    try{await readZipEntries(f);console.log(n+':OK');}
    catch(e){console.log(n+':FAIL:'+e.message);}
  }
  for(const s of ['{"a":01}','[{"k":1.5e3}]','{"a":5.}','{"a":-0.0}']){
    try{parseKeep(s);console.log('lit '+s+':accept');}
    catch(e){console.log('lit '+s+':reject');}
  }
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "bz:FAIL" in out and "compression method" in out
    assert "z64:FAIL" in out and "ZIP64" in out
    assert "fat:FAIL" in out and "64 MB" in out
    assert "ok:OK" in out
    assert 'lit {"a":01}:reject' in out
    assert 'lit [{"k":1.5e3}]:accept' in out
    assert 'lit {"a":5.}:reject' in out
    assert 'lit {"a":-0.0}:accept' in out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_extends_and_issued_at_gates(tmp_path):
    """_extOk mirrors verify_extends tri-state (true/false/null), and
    checkReceipt rejects a non-ISO envelope issued_at even on /1 receipts —
    both sides of every gate, in the browser's own runtime."""
    import re

    from attest.transparency import consistency_nodes, leaf_hash
    from attest.verifyjs import VERIFY_HTML

    m = re.search(r"<script>(.*)</script>", VERIFY_HTML, re.S)
    (tmp_path / "verify.js").write_text(m.group(1), encoding="utf-8")

    leaves = [b"leaf-one", b"leaf-two"]
    r1 = leaf_hash(leaves[0])
    nodes = consistency_nodes(leaves, 1)
    from attest.transparency import root

    r2 = root(leaves)
    good_ext = {
        "tree_size": 2,
        "root_sha256": r2.hex(),
        "extends": {
            "first": 1,
            "first_root_sha256": r1.hex(),
            "proof": [n.hex() for n in nodes],
        },
    }
    bad_ext = dict(good_ext)
    bad_ext["extends"] = {"first": 1, "first_root_sha256": "00" * 32, "proof": []}

    s = Signer.ephemeral()
    receipt = s.issue(
        visit_id="vis_x", sequence=1, prev_hash=None, facts={"record_type": "visit"}
    ).model_dump(mode="json")
    receipt["issued_at"] = "not a date"  # unsigned envelope — signature still valid

    driver = f"""
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
eval(src + `
const good={json.dumps(good_ext)},bad={json.dumps(bad_ext)},rc={json.dumps(receipt)};
(async()=>{{
  console.log('ext_good:'+(await _extOk(good)));
  console.log('ext_bad:'+(await _extOk(bad)));
  console.log('ext_junk:'+(await _extOk({{tree_size:1,root_sha256:"ab",extends:{{proof:"x"}}}})));
  console.log('ext_absent:'+(await _extOk({{tree_size:1,root_sha256:"ab"}})));
  console.log('rc_bad_issued:'+(await checkReceipt(parseKeep(JSON.stringify(rc)))).why);
}})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js"], cwd=tmp_path, capture_output=True, text=True, timeout=180
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "ext_good:true" in out, out
    assert "ext_bad:false" in out, out
    assert "ext_junk:null" in out, out
    assert "ext_absent:null" in out, out
    assert "rc_bad_issued:malformed receipt" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_model_int_arbitrary_precision(tmp_path):
    """Pydantic ints are unbounded; JSON.parse rounds past 2**53. An envelope
    sequence spelled 2**53+1 vs payload 2**53+0 is 'equal' to a Number unwrap
    but unequal to Python — the keep-node literal must carry the exactness."""
    import re

    from attest.verifyjs import VERIFY_HTML

    m = re.search(r"<script>(.*)</script>", VERIFY_HTML, re.S)
    (tmp_path / "verify.js").write_text(m.group(1), encoding="utf-8")

    s = Signer.ephemeral()
    big = 2**53 + 1
    rc = s.issue(visit_id="vis_x", sequence=big, prev_hash=None, facts={"record_type": "visit"}).model_dump(
        mode="json"
    )
    off_one = dict(rc)
    off_one["sequence"] = 2**53  # rounds to the same Number as 2**53+1
    spelled = dict(rc)
    spelled["sequence"] = str(big)  # digit-string — malformed under strict-int

    embedded = _lib()

    # The exact digits must reach parseKeep as TEXT — embedded JS literals or
    # JSON.stringify would round through Number before the verifier sees them.
    for name, doc in (("good", rc), ("off", off_one), ("strd", spelled)):
        (tmp_path / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")

    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
eval(src + `
(async()=>{
  const g=await checkReceipt(parseKeep(fs.readFileSync(process.argv[3]+'/good.json','utf8')));
  const o=await checkReceipt(parseKeep(fs.readFileSync(process.argv[3]+'/off.json','utf8')));
  const sd=await checkReceipt(parseKeep(fs.readFileSync(process.argv[3]+'/strd.json','utf8')));
  console.log('exact:'+g.ok);
  console.log('offone_ok:'+o.ok+' why:'+o.why);
  console.log('string_ok:'+sd.ok);
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # Python/embedded oracle — the same docs, same verdicts. A digit-STRING
    # sequence is now malformed on every surface: the model requires a real
    # JSON integer (round-7 strict-int gate — "5" is not 5 anywhere), so the
    # embedded verifier and the browser reject it too.
    e_ok, _ = embedded["check_receipt"](rc, s.public_key_b64)
    e_off, e_why = embedded["check_receipt"](off_one, s.public_key_b64)
    e_str, _ = embedded["check_receipt"](spelled, s.public_key_b64)
    assert e_ok and not e_off and not e_str
    assert "exact:true" in out, out
    assert "offone_ok:false" in out and "envelope fields disagree" in out, out
    assert "string_ok:false" in out, out
