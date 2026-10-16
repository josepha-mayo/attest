"""Round-8 audit regressions — the third adversarial verifier-parity pass.

Same rule as r6/r7: identical bytes must produce identical verdicts on
native Python, the embedded stdlib verifier, and the browser JS (under
node). Each test names the finding it pins.
"""

import io
import json
import shutil
import subprocess
import sys
import zipfile

import pytest
from pydantic import ValidationError
from ring_sandbox import WebhookEvent, webhooks

from attest import disputepack, packdiff
from attest.ledger import Signer, payload_hash, verify_receipt
from attest.models import Receipt

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


def _zip_rewrite(orig: bytes, replace: dict) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(orig))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n in src.namelist():
            z.writestr(n, replace.pop(n) if n in replace else src.read(n))
        for n, b in replace.items():
            z.writestr(n, b)
    return out.getvalue()


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


# ---------- F-1: non-canonical Ed25519 encodings are forgeries --------------
#
# OpenSSL (ref10 family) accepts y >= p and the sign-bit-set identity /
# order-2 encodings the browser's decodePoint rejects — under such a key
# the forgery S=0, R=identity satisfies S*B == R + h*A with no private key.
# The canonicality gate must reject them before OpenSSL ever sees them.

_IDENTITY_SIGNBIT = bytes.fromhex("01" + "00" * 30 + "80")  # identity, sign=1
_Y_Q_PLUS_1 = bytes.fromhex("ee" + "ff" * 30 + "7f")  # y = q+1
_ORDER2_SIGNBIT = bytes.fromhex("ec" + "ff" * 30 + "ff")  # y = q-1, sign=1
_FORGERY_SIG = bytes.fromhex("01" + "00" * 63)  # R = identity, S = 0


def test_f1_noncanonical_points_rejected_native_and_embedded():
    import base64

    s = Signer.ephemeral()
    good = _signed_receipt(s, 1, {"visit_id": "v", "record_type": "x"})
    ok, _ = verify_receipt(good, public_key=s.public_key_b64)
    assert ok
    ns = _lib()
    for pk in (_IDENTITY_SIGNBIT, _Y_Q_PLUS_1, _ORDER2_SIGNBIT):
        bad = dict(
            good,
            public_key=base64.b64encode(pk).decode(),
            signature=base64.b64encode(_FORGERY_SIG).decode(),
        )
        ok, why = verify_receipt(bad)
        assert ok is False and why == "signature invalid", (pk.hex(), why)
        eok, ewhy = ns["check_receipt"](bad, base64.b64encode(pk).decode())
        assert eok is False and ewhy == "signature invalid", (pk.hex(), ewhy)


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_f1_noncanonical_points_rejected_js(tmp_path):
    _js(tmp_path)
    vectors = [_IDENTITY_SIGNBIT, _Y_Q_PLUS_1, _ORDER2_SIGNBIT]
    for i, v in enumerate(vectors):
        (tmp_path / f"v{i}.hex").write_text(v.hex())
    out = _node(
        tmp_path,
        """
(async()=>{
  const fs=require('fs');
  const hex=h=>BigInt('0x'+h);
  for(let i=0;i<3;i++){
    const b=Uint8Array.from(Buffer.from(fs.readFileSync('v'+i+'.hex','utf8'),'hex'));
    console.log('v'+i+':'+(decodePoint(b)===null));
  }
})();""",
    )
    for i in range(3):
        assert f"v{i}:true" in out, out


# ---------- F-2: Receipt.id is required, not minted -------------------------


def test_f2_missing_id_rejected_all_surfaces():
    """The default_factory silently generated a missing id — a pass on every
    pydantic surface where embedded/JS said 'malformed receipt'."""
    s = Signer.ephemeral()
    good = _signed_receipt(s, 1, {"visit_id": "v", "record_type": "x"})
    bad = dict(good)
    bad.pop("id")
    with pytest.raises(ValidationError):
        Receipt.model_validate(bad)
    ns = _lib()
    ok, why = ns["check_receipt"](bad, s.public_key_b64)
    assert ok is False and why == "malformed receipt"


# ---------- F-4: packdiff manifest compares are unconditional ----------------


def _case_pack_zip(engine, store, household, schedule, t0, tmp_path, **kw):
    """Real signed case-pack bytes for one observed visit."""
    from attest.reviews import ReviewService, countersign_status

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]
    return disputepack.build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        **kw,
    ), visit


def test_f4_manifest_entry_missing_hash_flagged_packdiff(engine, store, household, schedule, t0, tmp_path):
    """entry.get('payload_hash') and ... used to SKIP the compare when the
    field was absent — an unsigned manifest could name a visit without
    committing to its hash."""
    data, visit = _case_pack_zip(engine, store, household, schedule, t0, tmp_path)
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("manifest.json"))
    manifest["visits"][0].pop("payload_hash", None)
    rewritten = _zip_rewrite(data, {"manifest.json": json.dumps(manifest).encode()})
    art = packdiff.load_artifact(_write(tmp_path, rewritten), key=engine.signer.public_key_b64)
    assert art["verify_failures"], art["verify_failures"]


def test_f4_manifest_entry_missing_hash_flagged_app(engine, store, household, schedule, t0, tmp_path):
    from attest.app import _verify_pack

    data, visit = _case_pack_zip(engine, store, household, schedule, t0, tmp_path)
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("manifest.json"))
    manifest["visits"][0].pop("payload_hash", None)
    rewritten = _zip_rewrite(data, {"manifest.json": json.dumps(manifest).encode()})
    ok, why = _verify_pack(rewritten, engine.signer.public_key_b64)
    assert ok is False and "manifest" in why


def _write(tmp_path, data: bytes, name="pack.zip"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


# ---------- F-7/F-12: media digest + redaction agreement in packdiff --------


def _bundle_pack(engine, store, household, schedule, t0, tmp_path):
    from attest.disputepack import build_pack
    from attest.reviews import ReviewService

    visit = engine.ingest(event(household[2], t0)).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    return build_pack(store, tmp_path / "media", bundle), bundle


def test_f7_packdiff_hashes_media_members(engine, store, household, schedule, t0, tmp_path):
    """packdiff used to exempt media/ members on the assumption an upstream
    check hashed them — nothing did. A smuggled member must flag now."""
    data, bundle = _bundle_pack(engine, store, household, schedule, t0, tmp_path)
    smuggled = _zip_rewrite(data, {"media/evil.png": b"not evidence"})
    art = packdiff.load_artifact(_write(tmp_path, smuggled), key=engine.signer.public_key_b64)
    assert any("evidence" in f for f in art["verify_failures"]), art["verify_failures"]


def test_f7_packdiff_flags_missing_media(engine, store, household, schedule, t0, tmp_path):
    """A signed digest neither present nor withheld is missing media."""
    data, bundle = _bundle_pack(engine, store, household, schedule, t0, tmp_path)
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    media = [n for n in names if n.startswith("media/") and not n.endswith("/")]
    if not media:
        pytest.skip("visit captured no media to drop")
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n in src.namelist():
            if n != media[0]:
                z.writestr(n, src.read(n))
    art = packdiff.load_artifact(_write(tmp_path, out.getvalue()), key=engine.signer.public_key_b64)
    assert any("missing" in f or "withheld" in f for f in art["verify_failures"]), art["verify_failures"]


def test_f12_media_withheld_compared_even_without_marker(engine, store, household, schedule, t0, tmp_path):
    """media_withheld:['x'] with NO redaction.json marker must disagree —
    the absent marker can't skip the compare."""
    data, visit = _case_pack_zip(engine, store, household, schedule, t0, tmp_path)
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("manifest.json"))
    manifest["visits"][0]["media_withheld"] = ["x" * 64]
    rewritten = _zip_rewrite(data, {"manifest.json": json.dumps(manifest).encode()})
    art = packdiff.load_artifact(_write(tmp_path, rewritten), key=engine.signer.public_key_b64)
    assert any("withheld" in f or "disagrees" in f for f in art["verify_failures"]), art["verify_failures"]
    from attest.app import _verify_pack

    ok, why = _verify_pack(rewritten, engine.signer.public_key_b64)
    assert ok is False and "disagrees" in why


def test_f12_marker_listing_unknown_digest_fails(engine, store, household, schedule, t0, tmp_path):
    """redaction.json naming a digest the signed evidence never wrote is
    itself suspicious — a withheld claim must never mint coverage."""
    data, bundle = _bundle_pack(engine, store, household, schedule, t0, tmp_path)
    marker = json.dumps({"withheld_digests": ["f" * 64]}).encode()
    rewritten = _zip_rewrite(data, {"redaction.json": marker})
    art = packdiff.load_artifact(_write(tmp_path, rewritten), key=engine.signer.public_key_b64)
    assert any("evidence" in f for f in art["verify_failures"]), art["verify_failures"]


# ---------- F-8/F-13: embedded member sweeps fail closed ---------------------


def _run_case(pack_dir, *args):
    return subprocess.run(
        [sys.executable, "verify_case.py", *args],
        cwd=pack_dir,
        capture_output=True,
        text=True,
    )


def _extract_case_pack(engine, store, household, schedule, t0, tmp_path):
    data, _ = _case_pack_zip(engine, store, household, schedule, t0, tmp_path)
    out = tmp_path / "case"
    zipfile.ZipFile(io.BytesIO(data)).extractall(out)
    return out


def test_f8_attestations_dir_sweeps_every_member(engine, store, household, schedule, t0, tmp_path):
    """glob('*.json') missed non-.json files and subdirs under attestations/.

    An EMPTY directory is a container artifact — zip extractors synthesize
    intermediate dirs with no member behind them, so only a directory
    carrying content can smuggle. The empty case is still caught at zip
    level: the signed pack_members list is exact, so a stray `subdir/` zip
    entry fails the member check (test_parity's zip-side sweeps cover it)."""
    pack = _extract_case_pack(engine, store, household, schedule, t0, tmp_path)
    clean = _run_case(pack)
    assert clean.returncode == 0, clean.stderr + clean.stdout
    for member, is_dir in (("evil.txt", False), ("subdir", True)):
        target = pack / "attestations" / member
        if is_dir:
            target.mkdir(parents=True, exist_ok=True)
            (target / "payload.txt").write_text("smuggled")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("smuggled")
        res = _run_case(pack)
        assert res.returncode != 0, (member, res.stdout)
        if is_dir:
            (target / "payload.txt").unlink()
            target.rmdir()
        else:
            target.unlink()


def test_f8_visits_dir_rejects_plain_files(engine, store, household, schedule, t0, tmp_path):
    """Only directories named for listed visit_ids may live under visits/."""
    pack = _extract_case_pack(engine, store, household, schedule, t0, tmp_path)
    (pack / "visits" / "readme.txt").write_text("smuggled")
    res = _run_case(pack)
    assert res.returncode != 0 and "not in the signed manifest" in res.stdout, res.stdout


def test_f13_bundle_main_sweeps_unconditionally(tmp_path):
    """The markers-gated sweep meant a bare bundle.json + evil.txt verified —
    the zip surfaces fail that member list, so the dir form must too. (A
    real pack keeps media/, which WAS a marker — the hole needs a minimal
    pack: signed bundle with no evidence, verifier, smuggled file.)"""
    s = Signer.ephemeral()
    original = _signed_receipt(s, 1, {"visit_id": "v", "record_type": "x"})
    bundle = {"kind": "attest.review_bundle/1", "original": original, "reviews": []}
    out = tmp_path / "pack"
    out.mkdir()
    (out / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
    (out / "verify_bundle.py").write_text(disputepack._VERIFIER, encoding="utf-8")
    (out / "evil.txt").write_text("smuggled")
    res = subprocess.run(
        [sys.executable, "verify_bundle.py", "bundle.json"],
        cwd=out,
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0 and "not part of the pack format" in res.stdout + res.stderr, (
        res.stdout,
        res.stderr,
    )


# ---------- F-10: packdiff bounds DECLARED size, not just bytes read --------


def _zip_with_lying_usize(member="big.txt", declared=257 * 1024 * 1024) -> bytes:
    """A small zip whose central-directory entry claims a >256MB usize —
    the member is never read, so only the declared-size pre-check sees it."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(member, b"tiny")
    data = bytearray(buf.getvalue())
    idx = data.find(b"PK\x01\x02")
    assert idx >= 0
    # usize sits at +24 in the central header (sig..csize fields before it)
    data[idx + 24 : idx + 28] = declared.to_bytes(4, "little")
    return bytes(data)


def test_f10_packdiff_bounds_declared_size(tmp_path):
    data = _zip_with_lying_usize()
    with pytest.raises(Exception, match="too large|256"):
        packdiff.load_artifact(_write(tmp_path, data))


# ---------- F-15: malformed base64 is 'signature invalid', not a crash ------


def test_f15_bad_base64_is_clean_fail_embedded():
    """_unb64 raising inside check_receipt made a 'verifier error' where
    verify_receipt returns the same verdict cleanly."""
    s = Signer.ephemeral()
    good = _signed_receipt(s, 1, {"visit_id": "v", "record_type": "x"})
    ns = _lib()
    for field in ("signature", "public_key"):
        bad = dict(good, **{field: "!!!not-base64!!!"})
        key = bad["public_key"]
        ok, why = ns["check_receipt"](bad, key)
        assert ok is False and why == "signature invalid", (field, why)
    ok, why = verify_receipt(dict(good, signature="!!!"))
    assert ok is False and why == "signature invalid"


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_f15_bad_base64_is_clean_fail_js(tmp_path):
    """atob() throwing inside checkReceipt used to abort the whole verify —
    it must return {ok:false} like Python's inert skip."""
    _js(tmp_path)
    out = _node(
        tmp_path,
        """
(async()=>{
  const p=parseKeep('{"schema":"attest.receipt/1","sequence":1,"visit_id":"v",'
    +'"prev_hash":null,"record_type":"x"}');
  const h=await sha256hex(new TextEncoder().encode(canonical(p)));
  const r=parseKeep(JSON.stringify({id:'x',visit_id:'v',sequence:1,prev_hash:null,
    public_key:'!!!',payload_hash:h,signature:'!!!',
    payload:{schema:'attest.receipt/1',sequence:1,visit_id:'v',prev_hash:null,record_type:'x'},
    issued_at:'2026-03-01T00:00:00Z'}));
  const c=await checkReceipt(r);
  console.log('res:'+c.ok+' '+c.why);
})();""",
    )
    assert "res:false signature invalid" in out, out


# ---------- F-6: digests() reads payload.evidence only -----------------------


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_f6_digests_is_evidence_only(tmp_path):
    """A media_sha256 nested outside payload.evidence must neither mint a
    'digest matches' for a smuggled file nor flag a 'missing' digest the
    signed evidence never declared."""
    _js(tmp_path)
    out = _node(
        tmp_path,
        """
(async()=>{
  const d=digests({evidence:[{media_sha256:'a'.repeat(64)}],
    details:{media_sha256:'b'.repeat(64)},notes:[{media_sha256:'c'.repeat(64)}]});
  console.log('n:'+d.length+' '+d.join(',').slice(0,1));
  const d2=digests({evidence:'x',other:{media_sha256:'a'.repeat(64)}});
  console.log('n2:'+d2.length);
})();""",
    )
    assert "n:1 a" in out, out
    assert "n2:0" in out, out


# ---------- F-14: >2^53 sequence sort order is exact -------------------------


def _rotation_pair(visit_id="v"):
    """Two consented rotations whose envelope sequences COLLIDE under JS
    Number rounding (2^53 exact vs 2^53+1 -> 2^53) but order distinctly as
    exact ints — the pivot pick must follow the exact order."""
    root, s1, s2 = Signer.ephemeral(), Signer.ephemeral(), Signer.ephemeral()
    rot_a = root.issue(
        visit_id=visit_id,
        sequence=2**53,
        prev_hash=None,
        facts={
            "record_type": "key_rotation",
            "previous_key": root.public_key_b64,
            "new_key": s1.public_key_b64,
        },
    )
    adopt_a = s1.issue(
        visit_id=visit_id,
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "key_adoption",
            "rotation_receipt": {"id": rot_a.id, "hash": rot_a.payload_hash},
        },
    )
    rot_b = root.issue(
        visit_id=visit_id,
        sequence=2**53 + 1,
        prev_hash=None,
        facts={
            "record_type": "key_rotation",
            "previous_key": root.public_key_b64,
            "new_key": s2.public_key_b64,
        },
    )
    adopt_b = s2.issue(
        visit_id=visit_id,
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "key_adoption",
            "rotation_receipt": {"id": rot_b.id, "hash": rot_b.payload_hash},
        },
    )
    return root, s1, s2, [rot_a, adopt_a, rot_b, adopt_b]


def test_f14_descendant_keys_exact_int_order_embedded():
    """disputepack.descendant_keys sorts candidates on raw ints — 2^53+1
    outranks 2^53 exactly, picking s2's pivot regardless of pool order."""
    root, s1, s2, receipts = _rotation_pair()
    ns = _lib()
    pool = [r.model_dump(mode="json") for r in receipts]
    got = ns["descendant_keys"](root.public_key_b64, pool)
    assert got == {root.public_key_b64, s2.public_key_b64}, got


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_f14_descendant_keys_exact_int_order_js(tmp_path):
    """toJS Numbers round 2^53+1 to 2^53 — the sort key must be the verbatim
    literal via _pyModelInt (BigInt), or a stable-sort tie lets pool order
    pick the WRONG successor."""
    _js(tmp_path)
    root, s1, s2, receipts = _rotation_pair()
    pool = [r.model_dump(mode="json") for r in receipts]
    (tmp_path / "pool.json").write_text(json.dumps(pool), encoding="utf-8")
    (tmp_path / "root.txt").write_text(root.public_key_b64)
    (tmp_path / "s2.txt").write_text(s2.public_key_b64)
    out = _node(
        tmp_path,
        """
(async()=>{
  const fs=require('fs');
  const pool=parseKeep(fs.readFileSync('pool.json','utf8'));
  const root=fs.readFileSync('root.txt','utf8'),s2=fs.readFileSync('s2.txt','utf8');
  const t=await descendantKeys(root,pool.v);
  console.log('has:'+t.has(s2)+' size:'+t.size);
})();""",
    )
    assert "has:true size:2" in out, out
