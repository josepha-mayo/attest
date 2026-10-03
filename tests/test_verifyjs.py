"""The browser verifier embedded in packs is real crypto, not packaging:

the same <script> block is executed under node against a Python-signed receipt
chain — a valid chain verifies, a tampered payload and a wrong key both fail.
Skipped when node is not installed (CI without a JS runtime still passes).
"""

import io
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from ring_sandbox import WebhookEvent, webhooks

from attest.disputepack import build_pack
from attest.ledger import Signer
from attest.verifyjs import VERIFY_HTML

NODE = shutil.which("node")


def _script() -> str:
    m = re.search(r"<script>(.*)</script>", VERIFY_HTML, re.S)
    assert m, "verify.html has no script block"
    return m.group(1)


def _chain():
    """A bundle-shaped pair: the original carries a global chain sequence (it
    legitimately interleaves with coverage certs/anchors/digests in the store)
    while the review is numbered within the visit — sequence == revision."""
    s = Signer.ephemeral()
    r1 = s.issue(
        visit_id="vis_a",
        sequence=7,
        prev_hash="aa" * 32,
        facts={"record_type": "visit", "coverage": {"fraction": 0.047619047619047616}},
    )
    r2 = s.issue(
        visit_id="vis_a",
        sequence=1,
        prev_hash=r1.payload_hash,
        facts={
            "record_type": "review",
            "original_receipt": {"id": r1.id, "hash": r1.payload_hash},
            "statement": "tést — non-ascii",
        },
    )
    return s, r1, r2


def _bundle(r1, r2) -> str:
    import json

    return json.dumps(
        {
            "kind": "attest.review_bundle/1",
            "original": r1.model_dump(mode="json"),
            "reviews": [
                {
                    "id": r2.id,
                    "visit_id": r1.visit_id,
                    "revision": 1,
                    "receipt": r2.model_dump(mode="json"),
                }
            ],
        },
        ensure_ascii=False,
    )


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_verifier_accepts_real_receipt_and_rejects_tampering(tmp_path):
    _, r1, r2 = _chain()
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    (tmp_path / "r.json").write_text(r1.model_dump_json(indent=2), encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
const rt=fs.readFileSync(process.argv[3],'utf8');
eval(src + `
const receiptText=${JSON.stringify(rt)};
(async()=>{
  console.log('verify:',JSON.stringify(await checkReceipt(parseKeep(receiptText))));
  const bad=JSON.parse(receiptText);bad.payload.coverage.fraction=1.0;
  console.log('tampered:',JSON.stringify(await checkReceipt(parseKeep(JSON.stringify(bad)))));
  const wk=JSON.parse(receiptText);const kb=Buffer.from(wk.public_key,'base64');kb[31]^=1;
  wk.public_key=kb.toString('base64');
  console.log('wrongkey:',JSON.stringify(await checkReceipt(parseKeep(JSON.stringify(wk)))));
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "r.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert 'verify: {"ok":true}' in out
    assert "tampered" in out and '"ok":false' in out
    assert "wrongkey" in out and '"ok":false' in out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_chain_verification(tmp_path):
    _, r1, r2 = _chain()
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    (tmp_path / "b.json").write_text(_bundle(r1, r2), encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
const a=fs.readFileSync(process.argv[3],'utf8');
eval(src + `
(async()=>{
  console.log('chain:',JSON.stringify(await checkBundle(parseKeep(a),null)));
  const bad=JSON.parse(a);bad.reviews[0].receipt.prev_hash='0'.repeat(64);
  console.log('broken:',JSON.stringify(await checkBundle(parseKeep(JSON.stringify(bad)),null)));
  const forged=JSON.parse(a);forged.reviews[0].id='rcpt_forged';
  console.log('forged:',JSON.stringify(await checkBundle(parseKeep(JSON.stringify(forged)),null)));
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "b.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert '"ok":true' in proc.stdout and "review(s) verified" in proc.stdout
    assert "envelope fields disagree" in proc.stdout  # broken: prev_hash is signed too
    assert "identity does not match" in proc.stdout


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_zip_reader_enforces_member_name_rules(tmp_path):
    """readZipEntries mirrors packdiff.check_member_names — duplicates and
    ../absolute/drive-qualified names reject the whole pack. The backslash
    traversal case guards the JS regex escaping (the source lives inside a
    Python string, one escape layer deep)."""
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
eval(src + `
(async()=>{
  const b=fs.readFileSync(process.argv[3]);
  const f={arrayBuffer:async()=>b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength)};
  try{const files=await readZipEntries(f);console.log('OK:'+files.length)}
  catch(e){console.log('FAIL:'+e.message)}
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")

    def run(names):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            for n in names:
                z.writestr(n, b"x")
        (tmp_path / "p.zip").write_bytes(buf.getvalue())
        proc = subprocess.run(
            [NODE, "drive.js", "verify.js", "p.zip"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    from attest.packdiff import check_member_names

    assert "OK:" in run(["bundle.json"]) and check_member_names(["bundle.json"]) is None
    for bad in ("../evil.txt", "media\\..\\evil.txt", "C:\\evil.txt", "/abs.txt"):
        out = run(["bundle.json", bad])
        assert "unsafe member name" in out, (bad, out)
        assert check_member_names(["bundle.json", bad]) is not None  # Python parity
    out = run(["bundle.json", "bundle.json"])
    assert "duplicate member name" in out
    assert check_member_names(["bundle.json", "bundle.json"]) is not None


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_issuer_doc_pin_bridges_and_rejects_foreign(tmp_path):
    """A dropped attest.issuer/1 document pins a pre-rotation pack to the
    deployment's CURRENT issuer — the doc's signed lifecycle receipts bridge
    the lineage. A foreign deployment's doc fails closed. The rotation
    payload carries a float (34.0) so the doc's receipts must keep canonical
    spellings — a JSON.parse→stringify round-trip would respell 34.0 as 34
    and silently break their payload hashes."""
    from attest.ledger import Signer

    old, new = Signer.ephemeral(), Signer.ephemeral()
    rotation = old.issue(
        visit_id="key:rot",
        sequence=1,
        prev_hash="bb" * 32,
        facts={
            "record_type": "key_rotation",
            "previous_key": old.public_key_b64,
            "new_key": new.public_key_b64,
            "drift_ratio": 34.0,
        },
    )
    adoption = new.issue(
        visit_id="key:adopt",
        sequence=2,
        prev_hash=rotation.payload_hash,
        facts={
            "record_type": "key_adoption",
            "previous_key": old.public_key_b64,
            "rotation_receipt": {"id": rotation.id, "hash": rotation.payload_hash},
        },
    )
    original = old.issue(
        visit_id="vis_pre",
        sequence=3,
        prev_hash=adoption.payload_hash,
        facts={"record_type": "visit", "state": "closed"},
    )
    bundle = json.dumps(
        {
            "kind": "attest.review_bundle/1",
            "original": original.model_dump(mode="json"),
            "reviews": [],
        },
        ensure_ascii=False,
    )
    doc = {
        "schema": "attest.issuer/1",
        "issuer_key": new.public_key_b64,
        "key_receipts": [rotation.model_dump(mode="json"), adoption.model_dump(mode="json")],
    }
    foreign = Signer.ephemeral()
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    (tmp_path / "bundle.json").write_text(bundle, encoding="utf-8")
    (tmp_path / "doc.json").write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    (tmp_path / "fk.txt").write_text(foreign.public_key_b64, encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
eval(src + `
const mk=(n,t)=>({name:n,text:async()=>t,arrayBuffer:async()=>new TextEncoder().encode(t).buffer});
const arm=dt=>{const dn=parseKeep(dt),d=toJS(dn)||{},kn=get(dn,'key_receipts');
  return{issuer_key:d.issuer_key,nodes:kn&&kn.t==='arr'?kn.v:[]};};
(async()=>{
  const b=fs.readFileSync(process.argv[3],'utf8');
  const docT=fs.readFileSync(process.argv[4],'utf8');
  const fk=fs.readFileSync(process.argv[5],'utf8').trim();
  issuerDoc=null;
  let html=await verifyFiles([mk('bundle.json',b)]);
  console.log('bare:',/VERIFIED/.test(html),/FAILED/.test(html));
  issuerDoc=arm(docT);
  html=await verifyFiles([mk('bundle.json',b)]);
  console.log('pinned:',/VERIFIED/.test(html),/pinned to the issuer/.test(html),/no signed link/.test(html));
  /* Foreign issuer, but carrying THIS pack's real lifecycle pool — the walk
     runs, the key is simply unreachable through it. */
  issuerDoc={issuer_key:fk,nodes:arm(docT).nodes};
  html=await verifyFiles([mk('bundle.json',b)]);
  console.log('foreign:',/FAILED/.test(html),/no signed link/.test(html));
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "bundle.json", "doc.json", "fk.txt"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "bare: true false" in out  # unpinned: verifies under its own key
    assert "pinned: true true false" in out  # doc pins + lifecycle bridges, no link failure
    assert "foreign: true true" in out  # foreign deployment fails closed


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_timeline_renders_marks_and_escapes_titles(tmp_path):
    """The pack's embedded verifier draws the record's timeline from the signed
    payload — and escapes payload text inside SVG titles (packs are untrusted)."""
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    payload = {
        "schedule": {
            "window_start": "2026-09-12T15:00:00+00:00",
            "window_end": "2026-09-12T17:00:00+00:00",
        },
        "evidence": [
            {"kind": "arrival_motion", "at": "2026-09-12T15:05:00+00:00"},
            {"kind": "departure_motion", "at": "2026-09-12T16:50:00+00:00"},
            {"kind": 'x"><script>alert(1)</script>', "at": "2026-09-12T16:00:00+00:00"},
        ],
        "checked_in_at": "2026-09-12T15:06:00+00:00",
        "history_poll_coverage": {
            "covered": [{"start": "2026-09-12T15:00:00+00:00", "end": "2026-09-12T16:00:00+00:00"}],
            "gaps": [{"start": "2026-09-12T16:00:00+00:00", "end": "2026-09-12T17:00:00+00:00"}],
            "live_sessions": [
                {
                    "opened_at": "2026-09-12T15:20:00+00:00",
                    "closed_at": "2026-09-12T15:30:00+00:00",
                    "device_id": "cam1",
                },
                {"opened_at": "2026-09-12T15:40:00+00:00", "closed_at": None, "device_id": "cam1"},
            ],
        },
    }
    (tmp_path / "p.json").write_text(__import__("json").dumps(payload), encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
const p=fs.readFileSync(process.argv[3],'utf8');
eval(src + `
const svg=timelineSVG(JSON.parse(p));
console.log('has_svg:', svg.startsWith('<svg'));
console.log('marks:', (svg.match(/<circle/g)||[]).length);
console.log('checkin_col:', svg.includes('#e8b93e'));
console.log('gap_band:', svg.includes('#9aa3b2'));
console.log('live_band:', (svg.match(/#22b8cf/g)||[]).length===2);
console.log('live_honest:', svg.includes('viewership not shown'));
console.log('escaped:', !svg.includes('<script') && svg.includes('&lt;'));
console.log('empty:', timelineSVG({})==='');`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "p.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    for expected in (
        "has_svg: true",
        "marks: 4",
        "checkin_col: true",
        "gap_band: true",
        "live_band: true",
        "live_honest: true",
        "escaped: true",
        "empty: true",
    ):
        assert expected in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_verifier_accepts_lone_signed_receipt(tmp_path):
    """A bare receipt JSON (e.g. `verify-live --sign --out report.json`) dropped
    on the hosted verifier verifies — judges can check the evidence itself."""
    s = Signer.ephemeral()
    r = s.issue(
        visit_id="verify:abc123",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "verification_report",
            "generated_at": "2026-09-30T03:00:00+00:00",
            "base_url": "https://api.amazonvision.com",
            "checks": [
                {"check": "users/me", "status": "pass", "detail": "account reachable"},
                {"check": "WHEP live view", "status": "fail", "detail": "HTTP 500"},
            ],
            "summary": {"pass": 1, "fail": 1, "warn": 0, "skip": 0},
        },
    )
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    rt = r.model_dump_json(indent=2)
    driver = f"""
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
const rt={json.dumps(rt)};
eval(src + `
const mk=t=>[{{name:'report.json',text:async()=>t,
  arrayBuffer:async()=>new TextEncoder().encode(t).buffer}}];
(async()=>{{
  const html=await verifyFiles(mk(rt));
  console.log('verified:',html.includes('<strong>VERIFIED</strong>'));
  console.log('report_card:',html.includes('signed verify-live report'));
  console.log('check_row:',html.includes('WHEP live view')&&html.includes('HTTP 500'));
  const bad=JSON.parse(rt);bad.payload.summary.fail=0;
  const html2=await verifyFiles(mk(JSON.stringify(bad)));
  console.log('tampered:',html2.includes('<strong>FAILED</strong>'));
}})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js"], cwd=tmp_path, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "verified: true" in out, out
    assert "report_card: true" in out, out
    assert "check_row: true" in out, out
    assert "tampered: true" in out, out


def test_packs_embed_browser_verifier(engine, store, household, schedule, t0, tmp_path):
    from ring_sandbox import WebhookEvent, webhooks

    from attest.reviews import ReviewService

    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    names = zipfile.ZipFile(io.BytesIO(build_pack(store, tmp_path / "m", bundle))).namelist()
    assert "verify.html" in names and "verify_bundle.py" in names


def test_verify_html_is_self_contained():
    assert "http://" not in VERIFY_HTML and "https://" not in VERIFY_HTML  # no CDN
    assert "crypto.subtle" in VERIFY_HTML  # real hashing, not a stub
    assert "BigInt" in VERIFY_HTML or "n<<" in VERIFY_HTML  # BigInt ed25519


def test_hosted_verifier_copy_stays_in_sync():
    # docs/verify.html is the GitHub Pages copy — regenerate with:
    #   python -c "from pathlib import Path; from attest.verifyjs import VERIFY_HTML; \
    #       Path('docs/verify.html').write_bytes(VERIFY_HTML.encode('utf-8'))"
    committed = Path(__file__).resolve().parents[1] / "docs" / "verify.html"
    assert committed.read_bytes() == VERIFY_HTML.encode("utf-8"), (
        "docs/verify.html drifted from attest.verifyjs.VERIFY_HTML — regenerate it"
    )


def test_live_sweep_receipt_artifact_verifies():
    """docs/live-sweep-receipt.json is the signed verify-live report from the
    real api.amazonvision.com run — it must verify offline under its embedded
    issuer key, and it must stay the real-API report (not emulator output)."""
    from attest.ledger import verify_receipt
    from attest.models import Receipt

    path = Path(__file__).resolve().parents[1] / "docs" / "live-sweep-receipt.json"
    receipt = Receipt.model_validate_json(path.read_bytes())
    assert receipt.payload["record_type"] == "verification_report"
    assert receipt.payload["base_url"] == "https://api.amazonvision.com"
    ok, why = verify_receipt(receipt, public_key=receipt.public_key)
    assert ok, why
    assert receipt.payload["summary"]["pass"] > 0


def test_sample_pack_artifact_verifies():
    """docs/sample-pack.zip is the zero-install sample on the hosted verifier —
    it must always verify end-to-end or the landing page demo breaks."""
    import io

    from attest.app import _verify_pack

    path = Path(__file__).resolve().parents[1] / "docs" / "sample-pack.zip"
    data = path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        issuer = json.loads(z.read("manifest.json"))["issuer_key"]
        # The shipped verifiers must be the current sources — a stale embedded
        # script would check the pack with rules the repo has since tightened.
        from attest.disputepack import _CASE_VERIFIER
        from attest.verifyjs import VERIFY_HTML

        assert z.read("verify_case.py").decode() == _CASE_VERIFIER
        assert z.read("verify.html").decode() == VERIFY_HTML
    ok, detail = _verify_pack(data, issuer)
    assert ok, detail


def _case_pack(engine, store, household, schedule, t0, tmp_path, ring_world=None):
    from ring_sandbox import WebhookEvent, webhooks

    from attest.disputepack import build_case_pack
    from attest.reviews import ReviewService, countersign_status

    if ring_world is not None:
        # the sandbox only serves media for windows it actually recorded
        ring_world.record_event(household[2].id, "button_press", at_ms=int(t0.timestamp() * 1000))
    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    return zipfile.ZipFile(io.BytesIO(data))


def test_case_pack_embeds_offline_record_browser(engine, store, household, schedule, t0, tmp_path):
    """index.html is the pack's front page: inlined base64 bundles (immune to
    </script> breakout inside signed statements) + the same verifier JS."""
    import base64
    import re

    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
    names = z.namelist()
    assert "index.html" in names
    html = z.read("index.html").decode()
    assert "http://" not in html and "https://" not in html
    assert 'id="packmeta"' in html
    tags = re.findall(r'data-vid="(vis_[0-9a-f]+)">([A-Za-z0-9+/=]+)</script>', html)
    assert len(tags) == 1
    vid, b64 = tags[0]
    decoded = base64.b64decode(b64).decode()
    assert decoded == z.read(f"visits/{vid}/bundle.json").decode()


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_case_pack_index_renders_failed_bundle_without_injection(
    engine, store, household, schedule, t0, tmp_path
):
    """A tampered bundle must surface as FAILED — and its narrative must never
    reach innerHTML as live markup. An attacker who splices a hostile
    household 'perception' into the pack can't inject script into whoever
    opens index.html (the failed card renders the verdict row only)."""
    import base64

    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
    html = z.read("index.html").decode()
    vid, b64 = re.search(r'data-vid="(vis_[0-9a-f]+)">([A-Za-z0-9+/=]+)</script>', html).groups()
    bundle = json.loads(base64.b64decode(b64))
    bundle["reviews"] = [
        {
            "receipt": {
                "id": "rcpt_forged",
                "visit_id": vid,
                "signature": "00",
                "payload": {
                    "actor": {"role": "household", "name": "x"},
                    "review": {
                        "kind": "household_account",
                        "perception": 'unsure"><img src=x onerror=alert(1)>',
                        "statement": '"><img src=y onerror=alert(2)>',
                    },
                },
            }
        }
    ]
    forged_b64 = base64.b64encode(json.dumps(bundle).encode()).decode()
    html = html.replace(b64, forged_b64)
    meta = re.search(r'id="packmeta">([A-Za-z0-9+/=]+)</script>', html).group(1)
    script = re.search(r'<script>\n("use strict";.*?)</script>', html, re.S).group(1)
    (tmp_path / "idx.js").write_text(script, encoding="utf-8")
    (tmp_path / "meta.b64").write_text(meta, encoding="utf-8")
    driver = """
const fs=require('fs');
const html=fs.readFileSync(process.argv[2],'utf8');
const bundles=[...html.matchAll(/data-vid="([^"]+)">([A-Za-z0-9+/=]+)<\\/script>/g)]
  .map(m=>({dataset:{vid:m[1]},textContent:m[2]}));
const els={packmeta:{textContent:fs.readFileSync(process.argv[4],'utf8')}};
const mm=html.match(/id="packmanifest">([A-Za-z0-9+/=]+)<\\/script>/);
if(mm)els.packmanifest={textContent:mm[1]};
const get=id=>els[id]||(els[id]={textContent:'',innerHTML:''});
global.document={querySelectorAll:s=>s==='script.bundle'?bundles:[],getElementById:get};
let src=fs.readFileSync(process.argv[3],'utf8');
src=src.replace(/renderIndex\\(\\)\\.catch[\\s\\S]*$/,'');
eval(src+';globalThis.__r=renderIndex;');
__r().then(()=>{
  console.log('verdict:',els.verdict.innerHTML.slice(0,140));
  console.log('img:',/<img/.test(els.cards.innerHTML));
  console.log('onerror:',/onerror/.test(els.cards.innerHTML));
  console.log('stmt:',/class="stmt"/.test(els.cards.innerHTML));
});
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "index.html", "idx.js", "meta.b64"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "FAILED" in out, out
    assert "img: false" in out, out
    assert "onerror: false" in out, out
    assert "stmt: false" in out, out  # the forged narrative never renders


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_case_pack_index_verifies_records_in_browser(engine, store, household, schedule, t0, tmp_path):
    """Run index.html's own script under node with a minimal DOM stub — the
    embedded driver must verify the real inlined bundle and report VERIFIED."""
    import re
    from datetime import timedelta

    site = store.sites()[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
    html = z.read("index.html").decode()
    meta = re.search(r'id="packmeta">([A-Za-z0-9+/=]+)</script>', html).group(1)
    script = re.search(r'<script>\n("use strict";.*?)</script>', html, re.S).group(1)
    (tmp_path / "idx.js").write_text(script, encoding="utf-8")
    (tmp_path / "meta.b64").write_text(meta, encoding="utf-8")
    driver = """
const fs=require('fs');
const html=fs.readFileSync(process.argv[2],'utf8');
const bundles=[...html.matchAll(/data-vid="([^"]+)">([A-Za-z0-9+/=]+)<\\/script>/g)]
  .map(m=>({dataset:{vid:m[1]},textContent:m[2]}));
const attags=[...html.matchAll(/class="attestation" data-rid="([^"]+)">([A-Za-z0-9+/=]+)<\\/script>/g)]
  .map(m=>({dataset:{rid:m[1]},textContent:m[2]}));
const mm=html.match(/id="packmanifest">([A-Za-z0-9+/=]+)<\\/script>/);
const els={packmeta:{textContent:fs.readFileSync(process.argv[4],'utf8')}};
if(mm)els.packmanifest={textContent:mm[1]};
const get=id=>els[id]||(els[id]={textContent:'',innerHTML:''});
global.document={querySelectorAll:s=>s==='script.bundle'?bundles:s==='script.attestation'?attags:[],getElementById:get};
let src=fs.readFileSync(process.argv[3],'utf8');
src=src.replace(/renderIndex\\(\\)\\.catch[\\s\\S]*$/,'');
eval(src+';globalThis.__r=renderIndex;');
__r().then(()=>{
  console.log('verdict:',els.verdict.innerHTML.slice(0,140));
  console.log('cards:',(els.cards.innerHTML.match(/class="card"/g)||[]).length);
  console.log('timeline:',els.cards.innerHTML.includes('<svg'));
  console.log('corr:',(els.cards.innerHTML.match(/class="corr"/g)||[]).length);
  console.log('corrrows:',els.cards.innerHTML.includes('Pipeline coverage'));
  console.log('week:',els.cards.innerHTML.includes('exported window at a glance')&&
    els.cards.innerHTML.includes('scheduled window'));
  console.log('attline:',
    els.verdict.innerHTML.includes('attestation coverage_attestation: signed and intact'));
  console.log('attcard:',els.cards.innerHTML.includes('watched')&&
    els.cards.innerHTML.includes('coverage attestation'));
});
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "index.html", "idx.js", "meta.b64"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "VERIFIED" in out, out
    assert "cards: 3" in out, out  # week strip + visit card + coverage attestation card
    assert "timeline: true" in out, out
    assert "corr: 1" in out, out
    assert "corrrows: true" in out, out
    assert "week: true" in out, out
    assert "attline: true" in out, out
    assert "attcard: true" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_dispute_pack_index_verifies_in_browser(engine, store, household, schedule, t0, tmp_path):
    """Single-visit packs get the same front page: index.html inlines the one
    bundle, verifies it live, and renders timeline + corroboration."""
    from ring_sandbox import WebhookEvent, webhooks

    from attest.reviews import ReviewService

    event = WebhookEvent.model_validate(
        webhooks.build_event(
            event_type="button_press",
            device_id=household[2].id,
            occurred_at=t0,
        )
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    data = build_pack(store, tmp_path / "media", bundle)
    z = zipfile.ZipFile(io.BytesIO(data))
    assert "index.html" in z.namelist()
    html = z.read("index.html").decode()
    assert "http://" not in html and "https://" not in html
    assert 'id="packmeta"' in html
    import base64

    tags = re.findall(r'data-vid="(vis_[0-9a-f]+)">([A-Za-z0-9+/=]+)</script>', html)
    assert len(tags) == 1
    assert base64.b64decode(tags[0][1]).decode() == z.read("bundle.json").decode()

    meta = re.search(r'id="packmeta">([A-Za-z0-9+/=]+)</script>', html).group(1)
    script = re.search(r'<script>\n("use strict";.*?)</script>', html, re.S).group(1)
    (tmp_path / "idx.js").write_text(script, encoding="utf-8")
    (tmp_path / "meta.b64").write_text(meta, encoding="utf-8")
    driver = """
const fs=require('fs');
const html=fs.readFileSync(process.argv[2],'utf8');
const bundles=[...html.matchAll(/data-vid="([^"]+)">([A-Za-z0-9+/=]+)<\\/script>/g)]
  .map(m=>({dataset:{vid:m[1]},textContent:m[2]}));
const mm=html.match(/id="packmanifest">([A-Za-z0-9+/=]+)<\\/script>/);
const els={packmeta:{textContent:fs.readFileSync(process.argv[4],'utf8')}};
if(mm)els.packmanifest={textContent:mm[1]};
const get=id=>els[id]||(els[id]={textContent:'',innerHTML:''});
global.document={querySelectorAll:s=>s==='script.bundle'?bundles:[],getElementById:get};
let src=fs.readFileSync(process.argv[3],'utf8');
src=src.replace(/renderIndex\\(\\)\\.catch[\\s\\S]*$/,'');
eval(src+';globalThis.__r=renderIndex;');
__r().then(()=>{
  console.log('verdict:',els.verdict.innerHTML.slice(0,120));
  console.log('cards:',(els.cards.innerHTML.match(/class="card"/g)||[]).length);
  console.log('corr:',(els.cards.innerHTML.match(/class="corr"/g)||[]).length);
  console.log('week:',els.cards.innerHTML.includes('exported window at a glance'));
});
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "index.html", "idx.js", "meta.b64"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "VERIFIED" in out, out
    assert "cards: 2" in out, out  # week strip + visit card
    assert "corr: 1" in out, out
    assert "week: true" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_week_strip_groups_signed_payloads_by_day(tmp_path):
    """weekSVG clips intervals to UTC days, marks explained vs. unexplained
    gaps differently, renders lifecycle marks and the worker's self-report —
    and stays silent when a payload carries nothing to show."""
    from attest.verifyjs import _INDEX_DRIVER, _JS_LIB

    src = _JS_LIB + _INDEX_DRIVER
    src = re.sub(r"renderIndex\(\)\.catch[\s\S]*$", "", src)
    driver = """
let src=fs.readFileSync(process.argv[2],'utf8');
eval(src+';globalThis.__w=weekSVG;');
const P={
  schedule:{window_start:'2026-09-20T09:00:00+00:00',window_end:'2026-09-20T11:00:00+00:00'},
  checked_in_at:'2026-09-20T09:05:00+00:00',
  evidence:[{kind:'arrival_motion',at:'2026-09-20T09:10:00+00:00'},
            {kind:'departure_motion',at:'2026-09-20T10:50:00+00:00'}],
  history_poll_coverage:{
    window:{start:'2026-09-20T09:00:00+00:00',end:'2026-09-20T11:00:00+00:00'},
    covered:[{start:'2026-09-20T09:00:00+00:00',end:'2026-09-20T10:00:00+00:00'},
             {start:'2026-09-20T10:30:00+00:00',end:'2026-09-20T11:00:00+00:00'}],
    gaps:[{start:'2026-09-20T10:00:00+00:00',end:'2026-09-20T10:30:00+00:00',explained:true,
           explained_by:[{kind:'device_offline',device_id:'dev_cam',start:'2026-09-20T09:55:00+00:00',
                          end:'2026-09-20T10:40:00+00:00',restored_by:'device_online'}]},
          {start:'2026-09-20T12:00:00+00:00',end:'2026-09-20T13:00:00+00:00'}],
    interruptions:[{kind:'device_offline',at:'2026-09-20T09:55:00+00:00',device_id:'dev_cam',
                    interrupts:true,detail:null},
                   {kind:'device_online',at:'2026-09-20T10:40:00+00:00',device_id:'dev_cam',
                    interrupts:false,detail:null}],
    live_sessions:[{opened_at:'2026-09-20T09:20:00+00:00',closed_at:'2026-09-20T09:35:00+00:00',
                    device_id:'dev_cam'},
                   {opened_at:'2026-09-20T10:45:00+00:00',closed_at:null,device_id:'dev_cam'}]}};
/* a coverage span that crosses midnight clips into two day rows */
const Q={
  schedule:{window_start:'2026-09-21T23:00:00+00:00',window_end:'2026-09-22T02:00:00+00:00'},
  history_poll_coverage:{
    window:{start:'2026-09-21T23:00:00+00:00',end:'2026-09-22T02:00:00+00:00'},
    covered:[{start:'2026-09-21T23:00:00+00:00',end:'2026-09-22T02:00:00+00:00'}],
    gaps:[],interruptions:[]}};
const html=__w([P,Q]);
console.log('rows:',(html.match(/class="week-row"/g)||[]).length);
console.log('explained:',html.includes('channel reported device offline'));
console.log('unexplained:',html.includes('the pipeline was not polling'));
console.log('intrmark:',html.includes('device offline — 2026-09-20T09:55:00+00:00 · dev_cam'));
console.log('checkin:',html.includes('(self-reported)'));
console.log('live:',html.includes('live view opened — dev_cam · stream established'));
console.log('liveopen:',html.includes('still open when signed'));
console.log('livebound:',html.includes('never proof anyone watched'));
console.log('bound:',html.includes('not proof nobody came'));
console.log('empty:',__w([{}])==='');
console.log('order:',html.indexOf('09-20')<html.indexOf('09-21')&&html.indexOf('09-21')<html.indexOf('09-22'));
"""
    (tmp_path / "idx.js").write_text(src, encoding="utf-8")
    (tmp_path / "drive.js").write_text("const fs=require('fs');\n" + driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "idx.js"], cwd=tmp_path, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "rows: 3" in out, out  # the midnight-crossing schedule splits into two day rows
    for needle in (
        "explained",
        "unexplained",
        "intrmark",
        "checkin",
        "live",
        "liveopen",
        "livebound",
        "bound",
        "empty",
        "order",
    ):
        assert f"{needle}: true" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_index_plain_view_renders_contested_record(engine, store, household, schedule, t0, tmp_path):
    """The pack's family-facing toggle must render the dispute in plain
    language from signed data only: the worker's quote verbatim, the
    contested stance, and the honesty boundary — never attendance claims."""
    from datetime import timedelta

    from attest.disputepack import build_case_pack
    from attest.models import ReviewInput
    from attest.reviews import ReviewService, countersign_status

    site = store.sites()[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    rv = ReviewService(store, engine.signer, engine.clock)
    z1 = _case_pack(engine, store, household, schedule, t0, tmp_path)
    vid = re.search(r'data-vid="(vis_[0-9a-f]+)">', z1.read("index.html").decode()).group(1)
    token = rv.issue_worker_link(vid)
    rv.worker_review(token, ReviewInput(decision="dispute", statement="I arrived earlier than logged."))
    visit = store.visit(vid)
    bundle = rv.bundle(vid)
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    z = zipfile.ZipFile(io.BytesIO(data))
    html = z.read("index.html").decode()
    meta = re.search(r'id="packmeta">([A-Za-z0-9+/=]+)</script>', html).group(1)
    script = re.search(r'<script>\n("use strict";.*?)</script>', html, re.S).group(1)
    (tmp_path / "idx.js").write_text(script, encoding="utf-8")
    (tmp_path / "meta.b64").write_text(meta, encoding="utf-8")
    driver = """
const fs=require('fs');
const html=fs.readFileSync(process.argv[2],'utf8');
const bundles=[...html.matchAll(/data-vid="([^"]+)">([A-Za-z0-9+/=]+)<\\/script>/g)]
  .map(m=>({dataset:{vid:m[1]},textContent:m[2]}));
const attags=[...html.matchAll(/class="attestation" data-rid="([^"]+)">([A-Za-z0-9+/=]+)<\\/script>/g)]
  .map(m=>({dataset:{rid:m[1]},textContent:m[2]}));
const mm=html.match(/id="packmanifest">([A-Za-z0-9+/=]+)<\\/script>/);
const els={packmeta:{textContent:fs.readFileSync(process.argv[4],'utf8')}};
if(mm)els.packmanifest={packmanifest:1,textContent:mm[1]};
const get=id=>els[id]||(els[id]={textContent:'',innerHTML:''});
global.document={querySelectorAll:s=>s==='script.bundle'?bundles:s==='script.attestation'?attags:[],getElementById:get};
let src=fs.readFileSync(process.argv[3],'utf8');
src=src.replace(/renderIndex\\(\\)\\.catch[\\s\\S]*$/,'');
eval(src+';globalThis.__r=renderIndex;');
__r().then(()=>{
  const c=els.cards.innerHTML;
  console.log('verdict:',els.verdict.innerHTML.slice(0,120));
  console.log('hero:',c.includes('plain-hero'));
  console.log('toggle:',c.includes('view-toggle'));
  console.log('quote:',c.includes('I arrived earlier than logged.'));
  console.log('stance:',c.includes('Disputes this record'));
  console.log('boundary:',c.includes('not proof nobody came'));
  console.log('noattend:',!c.includes('attended')&&!c.includes('was present'));
});
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "index.html", "idx.js", "meta.b64"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "VERIFIED" in out, out
    assert "hero: true" in out, out
    assert "toggle: true" in out, out
    assert "quote: true" in out, out
    assert "stance: true" in out, out
    assert "boundary: true" in out, out
    assert "noattend: true" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_index_plain_view_renders_household_account(engine, store, household, schedule, t0, tmp_path):
    """The trilateral chain in a pack: the household's account renders as its
    own voice — quoted, labeled self-reported, never merged into the worker's
    stance or presented as verification."""
    from datetime import timedelta

    from attest.disputepack import build_case_pack
    from attest.models import HouseholdStatementInput, ReviewInput
    from attest.reviews import ReviewService, countersign_status

    site = store.sites()[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    rv = ReviewService(store, engine.signer, engine.clock)
    z1 = _case_pack(engine, store, household, schedule, t0, tmp_path)
    vid = re.search(r'data-vid="(vis_[0-9a-f]+)">', z1.read("index.html").decode()).group(1)
    token = rv.issue_worker_link(vid)
    rv.worker_review(token, ReviewInput(decision="dispute", statement="I was there."))
    family = engine.issue_family_link(vid)
    rv.household_statement(
        family,
        HouseholdStatementInput(perception="no_one_seen", statement="Nobody knocked that morning."),
    )
    visit = store.visit(vid)
    bundle = rv.bundle(vid)
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
    )
    z = zipfile.ZipFile(io.BytesIO(data))
    html = z.read("index.html").decode()
    meta = re.search(r'id="packmeta">([A-Za-z0-9+/=]+)</script>', html).group(1)
    script = re.search(r'<script>\n("use strict";.*?)</script>', html, re.S).group(1)
    (tmp_path / "idx.js").write_text(script, encoding="utf-8")
    (tmp_path / "meta.b64").write_text(meta, encoding="utf-8")
    driver = """
const fs=require('fs');
const html=fs.readFileSync(process.argv[2],'utf8');
const bundles=[...html.matchAll(/data-vid="([^"]+)">([A-Za-z0-9+/=]+)<\\/script>/g)]
  .map(m=>({dataset:{vid:m[1]},textContent:m[2]}));
const attags=[...html.matchAll(/class="attestation" data-rid="([^"]+)">([A-Za-z0-9+/=]+)<\\/script>/g)]
  .map(m=>({dataset:{rid:m[1]},textContent:m[2]}));
const mm=html.match(/id="packmanifest">([A-Za-z0-9+/=]+)<\\/script>/);
const els={packmeta:{textContent:fs.readFileSync(process.argv[4],'utf8')}};
if(mm)els.packmanifest={packmanifest:1,textContent:mm[1]};
const get=id=>els[id]||(els[id]={textContent:'',innerHTML:''});
global.document={querySelectorAll:s=>s==='script.bundle'?bundles:s==='script.attestation'?attags:[],getElementById:get};
let src=fs.readFileSync(process.argv[3],'utf8');
src=src.replace(/renderIndex\\(\\)\\.catch[\\s\\S]*$/,'');
eval(src+';globalThis.__r=renderIndex;');
__r().then(()=>{
  const c=els.cards.innerHTML;
  console.log('verdict:',els.verdict.innerHTML.slice(0,60));
  console.log('hhquote:',c.includes('Nobody knocked that morning.'));
  console.log('hhlabel:',c.includes('household account')&&c.includes('no one seen'));
  console.log('selfreported:',c.includes('self-reported'));
  console.log('workerquote:',c.includes('I was there.'));
  console.log('nostance:',!c.includes('household disputes'));
  console.log('stmts:',c.includes('household account: no one seen'));
});
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "index.html", "idx.js", "meta.b64"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "VERIFIED" in out, out
    assert "hhquote: true" in out, out
    assert "hhlabel: true" in out, out
    assert "selfreported: true" in out, out
    assert "workerquote: true" in out, out
    assert "nostance: true" in out, out
    assert "stmts: true" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_verify_html_reads_the_zip_directly(engine, store, household, schedule, t0, tmp_path):
    """verify.html must verify a dropped .zip: readZipEntries parses stored +
    deflate entries (node's DecompressionStream stands in for the browser's),
    and media files are matched by CONTENT hash — their filenames hold only a
    digest prefix."""
    from datetime import timedelta

    site = store.sites()[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
    assert any(n.startswith("attestations/") for n in z.namelist())
    pack_bytes = tmp_path / "case.zip"
    with zipfile.ZipFile(pack_bytes, "w", zipfile.ZIP_DEFLATED) as out:
        for name in z.namelist():
            out.writestr(name, z.read(name))
    script = _script()
    (tmp_path / "verify.js").write_text(script, encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
eval(src+';globalThis.__v=verifyFiles;globalThis.__rz=readZipEntries;');
const bytes=fs.readFileSync(process.argv[3]);
const fake={name:'case.zip',
  arrayBuffer:async()=>bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength)};
__rz(fake).then(async files=>{
  console.log('entries:',files.length);
  const html=await __v(files);
  console.log('verdict:',(html.match(/VERIFIED[^<]*|FAILED[^<]*/)||['none'])[0]);
  console.log('media-ok:',(html.match(/digest matches/g)||[]).length);
  console.log('att-ok:',html.includes('attestation coverage_attestation: signed and intact'));
  console.log('manifest:',(html.match(/manifest: [^<]*/g)||['none']).pop());
}).catch(e=>{console.log('ERR',e.message);process.exit(2);});
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "case.zip"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "entries:" in out and "0" not in out.split("entries:")[1].split("\n")[0]
    assert "VERIFIED" in out, out
    assert "media-ok:" in out, out
    assert "att-ok: true" in out, out
    assert "export signed" in out, out


def _drive_zip(tmp_path, z, name="case.zip"):
    """Write zipfile contents to a real .zip + the node driver; returns stdout."""
    pack = tmp_path / name
    with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as out:
        for item in z.infolist():
            out.writestr(item.filename, z.read(item.filename))
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    driver = r"""
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\s\S]*$/,'');
eval(src+';globalThis.__v=verifyFiles;globalThis.__rz=readZipEntries;');
const bytes=fs.readFileSync(process.argv[3]);
const fake={name:'p.zip',
  arrayBuffer:async()=>bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength)};
__rz(fake).then(async files=>{
  const html=await __v(files);
  console.log('verdict:',(html.match(/VERIFIED[^<]*|FAILED[^<]*/)||['none'])[0]);
  console.log(html.replace(/<[^>]+>/g,' ').replace(/\s+/g,' '));
}).catch(e=>{console.log('ERR',e.message);process.exit(2);});
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", name],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_verify_html_escapes_hostile_extra_key_names(engine, store, household, schedule, t0, tmp_path):
    """A forged bundle whose extra key name carries HTML must fail closed AND
    render the name escaped — a raw key reaching innerHTML would let a crafted
    pack fake VERIFIED (or run script on the hosted /verify-pack origin)."""
    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
    bundle = json.loads(z.read(next(n for n in z.namelist() if n.endswith("bundle.json"))))
    bundle['x"><img src=x onerror=alert(1)>'] = True  # hostile extra key
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    (tmp_path / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
    driver = r"""
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\s\S]*$/,'');
eval(src+';globalThis.__v=verifyFiles;');
const txt=fs.readFileSync(process.argv[3],'utf8');
const f={name:'bundle.json',text:async()=>txt,
  arrayBuffer:async()=>new TextEncoder().encode(txt).buffer};
__v([f]).then(html=>{
  console.log('RAW:',html);
  console.log('verdict:',(html.match(/VERIFIED[^<]*|FAILED[^<]*/)||['none'])[0]);
}).catch(e=>{console.log('ERR',e.message);process.exit(2);});
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "bundle.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "FAILED" in out
    # The hostile key must appear entity-escaped — never as live markup.
    assert "<img src=x onerror" not in out
    assert "&lt;img" in out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_verify_html_fails_closed_when_listed_bundle_missing(
    engine, store, household, schedule, t0, tmp_path
):
    """A manifest-listed visit whose bundle.json was deleted from the zip must
    fail closed — red row AND FAILED verdict, never VERIFIED."""
    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
    vid = json.loads(z.read("manifest.json"))["visits"][0]["visit_id"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for name in z.namelist():
            if name == f"visits/{vid}/bundle.json":
                continue  # the dropped record
            out.writestr(name, z.read(name))
    buf.seek(0)
    out = _drive_zip(tmp_path, zipfile.ZipFile(buf))
    assert "FAILED" in out, out
    assert "VERIFIED" not in out, out
    assert "listed but missing" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_verify_html_rejects_smuggled_attestation_file(engine, store, household, schedule, t0, tmp_path):
    """An attestations/*.json file the signed manifest does not list fails
    closed in the browser — parity with the embedded verifier's sweep."""
    from datetime import timedelta

    site = store.sites()[0]
    engine.issue_coverage_attestation(site, t0 - timedelta(hours=1), t0 + timedelta(hours=2))
    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
    att_name = next(n for n in z.namelist() if n.startswith("attestations/"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for name in z.namelist():
            out.writestr(name, z.read(name))
        out.writestr("attestations/smuggled.json", z.read(att_name))
    buf.seek(0)
    out = _drive_zip(tmp_path, zipfile.ZipFile(buf))
    assert "FAILED" in out, out
    assert "VERIFIED" not in out, out
    assert "not in the signed manifest" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_verify_html_rejects_forged_countersign_status(engine, store, household, schedule, t0, tmp_path):
    """An unsigned countersign_status slipped into bundle.json is
    extra="forbid" content — the browser must FAIL, not render a fake worker
    stance under a VERIFIED banner."""
    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
    vid = json.loads(z.read("manifest.json"))["visits"][0]["visit_id"]
    bundle = json.loads(z.read(f"visits/{vid}/bundle.json"))
    bundle["countersign_status"] = {"state": "acknowledged", "detail": "worker confirmed"}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for name in z.namelist():
            if name == f"visits/{vid}/bundle.json":
                out.writestr(name, json.dumps(bundle))
            else:
                out.writestr(name, z.read(name))
    buf.seek(0)
    out = _drive_zip(tmp_path, zipfile.ZipFile(buf))
    assert "FAILED" in out, out
    assert "VERIFIED" not in out, out
    assert "unsigned extra field" in out, out
    assert "acknowledged" not in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_verify_html_rejects_forged_redaction_masking_deleted_media(
    engine, store, household, schedule, t0, tmp_path, ring_world
):
    """Delete a media file and drop an unsigned redaction.json claiming the
    digest was withheld — the signed manifest's empty media_withheld list must
    expose the lie. This is the audit's core browser-vs-Python asymmetry."""
    z = _case_pack(engine, store, household, schedule, t0, tmp_path, ring_world)
    vid = json.loads(z.read("manifest.json"))["visits"][0]["visit_id"]
    bundle = json.loads(z.read(f"visits/{vid}/bundle.json"))
    digest = next(  # the pack must carry at least one signed media digest
        e["media_sha256"] for e in bundle["original"]["payload"]["evidence"] if e.get("media_sha256")
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for name in z.namelist():
            if name.startswith(f"visits/{vid}/media/"):
                continue  # the stolen evidence
            out.writestr(name, z.read(name))
        out.writestr(
            f"visits/{vid}/redaction.json",
            json.dumps(
                {
                    "media_redacted": True,
                    "withheld_digests": [digest],
                    "note": "forged marker",
                }
            ),
        )
    buf.seek(0)
    out = _drive_zip(tmp_path, zipfile.ZipFile(buf))
    assert "FAILED" in out, out
    assert "VERIFIED" not in out, out
    assert "redaction list disagrees" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_verify_html_redacted_pack_still_verifies(
    engine, store, household, schedule, t0, tmp_path, ring_world
):
    """The honest redacted pack — manifest media_withheld + redaction.json
    agree — still VERIFIES with 'withheld' rows, so the parity check doesn't
    over-correct into rejecting legitimate redaction."""
    from ring_sandbox import WebhookEvent, webhooks

    from attest.disputepack import build_case_pack
    from attest.reviews import ReviewService, countersign_status

    ring_world.record_event(household[2].id, "button_press", at_ms=int(t0.timestamp() * 1000))
    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    bundle = ReviewService(store, engine.signer, engine.clock).bundle(visit.id)
    site = store.sites()[0]
    data = build_case_pack(
        store,
        tmp_path / "media",
        site,
        [(visit, bundle, countersign_status(bundle))],
        manifest_signer=lambda m: engine.issue_export_manifest(site, m),
        redact_media=True,
    )
    out = _drive_zip(tmp_path, zipfile.ZipFile(io.BytesIO(data)))
    assert "VERIFIED" in out, out
    assert "FAILED" not in out, out
    assert "withheld" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_canonicalization_matches_python_on_edge_cases(tmp_path):
    """Astral-plane key ordering and verbatim float spellings must canonicalize
    identically to Python's json.dumps(sort_keys=True) — or the signature
    check fails on honest records (or worse, diverges on adversarial ones)."""
    s = Signer.ephemeral()
    # An astral char sorts after all BMP chars by code point but BEFORE some
    # by UTF-16 unit; a 34.0 float spelling must survive verbatim.
    r = s.issue(
        visit_id="vis_edge",
        sequence=1,
        prev_hash="00" * 32,
        facts={
            "record_type": "visit",
            "\U0001f600key": "astral",
            "z_bmp": "after",
            "float_spelling": 34.0,
            "statement": "émojis 👍 and — dashes",
        },
    )
    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    (tmp_path / "r.json").write_text(r.model_dump_json(indent=2), encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
const rt=fs.readFileSync(process.argv[3],'utf8');
eval(src + `
const receiptText=${JSON.stringify(rt)};
(async()=>{
  console.log('edge:',JSON.stringify(await checkReceipt(parseKeep(receiptText))));
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "r.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert 'edge: {"ok":true}' in proc.stdout, proc.stdout


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_js_issuer_doc_pins_across_rotation(engine, store, household, schedule, t0, tmp_path):
    """Dropping an attest.issuer/1 doc arms a deployment pin in the browser
    verifier: a bundle signed by the RETIRED key verifies under the doc's
    CURRENT issuer via the doc's signed lifecycle receipts — and an unrelated
    doc fails closed."""
    import json

    from attest import ledger
    from attest.ledger import Signer
    from attest.reviews import ReviewService

    event = WebhookEvent.model_validate(
        webhooks.build_event(event_type="button_press", device_id=household[2].id, occurred_at=t0)
    )
    visit = engine.ingest(event).visit
    engine.close_for_review(visit.id)
    service = ReviewService(store, engine.signer, engine.clock)
    bundle_text = service.bundle(visit.id).model_dump_json()

    old_key = engine.signer.public_key_b64
    new_signer = Signer.ephemeral()
    rotation = engine.issue_key_rotation(new_signer.public_key_b64, "")
    engine.signer = new_signer
    engine.issue_key_adoption(old_key, rotation)
    doc = ledger.issuer_document(new_signer.public_key_b64, store.receipts())
    assert len(doc["key_receipts"]) == 2, doc["key_receipts"]

    (tmp_path / "verify.js").write_text(_script(), encoding="utf-8")
    (tmp_path / "doc.json").write_text(json.dumps(doc), encoding="utf-8")
    (tmp_path / "b.json").write_text(bundle_text, encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
const doc=fs.readFileSync(process.argv[3],'utf8');
const b=fs.readFileSync(process.argv[4],'utf8');
eval(src + `
const fileOf=t=>({name:'bundle.json',text:()=>Promise.resolve(t),
  arrayBuffer:()=>Promise.resolve(new TextEncoder().encode(t).buffer)});
const arm=dt=>{const dn=parseKeep(dt),d=toJS(dn)||{},kn=get(dn,'key_receipts');
  return{issuer_key:d.issuer_key,nodes:kn&&kn.t==='arr'?kn.v:[]};};
(async()=>{
  issuerDoc=arm(doc);
  const html=await verifyFiles([fileOf(b)]);
  console.log('pinned:',/VERIFIED/.test(html),/pinned to the issuer document/.test(html));
  issuerDoc={issuer_key:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',nodes:[]};
  const bad=await verifyFiles([fileOf(b)]);
  console.log('wrongdoc:',/FAILED/.test(bad),/no signed link/.test(bad));
  issuerDoc=null;
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "doc.json", "b.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "pinned: true true" in proc.stdout, proc.stdout
    assert "wrongdoc: true true" in proc.stdout, proc.stdout
