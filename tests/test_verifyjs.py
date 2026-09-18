"""The browser verifier embedded in packs is real crypto, not packaging:

the same <script> block is executed under node against a Python-signed receipt
chain — a valid chain verifies, a tampered payload and a wrong key both fail.
Skipped when node is not installed (CI without a JS runtime still passes).
"""

import io
import re
import shutil
import subprocess
import zipfile

import pytest

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
        "escaped: true",
        "empty: true",
    ):
        assert expected in out, out


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


def _case_pack(engine, store, household, schedule, t0, tmp_path):
    from ring_sandbox import WebhookEvent, webhooks

    from attest.disputepack import build_case_pack
    from attest.reviews import ReviewService, countersign_status

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
def test_case_pack_index_verifies_records_in_browser(engine, store, household, schedule, t0, tmp_path):
    """Run index.html's own script under node with a minimal DOM stub — the
    embedded driver must verify the real inlined bundle and report VERIFIED."""
    import re

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
  console.log('timeline:',els.cards.innerHTML.includes('<svg'));
  console.log('corr:',(els.cards.innerHTML.match(/class="corr"/g)||[]).length);
  console.log('corrrows:',els.cards.innerHTML.includes('Pipeline coverage'));
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
    assert "cards: 1" in out, out
    assert "timeline: true" in out, out
    assert "corr: 1" in out, out
    assert "corrrows: true" in out, out


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
    assert "cards: 1" in out, out
    assert "corr: 1" in out, out


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
def test_verify_html_reads_the_zip_directly(engine, store, household, schedule, t0, tmp_path):
    """verify.html must verify a dropped .zip: readZipEntries parses stored +
    deflate entries (node's DecompressionStream stands in for the browser's),
    and media files are matched by CONTENT hash — their filenames hold only a
    digest prefix."""
    z = _case_pack(engine, store, household, schedule, t0, tmp_path)
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
    assert "export signed" in out, out
