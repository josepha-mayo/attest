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
    s = Signer.ephemeral()
    r1 = s.issue(
        visit_id="vis_a",
        sequence=1,
        prev_hash=None,
        facts={"record_type": "visit", "coverage": {"fraction": 0.047619047619047616}},
    )
    r2 = s.issue(
        visit_id="vis_a",
        sequence=2,
        prev_hash=r1.payload_hash,
        facts={"record_type": "review", "statement": "tést — non-ascii"},
    )
    return s, r1, r2


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
    (tmp_path / "r1.json").write_text(r1.model_dump_json(indent=2), encoding="utf-8")
    (tmp_path / "r2.json").write_text(r2.model_dump_json(indent=2), encoding="utf-8")
    driver = """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
const a=fs.readFileSync(process.argv[3],'utf8'),b=fs.readFileSync(process.argv[4],'utf8');
eval(src + `
(async()=>{
  console.log('chain:',JSON.stringify(await checkChain([parseKeep(a),parseKeep(b)],null)));
  const rev=JSON.parse(b);rev.prev_hash='0'.repeat(64);
  console.log('broken:',JSON.stringify(await checkChain([parseKeep(a),parseKeep(JSON.stringify(rev))],null)));
})();`);
"""
    (tmp_path / "drive.js").write_text(driver, encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", "r1.json", "r2.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert '"ok":true' in proc.stdout and "chain intact" in proc.stdout
    assert "broken" in proc.stdout


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
