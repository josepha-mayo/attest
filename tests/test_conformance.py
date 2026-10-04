"""Cross-verifier conformance: the committed vector corpus is the contract.

Every Attest verifier — the server-side pack checker, the embedded
stdlib-only Python scripts, and the dependency-free browser JS lib under
node — must judge the same bytes identically. A disagreement is a verifier
bug, not a test tweak. Regenerate the corpus with tools/make_vectors.py
when the pack format deliberately changes.
"""

from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from attest.app import _verify_pack
from attest.models import Receipt
from attest.verifyjs import VERIFY_HTML

VECTORS = Path(__file__).parent / "vectors"
NODE = shutil.which("node")
PY = sys.executable


def _vectors() -> list[Path]:
    return sorted(d for d in VECTORS.iterdir() if d.is_dir())


def _spec(d: Path) -> dict:
    return json.loads((d / "expected.json").read_text(encoding="utf-8"))


def _resolve_pin(data: bytes, spec: dict) -> str:
    pin = spec.get("pin", "declared")
    if pin != "declared":
        return pin
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if spec["kind"] == "case":
            return json.loads(z.read("manifest.json"))["issuer_key"]
        return json.loads(z.read("bundle.json"))["original"]["public_key"]


def _issuer_doc(vec: Path, spec: dict) -> dict | None:
    """A vector may ship an attest.issuer/1 document beside the pack — its
    issuer_key becomes the pin and its signed lifecycle receipts the lineage
    pool, on every verifier surface."""
    name = spec.get("issuer_doc")
    if not name:
        return None
    return json.loads((vec / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("vec", _vectors(), ids=lambda d: d.name)
def test_server_verifier_matches_oracle(vec: Path):
    spec = _spec(vec)
    data = (vec / "pack.zip").read_bytes()
    doc = _issuer_doc(vec, spec)
    if doc is not None:
        pin = doc["issuer_key"]
        known = [Receipt.model_validate(r) for r in doc.get("key_receipts") or []]
    else:
        pin, known = _resolve_pin(data, spec), None
    ok, detail = _verify_pack(data, pin, known_rotations=known)
    assert ok == (spec["verdict"] == "ok"), f"{vec.name}: {detail}"
    for frag in spec.get("detail_contains", []):
        assert frag in detail, f"{vec.name}: missing {frag!r} in {detail!r}"
    for frag in spec.get("detail_excludes", []):
        assert frag not in detail, f"{vec.name}: unexpected {frag!r} in {detail!r}"


@pytest.mark.parametrize("vec", _vectors(), ids=lambda d: d.name)
def test_embedded_verifier_matches_oracle(vec: Path, tmp_path: Path):
    spec = _spec(vec)
    # The pack extracts into pack/ — an issuer document lands one level up
    # (its provenance is a different channel); inside the pack dir it would
    # be smuggled content and correctly fail the member check.
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    with zipfile.ZipFile(vec / "pack.zip") as z:
        z.extractall(pack_dir)
    doc = _issuer_doc(vec, spec)
    if doc is not None:
        (tmp_path / spec["issuer_doc"]).write_text(json.dumps(doc, indent=2), encoding="utf-8")
        key_args = ["--issuer", str(tmp_path / spec["issuer_doc"])]
    else:
        pin = spec.get("pin", "declared")
        key_args = [] if pin == "declared" else ["--key", pin]
    if spec["kind"] == "case":
        cmd = [PY, "verify_case.py", ".", *key_args]
    else:
        cmd = [PY, "verify_bundle.py", "bundle.json", *key_args]
    proc = subprocess.run(cmd, cwd=pack_dir, capture_output=True, text=True, timeout=120)
    out = proc.stdout + proc.stderr
    if spec["verdict"] == "ok":
        assert proc.returncode == 0, f"{vec.name}: {out}"
        assert "OK" in out
    else:
        assert proc.returncode != 0, f"{vec.name}: expected FAIL, got:\n{out}"
        assert "FAIL" in out
    # The annotation phrasing is part of the contract — the suspect-window and
    # trust-pivot lines are the revocation feature's observable surface.
    for frag in spec.get("detail_contains", []):
        assert frag in out, f"{vec.name}: missing {frag!r} in {out!r}"
    for frag in spec.get("detail_excludes", []):
        assert frag not in out, f"{vec.name}: unexpected {frag!r} in {out!r}"


def _js_driver() -> str:
    """Node driver: run _JS_LIB (script minus the zip-loading tail) against
    members the Python side already extracted — the same trust math the
    in-browser verifier runs, judged against the shared oracle."""
    return """
const fs=require('fs');
let src=fs.readFileSync(process.argv[2],'utf8').replace(/const dz=[\\s\\S]*$/,'');
const dir=process.argv[3]+'/';
const job=JSON.parse(fs.readFileSync(process.argv[4],'utf8'));
eval(src + `
(async()=>{
  const read=p=>fs.readFileSync(dir+p,'utf8');
  let rotNodes=[];
  let issuerKey=null;
  if(job.issuer_doc){
    const dn=parseKeep(await read(job.issuer_doc)),d=toJS(dn)||{};
    const kn=get(dn,'key_receipts');
    issuerKey=d.issuer_key;
    rotNodes=rotNodes.concat(kn&&kn.t==='arr'?kn.v:[]);
  }
  if(job.rotations_file){rotNodes=rotNodes.concat(
    get(parseKeep(await read(job.rotations_file)),'rotations').v);}
  if(job.attestation_files){
    for(const f of job.attestation_files){
      const n=parseKeep(await read(f));
      const rt=(toJS(n).payload||{}).record_type;
      if(rt==='key_rotation'||rt==='key_adoption'||rt==='key_revocation')rotNodes.push(n);
    }
  }
  let trusted=null;
  let manifestIssuer=null;
  if(job.manifest){
    const m=toJS(parseKeep(await read(job.manifest)));
    manifestIssuer=m.issuer_key||'';
    trusted=await trustedKeys(manifestIssuer,rotNodes);
  }
  // Revocation authority anchors at the same key verifyFiles uses: the
  // manifest issuer for case packs, the bundle's own original key for
  // dispute packs — never pool order.
  let revAnchor=manifestIssuer||'';
  if(!revAnchor){
    const n0=parseKeep(await read(job.bundles[0]));
    revAnchor=(toJS(get(n0,'original'))||{}).public_key||'';
  }
  const revoked=await revokedKeys(rotNodes,revAnchor);
  const results=[];
  for(const b of job.bundles){
    const node=parseKeep(await read(b));
    if(!trusted){
      const oKey=toJS(get(node,'original')||{v:[]}).public_key;
      trusted=new Set([oKey,
        ...(await trustedKeys(oKey,rotNodes)),
        ...(await descendantKeys(oKey,rotNodes))]);
    }
    const c=await checkBundle(node,trusted);
    results.push(c.ok);
  }
  // suspect over bundle records vs. key-lifecycle receipts, counted apart —
  // same split the pack drivers report.
  let suspect=0;
  for(const b of job.bundles){
    const node=parseKeep(await read(b));
    suspect+=suspectRecords(
      [get(node,'original')].concat((get(node,'reviews')||{v:[]}).v.map(e=>get(e,'receipt'))),
      revoked).length;
  }
  // Pin linkage mirrors verifyFiles: the doc's issuer must be reachable from
  // the pack's issuer through the signed lifecycle — either direction.
  let pinLinked=null;
  if(issuerKey!==null){
    if(manifestIssuer!==null){
      const reach=new Set([manifestIssuer,...trusted,
        ...(await descendantKeys(manifestIssuer,rotNodes))]);
      pinLinked=reach.has(issuerKey);
    }else{
      pinLinked=trusted!==null&&trusted.has(issuerKey);
    }
  }
  // Full pack-driver pass: the same verifyFiles the browser runs — member
  // whitelists, manifest consistency, media digests, the signed tool pin —
  // not just the lib functions above. File shims replay the extracted zip.
  let verdict=null;
  if(job.members){
    const files=job.members.map(n=>{
      const buf=fs.readFileSync(dir+n);
      return {name:n,
        text:async()=>buf.toString('utf8'),
        arrayBuffer:async()=>buf.buffer.slice(buf.byteOffset,buf.byteOffset+buf.length)};
    });
    if(job.issuer_doc){
      /* Arm the pin exactly like the drop path: the doc's own parseKeep nodes
         preserve canonical spellings for the lifecycle signatures. */
      const dn=parseKeep(await read(job.issuer_doc)),d=toJS(dn)||{};
      const kn=get(dn,'key_receipts');
      issuerDoc={issuer_key:d.issuer_key,nodes:kn&&kn.t==='arr'?kn.v:[]};
    }
    const html=await verifyFiles(files);
    verdict=html.includes('FAILED')?'fail':(html.includes('VERIFIED')?'ok':'?');
  }
  console.log(JSON.stringify({
    bundles_ok:results.every(Boolean),
    trusted_count:trusted?trusted.size:0,
    suspect_count:suspect,
    lifecycle_suspect_count:suspectRecords(rotNodes,revoked).length,
    pin_linked:pinLinked,
    verdict:verdict,
  }));
})();`);
"""


def _js_job(zf: zipfile.ZipFile, tmp: Path, spec: dict, vec: Path) -> dict:
    """Extract the members the JS driver needs and describe the job."""
    names = zf.namelist()
    job: dict = {"bundles": [], "attestation_files": []}
    if spec.get("issuer_doc"):
        job["issuer_doc"] = spec["issuer_doc"]
        (tmp / spec["issuer_doc"]).write_bytes((vec / spec["issuer_doc"]).read_bytes())
    # The full pack-driver pass replays EVERY member — the same files a
    # dropped zip would hand verifyFiles in the browser.
    job["members"] = [n for n in names if not n.endswith("/")]
    for n in job["members"]:
        p = tmp / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(zf.read(n))
    if spec["kind"] == "case":
        job["manifest"] = "manifest.json"
        job["bundles"] = sorted(n for n in names if n.startswith("visits/") and n.endswith("bundle.json"))
        job["attestation_files"] = sorted(
            n for n in names if n.startswith("attestations/") and n.endswith(".json")
        )
    else:
        job["bundles"] = ["bundle.json"]
        if "key_rotations.json" in names:
            job["rotations_file"] = "key_rotations.json"
    return job


@pytest.mark.skipif(NODE is None, reason="node runtime not available")
@pytest.mark.parametrize("vec", _vectors(), ids=lambda d: d.name)
def test_browser_lib_matches_oracle(vec: Path, tmp_path: Path):
    spec = _spec(vec)
    want = spec.get("js")
    if want is None:
        pytest.skip("vector has no lib-level oracle (driver-only semantics)")
    m = re.search(r"<script>(.*)</script>", VERIFY_HTML, re.S)
    (tmp_path / "verify.js").write_text(m.group(1), encoding="utf-8")
    (tmp_path / "drive.js").write_text(_js_driver(), encoding="utf-8")
    with zipfile.ZipFile(vec / "pack.zip") as z:
        job = _js_job(z, tmp_path, spec, vec)
    (tmp_path / "job.json").write_text(json.dumps(job), encoding="utf-8")
    proc = subprocess.run(
        [NODE, "drive.js", "verify.js", str(tmp_path), "job.json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout.strip().splitlines()[-1])
    if "bundle_ok" in want:
        assert got["bundles_ok"] == want["bundle_ok"], f"{vec.name}: {got}"
    if "trusted_count" in want:
        assert got["trusted_count"] == want["trusted_count"], f"{vec.name}: {got}"
    if "suspect_count" in want:
        assert got["suspect_count"] == want["suspect_count"], f"{vec.name}: {got}"
    if "lifecycle_suspect_count" in want:
        assert got["lifecycle_suspect_count"] == want["lifecycle_suspect_count"], f"{vec.name}: {got}"
    if "pin_linked" in want:
        assert got["pin_linked"] == want["pin_linked"], f"{vec.name}: {got}"
    if "verdict" in want:
        assert got["verdict"] == want["verdict"], f"{vec.name}: {got}"
