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


@pytest.mark.parametrize("vec", _vectors(), ids=lambda d: d.name)
def test_server_verifier_matches_oracle(vec: Path):
    spec = _spec(vec)
    data = (vec / "pack.zip").read_bytes()
    ok, detail = _verify_pack(data, _resolve_pin(data, spec))
    assert ok == (spec["verdict"] == "ok"), f"{vec.name}: {detail}"
    for frag in spec.get("detail_contains", []):
        assert frag in detail, f"{vec.name}: missing {frag!r} in {detail!r}"


@pytest.mark.parametrize("vec", _vectors(), ids=lambda d: d.name)
def test_embedded_verifier_matches_oracle(vec: Path, tmp_path: Path):
    spec = _spec(vec)
    with zipfile.ZipFile(vec / "pack.zip") as z:
        z.extractall(tmp_path)
    pin = spec.get("pin", "declared")
    key_args = [] if pin == "declared" else ["--key", pin]
    if spec["kind"] == "case":
        cmd = [PY, "verify_case.py", ".", *key_args]
    else:
        cmd = [PY, "verify_bundle.py", "bundle.json", *key_args]
    proc = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, timeout=120)
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
  if(job.rotations_file){rotNodes=get(parseKeep(await read(job.rotations_file)),'rotations').v;}
  if(job.attestation_files){
    for(const f of job.attestation_files){
      const n=parseKeep(await read(f));
      const rt=(toJS(n).payload||{}).record_type;
      if(rt==='key_rotation'||rt==='key_adoption'||rt==='key_revocation')rotNodes.push(n);
    }
  }
  const revoked=await revokedKeys(rotNodes);
  let trusted=null;
  if(job.manifest){
    const m=toJS(parseKeep(await read(job.manifest)));
    trusted=await trustedKeys(m.issuer_key||'',rotNodes);
  }
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
  console.log(JSON.stringify({
    bundles_ok:results.every(Boolean),
    trusted_count:trusted?trusted.size:0,
    suspect_count:suspect,
    lifecycle_suspect_count:suspectRecords(rotNodes,revoked).length,
  }));
})();`);
"""


def _js_job(zf: zipfile.ZipFile, tmp: Path, spec: dict) -> dict:
    """Extract the members the JS driver needs and describe the job."""
    names = zf.namelist()
    job: dict = {"bundles": [], "attestation_files": []}
    if spec["kind"] == "case":
        job["manifest"] = "manifest.json"
        (tmp / "manifest.json").write_bytes(zf.read("manifest.json"))
        bundles = sorted(n for n in names if n.startswith("visits/") and n.endswith("bundle.json"))
        job["bundles"] = bundles
        atts = sorted(n for n in names if n.startswith("attestations/") and n.endswith(".json"))
        job["attestation_files"] = atts
        for n in ["manifest.json", *bundles, *atts]:
            p = tmp / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(zf.read(n))
    else:
        job["bundles"] = ["bundle.json"]
        (tmp / "bundle.json").write_bytes(zf.read("bundle.json"))
        if "key_rotations.json" in names:
            job["rotations_file"] = "key_rotations.json"
            (tmp / "key_rotations.json").write_bytes(zf.read("key_rotations.json"))
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
        job = _js_job(z, tmp_path, spec)
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
