"""Regenerate docs/site-manifest.json — a signed attest.receipt/2 whose
payload pins the sha256 of every artifact the static site ships, so the
hosted verifier's `#verify-site` deep link can prove each page's bytes
against the demo issuer's key.

Run from the repo root after any docs/ change:

    python tools/make_site_manifest.py --dry-run
    python tools/make_site_manifest.py --write --key /existing/issuer.key

The deployment tree must match committed Git blob bytes. Commit intended docs
changes first, audit with --dry-run, then sign using the existing issuer only.
--check validates freshness without opening a private key.

The manifest never lists itself; artifact names are relative POSIX paths
under docs/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from attest.ledger import Signer, verify_receipt
from attest.transparency import json_loads

DOCS = Path("docs")
OUT = DOCS / "site-manifest.json"


def _iter_artifacts() -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for path in sorted(DOCS.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(DOCS).as_posix()
        if rel == "site-manifest.json" or "__pycache__" in rel:
            continue
        artifacts[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return artifacts


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def _audit(*, require_original: bool = True) -> tuple[dict[str, str], dict]:
    """Require exact committed deployment bytes, not newline-normalized guesses."""
    baseline = json_loads(_git("show", "HEAD:docs/site-manifest.json"))
    issuer = json_loads(_git("show", "HEAD:docs/.well-known/attest-issuer.json"))["issuer_key"]
    ok, why = verify_receipt(baseline, public_key=issuer)
    if not ok or baseline["payload"].get("record_type") != "site_manifest":
        raise ValueError(f"committed manifest is not valid under committed issuer: {why}")
    if require_original and OUT.read_bytes() != _git("show", "HEAD:docs/site-manifest.json"):
        raise ValueError("existing manifest differs from HEAD; refusing to overwrite it")
    artifacts = _iter_artifacts()
    paths = _git("ls-tree", "-r", "--name-only", "-z", "HEAD", "--", "docs").split(b"\0")
    committed = {}
    for raw in paths:
        if not raw:
            continue
        name = raw.decode("utf-8")
        rel = name.removeprefix("docs/")
        if rel == "site-manifest.json" or "__pycache__" in rel:
            continue
        if (DOCS / rel).is_symlink():
            raise ValueError(f"deployment symlink is not supported: {rel}")
        committed[rel] = hashlib.sha256(_git("show", f"HEAD:{name}")).hexdigest()
    drift = sorted(n for n in set(committed) | set(artifacts) if committed.get(n) != artifacts.get(n))
    if drift:
        raise ValueError(f"docs differ from committed deployment bytes: {drift}")
    return artifacts, baseline


def main() -> None:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Audit bytes; never open a signing key")
    mode.add_argument("--check", action="store_true", help="Audit bytes and require a fresh signed manifest")
    mode.add_argument("--write", action="store_true", help="Re-sign using the existing committed issuer")
    ap.add_argument("--key", help="Existing issuer PEM; never created or replaced")
    args = ap.parse_args()
    if args.write and not args.key:
        ap.error("--write requires --key pointing to an existing issuer key")
    if not args.write and args.key:
        ap.error("--key is only permitted with --write")
    artifacts, baseline = _audit(require_original=not args.check)
    current = json_loads(OUT.read_bytes())
    ok, why = verify_receipt(current, public_key=baseline["public_key"])
    if not ok or current["payload"].get("record_type") != "site_manifest":
        raise ValueError(f"current manifest is invalid: {why}")
    old = current["payload"]["artifacts"]
    drift = sorted(n for n in set(old) | set(artifacts) if old.get(n) != artifacts.get(n))
    if not args.write:
        print(
            json.dumps(
                {"artifacts": len(artifacts), "issuer": baseline["public_key"], "drift": drift}, indent=2
            )
        )
        if args.check and drift:
            raise SystemExit(1)
        return
    signer = Signer.load(Path(args.key))
    if signer.public_key_b64 != baseline["public_key"]:
        raise ValueError("key does not match the committed issuer; refusing identity change")
    receipt = signer.issue(
        visit_id=baseline["payload"]["visit_id"],
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "site_manifest",
            "origin": baseline["payload"]["origin"],
            "artifacts": artifacts,
            "boundary": (
                "pins the sha256 of every file the site serves; a matching "
                "hash proves the served bytes are what the issuer shipped — "
                "not that any claim the bytes carry is true"
            ),
        },
    )
    serialized = (json.dumps(json_loads(receipt.model_dump_json()), indent=1) + "\n").encode("utf-8")
    regenerated = json_loads(serialized)
    ok, why = verify_receipt(regenerated, public_key=baseline["public_key"])
    if not ok or regenerated["payload"]["artifacts"] != artifacts:
        raise ValueError(f"regenerated manifest failed validation: {why}")
    # Re-audit after signing, before the atomic replace; no partial output.
    if _audit() != (artifacts, baseline):
        raise ValueError("deployment bytes changed while signing")
    fd, tmp = tempfile.mkstemp(dir=OUT.parent, prefix=".site-manifest-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(serialized)
        os.replace(tmp, OUT)
    finally:
        Path(tmp).unlink(missing_ok=True)
    print(f"{OUT}: {len(artifacts)} artifacts pinned by {signer.public_key_b64[:16]}…")


if __name__ == "__main__":
    main()
