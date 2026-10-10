"""Regenerate docs/site-manifest.json — a signed attest.receipt/2 whose
payload pins the sha256 of every artifact the static site ships, so the
hosted verifier's `#verify-site` deep link can prove each page's bytes
against the demo issuer's key.

Run from the repo root after any docs/ change:

    python tools/make_site_manifest.py --key data-pack-demo/attest-ed25519.key

The manifest never lists itself; artifact names are relative POSIX paths
under docs/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from attest.ledger import Signer
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--key",
        required=True,
        help="PEM Ed25519 key of the issuer the site attests under (the pack-demo deployment's signing key).",
    )
    ap.add_argument("--visit", default="site:josepha-mayo.github.io/attest")
    args = ap.parse_args()

    artifacts = _iter_artifacts()
    signer = Signer.load_or_create(Path(args.key))
    receipt = signer.issue(
        visit_id=args.visit,
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "site_manifest",
            "origin": "https://josepha-mayo.github.io/attest/",
            "artifacts": artifacts,
            "boundary": (
                "pins the sha256 of every file the site serves; a matching "
                "hash proves the served bytes are what the issuer shipped — "
                "not that any claim the bytes carry is true"
            ),
        },
    )
    OUT.write_text(
        json.dumps(json_loads(receipt.model_dump_json()), indent=1) + "\n",
        encoding="utf-8",
        newline="",
    )
    print(f"{OUT}: {len(artifacts)} artifacts pinned by {signer.public_key_b64[:16]}…")


if __name__ == "__main__":
    main()
