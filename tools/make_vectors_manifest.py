#!/usr/bin/env python3
"""Rebuild docs/vectors-manifest.json from the tests/vectors oracles and
sync the hosted pack bytes.

The hosted page (`docs/vectors.html` rows + `verify.html#vectors/<name>`
deep links) reads this manifest — it is NOT written by make_vectors.py
(which emits the repo corpus) because hosting is a publishing decision:
vectors whose oracle needs a live issuer document sidecar stay repo-only.

Per row, from expected.json:
  name          vector dir name
  verdict       the shared oracle's verdict ("ok"/"fail")
  note          the oracle's explanation (rendered beside the deep link)
  pin_required  derived: the pack's oracle FAILs only under a --key pin —
                verdict == "fail" while the browser oracle (js.verdict,
                which verifies self-declared) says "ok". The browser row
                must annotate that its green stamp IS the attack the pin
                defeats, or a judge reads corpus-vs-verdict disagreement.

Also copies each hosted pack.zip -> docs/vectors/<name>.zip when bytes
differ (the embedded verifier changes invalidate them every regen), and
warns on repo vectors missing from the hosted set.
"""

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors"
DOCS = ROOT / "docs" / "vectors"
MANIFEST = ROOT / "docs" / "vectors-manifest.json"


def main() -> int:
    rows = []
    synced = missing = 0
    for d in sorted(VECTORS.iterdir()):
        if not d.is_dir():
            continue
        exp = json.loads((d / "expected.json").read_text(encoding="utf-8"))
        hosted = DOCS / f"{d.name}.zip"
        pack = d / "pack.zip"
        if not hosted.exists():
            missing += 1
            continue
        row = {"name": d.name, "verdict": exp["verdict"], "note": exp["note"]}
        js = exp.get("js") or {}
        if exp["verdict"] == "fail" and js.get("verdict") == "ok":
            row["pin_required"] = True
        rows.append(row)
        if pack.exists() and pack.read_bytes() != hosted.read_bytes():
            shutil.copy2(pack, hosted)
            synced += 1
    MANIFEST.write_text(
        json.dumps(rows, indent=1, ensure_ascii=False) + "\n", encoding="utf-8",
        newline="",
    )
    print(
        f"vectors-manifest: {len(rows)} hosted rows"
        + (f", {synced} pack(s) re-synced" if synced else "")
        + (f", {missing} repo-only vector(s) intentionally unhosted" if missing else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
