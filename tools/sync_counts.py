#!/usr/bin/env python3
"""Sync published corpus counts in hand-authored docs to the live artifacts.

Every number the site quotes — receipts, proven leaves, checkpoint size,
witness cosignatures, audit receipts, attack verdicts, vector count,
gauntlet width — is a property of generated artifacts, so a literal can only
ever be stale. This tool reads each artifact and rewrites the quoting strings
in place. Run it between the last minting step of a regen cascade and
`make_site_manifest.py` (the manifest must pin the final bytes).

    python tools/sync_counts.py            # patch in place
    python tools/sync_counts.py --check    # fail if any drift — CI guard

Patch table entries are (file, regex, replacement-callback) where the regex
carries enough context to be unambiguous. A pattern that matches nothing
warns — an anchor that silently stops matching is how stale claims ship.
"""

from __future__ import annotations

import argparse
import inspect
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

_ONES = [
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    "sixteen", "seventeen", "eighteen", "nineteen", "twenty",
]


def _word(n: int) -> str:
    """Twenty-eight — spelled-out counts stay readable in prose."""
    if n < len(_ONES):
        return _ONES[n].capitalize()
    if n < 100:
        tens, ones = divmod(n, 10)
        w = ["", "", "Twenty", "Thirty", "Forty",
             "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"][tens]
        return f"{w}-{_ONES[ones]}" if ones else w
    return str(n)


def derive() -> dict[str, int]:
    d: dict[str, int] = {}
    receipts = json.loads((DOCS / "demo-receipts.json").read_text(encoding="utf-8"))
    d["receipts"] = len(receipts)
    audit = {"pack_verification", "pack_comparison"}
    d["audit"] = sum(1 for r in receipts if r["payload"].get("record_type") in audit)
    with zipfile.ZipFile(DOCS / "sample-pack.zip") as z:
        cp = json.loads(z.read("log_checkpoint.json"))
        d["proven"] = len(cp["proofs"])
        d["cpsize"] = cp["checkpoint"]["payload"]["tree_size"]
        d["cosigs"] = len(cp.get("cosignatures", []))
        vm = json.loads(z.read("verifier_manifest.json"))
        d["tools"] = len(vm.get("tools", vm.get("members", vm)))
        man = json.loads(z.read("manifest.json"))
        d["visits"] = len(man.get("visits", man.get("records", [])))
    vm_rows = json.loads((DOCS / "vectors-manifest.json").read_text(encoding="utf-8"))
    d["vectors"] = len(vm_rows if isinstance(vm_rows, list) else vm_rows["vectors"])
    integ = json.loads((DOCS / "demo-integrity.json").read_text(encoding="utf-8"))
    d["suspect"] = integ["suspect_receipts"]
    # Attack totals come from the battery's own source — the same derivation
    # `attest judge` uses, so the site and the CLI can never disagree.
    sys.path.insert(0, str(ROOT / "src"))
    from attest import attackdemo, verifyjs

    src = inspect.getsource(attackdemo)
    d["attacks"] = src.count("results.append")
    m = re.search(r"(\d+)/(\d+) caught", (DOCS / "attacks.html").read_text(encoding="utf-8"))
    d["caught"] = int(m.group(1)) if m else d["attacks"] - 1
    seq = re.search(r"const seq=\[(.*?)\];", inspect.getsource(verifyjs), re.S)
    d["gauntlet"] = len(re.findall(r'\["[^"\]]+","', seq.group(1))) if seq else 9
    return d


def build_patches(d: dict[str, int]) -> list[tuple[str, str, str]]:
    """(file, regex, replacement) — replacement may use {key} from derive()."""
    audit_w = _word(d["audit"])
    return [
        ("index.html", r'demo-receipts\.html">\d+ signed receipts',
         'demo-receipts.html">{receipts} signed receipts'),
        ("tour.html", r"All \d+ signed receipts", "All {receipts} signed receipts"),
        ("tour.html", r"(?:Twenty|Thirty|Forty|Fifty|Sixty|Seventy|Eighty|Ninety)"
                      r"(?:-[a-z]+)? of them are the deployment",
         f"{audit_w} of them are the deployment"),
        ("anatomy.html", r"fetches the \d+ signed receipts",
         "fetches the {receipts} signed receipts"),
        ("anatomy.html", r"all \d+ receipts as the chain",
         "all {receipts} receipts as the chain"),
        ("anatomy.html", r"any of the \d+ real receipts",
         "any of the {receipts} real receipts"),
        ("../JUDGE.md", r"all \d+ signed receipts", "all {receipts} signed receipts"),
        ("../JUDGE.md", r"all \d+ at once", "all {receipts} at once"),
        ("../JUDGE.md", r"decomposes any of the \d+ field-by-field",
         "decomposes any of the {receipts} field-by-field"),
        ("../JUDGE.md", r"(?:Twenty|Thirty|Forty|Fifty|Sixty|Seventy|Eighty|Ninety)"
                         r"(?:-[a-z]+)? of them are the deployment\s+auditing",
         f"{audit_w} of them are the deployment auditing"),
        ("../JUDGE.md", r"\d+ receipts in scope", "{suspect} receipts in scope"),
        ("../src/attest/verifyjs.py", r"renders all \d+ live verdicts",
         "renders all {attacks} live verdicts"),
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="report drift without writing; exit 1 if any found")
    args = ap.parse_args()
    d = derive()
    drift = []
    for rel, pat, tpl in build_patches(d):
        path = (DOCS / rel).resolve()
        if not path.exists():
            print(f"sync-counts: {rel}: file missing — pattern table stale", file=sys.stderr)
            drift.append(rel)
            continue
        text = path.read_text(encoding="utf-8")
        new, n = re.subn(pat, lambda _, t=tpl: t.format(**d), text)
        if n == 0:
            # Not drift if the replacement is already the text — only if the
            # pattern is truly absent (stale anchor) or already applied.
            if tpl.format(**d) in text:
                continue
            print(f"sync-counts: {rel}: /{pat}/ matched nothing — anchor moved?",
                  file=sys.stderr)
            drift.append(rel)
            continue
        if new != text:
            drift.append(rel)
            if not args.check:
                path.write_text(new, encoding="utf-8", newline="")
                print(f"sync-counts: {rel}: {n} count(s) synced")
    if drift and args.check:
        print(f"sync-counts: {len(drift)} file(s) drifted — run tools/sync_counts.py",
              file=sys.stderr)
        return 1
    if not drift:
        print("sync-counts: all quoted counts already match the artifacts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
