"""Regenerate docs/demo-receipts.{json,html}, docs/demo-receipts/*.json and
docs/chain.svg from the pack-demo store.

Route parity: each per-receipt file is the receipt body the /receipts/<id>.json
route serves (``transparency.json_loads(r.model_dump_json())`` re-dumped with
2-space indent); demo-receipts.json is the /receipts.json array. The index page
draws the receipts-table chain as a serpentine SVG and links every receipt to
verify.html#demo-receipts/<id>.

    python tools/make_receipts_page.py

Run from the repo root; reads data-pack-demo/attest.sqlite3 read-only.
"""

from __future__ import annotations

import html as htmllib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
DB = ROOT / "data-pack-demo" / "attest.sqlite3"

COLORS = {
    "visit_record": "#2563eb",
    "verifier_manifest": "#94a3b8",
    "log_checkpoint": "#0d9488",
    "case_export": "#7c3aed",
    "coverage_attestation": "#d97706",
    "period_digest": "#db2777",
    "key_rotation": "#dc2626",
    "key_adoption": "#ea580c",
    "key_revocation": "#991b1b",
    "verification_report": "#16a34a",
    "pack_verification": "#0891b2",
}
COLS = 10  # nodes per serpentine row
PITCH_X = 62  # horizontal pitch between node centers
PITCH_Y = 52  # vertical pitch between rows
X0, Y0 = 57, 52  # first node center
NODE = 18  # node square size


def _ctype(rec: dict) -> str:
    return rec["payload"].get("record_type") or "visit_record"


def _pos(i: int) -> tuple[int, int]:
    row, col = divmod(i, COLS)
    if row % 2:  # serpentine: odd rows run right-to-left
        col = COLS - 1 - col
    return X0 + col * PITCH_X, Y0 + row * PITCH_Y


def chain_svg(receipts: list[dict]) -> str:
    rows = (len(receipts) + COLS - 1) // COLS
    legend_y = Y0 + rows * PITCH_Y + 31
    height = legend_y + 2 * 22 + 8
    parts = [
        f'<svg viewBox="0 0 672 {height}" xmlns="http://www.w3.org/2000/svg" '
        f'role="group" aria-label="Hash chain of the {len(receipts)} signed receipts">'
    ]
    for i in range(1, len(receipts)):
        x1, y1 = _pos(i - 1)
        x2, y2 = _pos(i)
        parts.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#94a3b8" '
            f'stroke-width="1.5" stroke-dasharray=""/>'
        )
    legend = [t for t, _ in Counter(_ctype(r) for r in receipts).most_common()]
    legend += [t for t in COLORS if t not in legend]
    parts.append('<g font-family="system-ui,sans-serif" font-size="11">')
    for i, t in enumerate(legend):
        lx = 26 + (i % 5) * 128
        ly = legend_y + (i // 5) * 22
        parts.append(f'<rect x="{lx}" y="{ly}" width="9" height="9" rx="2" fill="{COLORS[t]}"/>')
        parts.append(f'<text x="{lx + 12}" y="{ly + 8}" fill="#475569">{t}</text>')
    parts.append("</g>")
    for i, r in enumerate(receipts):
        x, y = _pos(i)
        t = _ctype(r)
        ts = r["issued_at"].replace("+00:00", "Z")
        title = f"{r['id']} · {t} · seq {r['sequence']} · {ts}"
        parts.append(
            f'<a href="verify.html#demo-receipts/{r["id"]}">'
            f'<rect x="{x - 9}" y="{y - 9}" width="18" height="18" rx="4" '
            f'fill="{COLORS[t]}" stroke="#fff" stroke-width="1.2">'
            f"<title>{htmllib.escape(title)}</title></rect></a>"
        )
    parts.append("</svg>")
    return "\n".join(parts)


def main() -> int:
    if not DB.exists():
        print(f"no store at {DB}", file=sys.stderr)
        return 1
    sys.path.insert(0, str(ROOT / "src"))
    from attest import transparency
    from attest.store import Store

    store = Store(DB)
    try:
        receipts = [transparency.json_loads(r.model_dump_json()) for r in store.receipts()]
    finally:
        store.close()
    n = len(receipts)
    counts = Counter(_ctype(r) for r in receipts)

    out_dir = DOCS / "demo-receipts"
    out_dir.mkdir(exist_ok=True)
    keep = set()
    for r in receipts:
        keep.add(f"{r['id']}.json")
        (out_dir / f"{r['id']}.json").write_text(
            json.dumps(r, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    for stale in out_dir.glob("*.json"):
        if stale.name not in keep:
            stale.unlink()
    (DOCS / "demo-receipts.json").write_text(
        json.dumps(receipts, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    svg = chain_svg(receipts)
    (DOCS / "chain.svg").write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + svg + "\n", encoding="utf-8")

    visits = len({r["visit_id"] for r in receipts if _ctype(r) == "visit_record"})
    type_list = " · ".join(f"{c} {t}" for t, c in counts.most_common())
    desc = (
        f"All {n} signed receipts of the demo story, drawn as the hash chain "
        "itself — each a one-click browser verification."
    )
    rows = []
    for r in receipts:
        t = _ctype(r)
        ts = r["issued_at"].replace("+00:00", "Z").replace("T", " ")
        subj = htmllib.escape(r["visit_id"])
        rid = r["id"]
        rows.append(
            f'<tr><th scope="row"><a href="demo-receipts/{rid}.json"><code>{rid}</code></a></th>'
            f"<td>{t}</td><td><code>{subj}</code></td><td>{htmllib.escape(ts)}</td>"
            f'<td><a class="plink" href="verify.html#demo-receipts/{rid}" '
            f'aria-label="verify receipt {rid} in the browser verifier">verify →</a></td></tr>'
        )
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg' viewBox='0 0 16 16'%3E%3Cpath d='M8 1l6 2v5c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V3z' fill='%231c1c1e'/%3E%3Cpath d='M4.6 8.2l2.2 2.2 4.6-4.9' stroke='%23fff' stroke-width='1.5' fill='none'/%3E%3C/svg%3E">
<title>Signed receipts — the raw layer · Attest</title>
<meta name="description" content="{desc}">
<meta property="og:title" content="Signed receipts — the raw layer · Attest">
<meta property="og:description" content="{desc}">
<meta property="og:type" content="website">

<style>
body{{font-family:system-ui,sans-serif;max-width:66em;margin:0 auto;
padding:1.2rem;color:#1a1a1a;line-height:1.5}}
code{{background:#f4f4f5;padding:.1rem .35rem;border-radius:4px;font-size:.85em}}
a{{color:#2563eb}}
table{{border-collapse:collapse;width:100%;font-size:.88rem}}
th,td{{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #e4e4e7;vertical-align:top}}
thead th{{border-bottom:2px solid #a1a1aa}}
.plink{{color:#7c3aed;font-weight:600;white-space:nowrap}}
.plink:focus{{outline:2px solid #7c3aed;outline-offset:2px}}
.snap{{background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:.6rem .9rem;font-size:.85rem}}
.sum{{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;
padding:.6rem .9rem;font-size:.85rem;margin:.8rem 0}}
.small{{color:#6b6b70;font-size:.85rem}}
.tw{{overflow-x:auto}}
.sr-only{{position:absolute;width:1px;height:1px;overflow:hidden;
clip:rect(0 0 0 0);white-space:nowrap}}
</style>
</head>
<body>
<main>
<p class="snap"><strong>Static snapshot.</strong> These are the {n} signed receipts of
the simulated <em>Alvarez residence</em> deployment — the raw signed layer every
other surface derives from. Fetched from a live <code>attest demo</code> runtime's
<code>/receipts.json</code> surface; served here as static files. Nothing was
rewritten — bytes are the exact signed payloads.</p>
<h1>Signed receipts — the raw layer</h1>
<p class="sum"><strong>{n} receipts</strong> across {visits} visits and
2 issuer keys (a mid-history rotation — both lineages verify): {type_list}.</p>
<figure style="margin:.8rem 0;overflow-x:auto"><figcaption class="small">
<strong>The chain, literally.</strong> Each node is a receipt; every edge is a
<code>prev_hash</code> link — all {n - 1} verify. Hover a node for its id, type,
sequence, and issue time; click it to verify that receipt in your browser ·
<a href="chain.svg">open the SVG alone</a> to zoom.</figcaption>
{svg}
</figure>
<p>Every row is a self-contained Ed25519-signed receipt. <strong>verify →</strong>
opens this site's own verifier on that receipt (a lone signed JSON verifies the
same way the sweep receipt does). The JSON file itself is also directly
fetchable — the bytes are what was signed, not a rendering of them.</p>
<div class="tw"><table>
<thead><tr><th scope="col">receipt</th><th scope="col">record_type</th>
<th scope="col">subject</th><th scope="col">issued (UTC)</th>
<th scope="col"><span class="sr-only">file</span></th></tr></thead>
<tbody>
{chr(10).join(rows)}
</tbody>
</table></div>
<p class="small">Back to the <a href="index.html">landing page</a> ·
<a href="demo-receipts.json">all {n} as one JSON array</a> ·
<a href="verify.html">the verifier</a> ·
<a href="story.html">the story these receipts tell</a></p>
</main>
</body>
</html>
"""
    (DOCS / "demo-receipts.html").write_text(page, encoding="utf-8")
    print(f"demo-receipts: {n} receipts, {visits} visits -> page + {n} files + chain.svg")
    return 0


if __name__ == "__main__":
    sys.exit(main())
