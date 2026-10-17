"""Regenerate docs/attacks.html — the adversarial battery's verdicts,
rendered from a live run against the shipped demo store.

The page never quotes a stale transcript: it opens ``data-pack-demo``,
runs ``attackdemo.run`` for real (every attempt executes inside a transaction
that rolls back — the store it attacks is the one the sample packs exported
from), and renders the verdict lines verbatim. A SKIPPED row means the store
lacked the precondition for that attack; it is reported, never counted as a
catch.

    ATTEST_DATA_DIR=data-pack-demo python tools/make_attacks.py

Run from the repo root.
"""

from __future__ import annotations

import html as htmllib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attest import attackdemo  # noqa: E402
from attest.config import settings  # noqa: E402
from attest.instance import acquire_instance_lock  # noqa: E402
from attest.store import Store  # noqa: E402

DOCS = ROOT / "docs"
ESC = htmllib.escape


def main() -> None:
    db = settings.data_dir / "attest.sqlite3"
    if not db.exists():
        sys.exit(f"no store at {db} — expected ATTEST_DATA_DIR=data-pack-demo")
    acquire_instance_lock(settings.data_dir)
    store = Store(db)
    inbox = None
    inbox_path = settings.data_dir / "webhooks.sqlite3"
    if inbox_path.exists():
        from attest.inbox import WebhookInbox

        inbox = WebhookInbox(inbox_path)

    from attest.cli import _cli_engine

    engine = _cli_engine(store)
    out = attackdemo.run(store, settings.data_dir / "media", inbox=inbox, engine=engine)

    results = out["results"]
    n_caught = sum(1 for r in results if r["caught"] is True)
    n_skip = sum(1 for r in results if r["caught"] is None)
    n_err = sum(1 for r in results if r["caught"] == "error")
    n_bound = sum(1 for r in results if r["caught"] is False and r.get("boundary"))
    n_missed = sum(1 for r in results if r["caught"] is False and not r.get("boundary"))
    n = len(results)
    unchanged = out["unchanged"]

    rows = []
    for r in results:
        if r["caught"] is None:
            badge = '<span class="b skip">SKIPPED</span>'
        elif r["caught"] == "error":
            badge = '<span class="b miss">ERROR</span>'
        elif r["caught"]:
            badge = '<span class="b ok">CAUGHT</span>'
        elif r.get("boundary"):
            badge = '<span class="b bound">EXPECTED MISS</span>'
        else:
            badge = '<span class="b miss">MISSED</span>'
        rows.append(
            f"<tr><td>{badge}</td><td>{ESC(r['attack'])}</td>"
            f'<td class="d">{ESC(r["detail"])}</td></tr>'
        )

    verdict = (
        f"{n_caught}/{n - n_skip - n_err} caught"
        + (f", {n_skip} skipped (precondition absent)" if n_skip else "")
        + (f", {n_missed} MISSED" if n_missed else "")
        + (f", {n_err} battery error(s)" if n_err else "")
        + (f" + {n_bound} documented detection boundary" if n_bound else "")
    )
    stamp = "ok" if n_missed == 0 and n_err == 0 and n_caught else "miss"

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http%3A%2F%2Fwww.w3.org%2F2000/svg' viewBox='0 0 16 16'%3E%3Cpath d='M8 1l6 2v5c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V3z' fill='%231c1c1e'/%3E%3Cpath d='M4.6 8.2l2.2 2.2 4.6-4.9' stroke='%23fff' stroke-width='1.5' fill='none'/%3E%3C/svg%3E">
<title>Twenty-three attacks. Every one named — even the one that wins. · Attest</title>
<meta name="description" content="The adversarial battery's real output — each tamper attempt executed against the shipped demo store, caught, and rolled back. The one attack nothing can catch is listed too, as a named boundary.">
<meta property="og:title" content="Twenty-three attacks. Every one named — even the one that wins.">
<meta property="og:description" content="attest attack-demo run live on the demo store — verdicts rendered verbatim.">
<meta property="og:type" content="website">
<meta property="og:image" content="https://josepha-mayo.github.io/attest/og-image.png">
<meta property="og:url" content="https://josepha-mayo.github.io/attest/attacks.html">
<style>
body{{font-family:system-ui,sans-serif;max-width:62em;margin:0 auto;
padding:1.4rem 1.2rem;color:#1c1c1e;line-height:1.55}}
a{{color:#2563eb}}
h1{{margin-bottom:.15rem}}
.sub{{color:#6b6b70;margin-top:0}}
.score{{font-size:1.4rem;font-weight:700;margin:1rem 0 .2rem}}
.score.ok{{color:#166534}} .score.miss{{color:#991b1b}}
table{{border-collapse:collapse;width:100%;margin:1.2rem 0;font-size:.92rem}}
td,th{{text-align:left;padding:.5rem .7rem;border-bottom:1px solid #e4e4e7;
vertical-align:top}}
th{{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;
color:#6b6b70}}
.b{{display:inline-block;border-radius:5px;padding:.08rem .45rem;
font-size:.72rem;font-weight:700;letter-spacing:.03em;white-space:nowrap}}
.b.ok{{background:#dcfce7;color:#166534}}
.b.skip{{background:#fef3c7;color:#92400e}}
.b.bound{{background:#ede9fe;color:#5b21b6}}
.b.miss{{background:#fee2e2;color:#991b1b}}
.d{{font-family:ui-monospace,monospace;font-size:.78rem;color:#52525b}}
code{{background:#f4f4f5;padding:.08rem .35rem;border-radius:4px;
font-size:.88em}}
.note{{background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;
padding:.7rem 1rem;font-size:.9rem}}
.cta{{display:flex;gap:.7rem;flex-wrap:wrap;margin:1.4rem 0}}
.btn{{border:1px solid #d4d4d8;border-radius:8px;padding:.55rem 1rem;
text-decoration:none;color:inherit;font-size:.9rem;background:#fff}}
.btn:hover{{border-color:#2563eb}}
.btn.pri{{background:#2563eb;border-color:#2563eb;color:#fff}}
.small{{color:#6b6b70;font-size:.82rem}}
footer.page{{margin-top:3rem;padding-top:1rem;border-top:1px solid #e4e4e7;
color:#6b6b70;font-size:.8rem}}
</style>
</head>
<body>
<main>
<p class="small"><a href="index.html">Attest</a> → the attack battery</p>
<h1>Twenty-three attempts.<br>Every one named — even the one that wins.</h1>
<p class="sub">"Tamper-evident" is a claim; this page is the test. Each row
below is a real attempt executed against the same store the
<a href="sample-pack.zip">shipped sample pack</a> exported from — inside a
transaction that is never committed, so the store is byte-identical after.
Verdicts rendered verbatim from the run; nothing on this page is
hand-written prose about what <em>would</em> happen. The one row no
in-process check can catch — a forged row <em>plus</em> its covering
journal entry — is listed too, marked EXPECTED MISS: an honest battery
names its own edge, and the fix (<code>attest anchor --publish</code>)
is on this site.</p>

<div class="score {stamp}">{ESC(verdict)} — store unchanged:
{"yes" if unchanged else "NO"}</div>
<p class="small">A SKIPPED row means the store lacked that attack's
precondition (e.g. nothing to forge) — it is reported, never counted.
EXPECTED MISS is a documented detection boundary, not a defense failure.
Reproduce: <code>attest demo</code> then <code>attest attack-demo</code>
in the checkout; the battery exits non-zero on any MISSED or ERROR.</p>

<table>
<tr><th></th><th>attack</th><th>how it was caught</th></tr>
{"".join(rows)}
</table>

<div class="note"><b>Attack the export, not the store.</b> The table mixes
in-store and artifact-layer tampering — the forged-verifier, grafted-receipt,
and truncated-review rows attack the pack format itself. Four more artifact
attacks ship as real zips you can feed the
<a href="verify.html">browser verifier</a> right now — a doctored number, a
deleted record, a smuggled file, a forged verifier:
<a href="verify.html#sample-pack-tampered">the twin</a> ·
<a href="verify.html#sample-pack-attack-missing-record">deleted record</a> ·
<a href="verify.html#sample-pack-attack-smuggled-file">smuggled file</a> ·
<a href="verify.html#sample-pack-attack-forged-verifier">forged verifier</a>.
Or <a href="verify.html#tamper-lab">forge a field yourself</a> in the tamper
lab.</div>

<div class="cta">
<a class="btn pri" href="verify.html#gauntlet">Run the 9-artifact oracle →</a>
<a class="btn" href="verify.html#tamper-lab">Tamper lab →</a>
<a class="btn" href="tour.html">2-minute tour →</a>
</div>

<footer class="page">Generated by <code>tools/make_attacks.py</code> running
<code>attackdemo.run</code> against <code>data-pack-demo</code> — every row
above is a live verdict from that run, not a transcript pasted in.</footer>
</main>
</body>
</html>
"""
    (DOCS / "attacks.html").write_text(page, encoding="utf-8", newline="")
    print(f"attacks.html: {verdict}; unchanged={unchanged}")
    if n_missed or n_err or not unchanged:
        sys.exit(1)


if __name__ == "__main__":
    main()
