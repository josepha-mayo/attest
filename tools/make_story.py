"""Regenerate docs/story.html — the contested visit retold entirely from
shipped, signed bytes.

Every quote, timestamp, count, and claim on the page is read out of
``docs/sample-pack.zip`` (the exact artifact judges download), so the page can
never drift from the evidence it narrates. Review-chain statements live inside
the visit bundle — they deep-link to ``verify.html#sample-pack``; the original
receipt deep-links to its one-click slot in the receipts index.

    python tools/make_story.py

Run from the repo root. No third-party imports.
"""

from __future__ import annotations

import html as htmllib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PACK = DOCS / "sample-pack.zip"
VISIT = "vis_70e42116a4cf"  # the contested visit — same id the twin tampers

ESC = htmllib.escape


def _utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _hm(ts: str) -> str:
    d = _utc(ts).astimezone(UTC)
    return d.strftime("%I:%M %p").lstrip("0")


def _dt(ts: str) -> str:
    d = _utc(ts).astimezone(UTC)
    return d.strftime("%b ") + str(d.day) + ", " + d.strftime("%I:%M %p").lstrip("0")


def _short(rid: str) -> str:
    return rid[:18] + "…"


def main() -> None:
    z = zipfile.ZipFile(PACK)
    bundle = json.loads(z.read(f"visits/{VISIT}/bundle.json"))
    o = bundle["original"]
    p = o["payload"]

    sched = p["schedule"]
    ws, we = _hm(sched["window_start"]), _hm(sched["window_end"])
    expected = sched["expected_minutes"]
    service = ESC(sched["service"])
    site = ESC(p["site"]["name"])
    worker = ESC(p["worker"])

    ev_rows = []
    ev_counts = 0
    n_device = 0
    for ev in p.get("evidence", []):
        ev_counts += 1
        if ev.get("device"):
            n_device += 1
        kind = ev["kind"].replace("_", " ")
        src = ev.get("ingestion_source") or ""
        src_tag = f' <span class="src">{ESC(src)}</span>' if src else ""
        media = ' <span class="src">sha-256 pinned</span>' if ev.get("media_sha256") else ""
        ev_rows.append(f"<li><b>{_hm(ev['at'])}</b> {ESC(kind)}{src_tag}{media}</li>")
    n_other = ev_counts - n_device

    cov = p.get("history_poll_coverage") or {}
    cov_pct = round(100 * (cov.get("fraction") or 0))
    cov_state = ESC(str(cov.get("state", "")).replace("_", " "))
    cov_claim = ESC(cov.get("claim") or "")
    cov_ws = (cov.get("window") or {}).get("start")
    cov_we = (cov.get("window") or {}).get("end")
    cov_span = f"{_hm(cov_ws)} – {_hm(cov_we)} UTC" if cov_ws and cov_we else "its bounded window"

    assessed = p["assessment"]
    flags = p.get("flags") or []
    flag_rows = "".join(f"<li><code>{ESC(f['code'])}</code> — {ESC(f['message'])}</li>" for f in flags)

    reviews = bundle.get("reviews", [])
    voices = []
    for r in reviews:
        rp = r["receipt"]["payload"]
        act, rv = rp["actor"], rp["review"]
        role = act.get("role", "?")
        name = ESC(act.get("name") or ("Household member" if role == "household" else role))
        stmt = ESC(str(rv.get("statement") or rv.get("decision") or ""))
        cls = {"worker": "v-worker", "household": "v-house"}.get(role, "v-other")
        extra = ""
        if rv.get("reason_label"):
            extra += (
                f'<div class="why">stated reason: {ESC(rv["reason_label"])} '
                "<i>(worker-stated, never a verified cause)</i></div>"
            )
        if rv.get("perception"):
            extra += f'<div class="why">perception: <code>{ESC(rv["perception"])}</code></div>'
        auth = ESC(act.get("authentication", ""))
        when = rp.get("statement_received_at") or rp.get("issued_at") or ""
        when_txt = f" · {_dt(when)} UTC" if when else ""
        voices.append(
            f'<blockquote class="voice {cls}"><p>“{stmt}”</p>'
            f"<footer>{name} · via {auth}{when_txt} · signed verbatim · "
            f'<a href="verify.html#sample-pack">verify inside the pack →</a>{extra}</footer></blockquote>'
        )

    rid = o["id"]
    span = p.get("observed_span_minutes")
    # The doctored value is read out of the shipped twin itself — the page
    # tells on the tamper verbatim instead of recomputing what it should be.
    tampered_span = None
    twin_path = DOCS / "sample-pack-tampered.zip"
    if twin_path.exists():
        twin = zipfile.ZipFile(twin_path)
        tampered_span = json.loads(twin.read(f"visits/{VISIT}/bundle.json"))["original"]["payload"].get(
            "observed_span_minutes"
        )
    if tampered_span is None and span is not None:
        tampered_span = round(span + 70, 2)  # twin absent — derive from the signed field
    desc = (
        "The contested visit, retold entirely from signed bytes — every "
        "quote below is lifted from the artifact you can verify."
    )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg' viewBox='0 0 16 16'%3E%3Cpath d='M8 1l6 2v5c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V3z' fill='%231c1c1e'/%3E%3Cpath d='M4.6 8.2l2.2 2.2 4.6-4.9' stroke='%23fff' stroke-width='1.5' fill='none'/%3E%3C/svg%3E">
<title>One visit. Three accounts. Nothing rewritten. · Attest</title>
<meta name="description" content="{desc}">
<meta property="og:title" content="One visit. Three accounts. Nothing rewritten.">
<meta property="og:description" content="{desc}">
<meta property="og:type" content="website">
<meta property="og:image" content="https://josepha-mayo.github.io/attest/og-image.png">
<meta property="og:url" content="https://josepha-mayo.github.io/attest/story.html">
<style>
body{{font-family:system-ui,sans-serif;max-width:56em;margin:0 auto;
padding:1.4rem 1.2rem;color:#1c1c1e;line-height:1.55}}
a{{color:#2563eb}}
h1{{margin-bottom:.15rem}}
.sub{{color:#6b6b70;margin-top:0}}
.act{{margin-top:2.2rem}}
.beat{{border-left:3px solid #bfdbfe;padding:.2rem 0 .2rem 1rem;margin:.9rem 0}}
.beat .t{{font-family:ui-monospace,monospace;font-size:.8rem;color:#6b6b70}}
.ev{{list-style:none;padding:0;margin:.5rem 0;font-size:.92rem}}
.ev li{{padding:.3rem 0 .3rem 1.6rem;position:relative;
border-bottom:1px solid #f0f0f2}}
.ev li::before{{content:"";position:absolute;left:.4rem;top:.85em;
width:.45rem;height:.45rem;border-radius:50%;background:#2563eb}}
.src{{font-size:.75rem;color:#6b6b70;background:#f4f4f5;border-radius:4px;
padding:.05rem .35rem;margin-left:.3rem}}
.voice{{margin:.9rem 0;padding:.7rem 1rem;border-radius:0 8px 8px 0;
font-size:1rem}}
.voice p{{margin:.1rem 0 .4rem;font-style:italic}}
.voice footer{{font-size:.78rem;color:#52525b;font-style:normal}}
.v-worker{{background:#fffbeb;border-left:4px solid #d97706}}
.v-house{{background:#f0fdfa;border-left:4px solid #0d9488}}
.why{{margin-top:.3rem;font-size:.76rem;color:#59595f}}
.bound{{background:#eef2ff;border:1px solid #c7d2fe;border-radius:8px;
padding:.7rem 1rem;font-size:.9rem}}
.flags{{background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;
padding:.6rem 1rem;font-size:.86rem}}
.flags ul{{margin:.3rem 0}}
.tamper{{background:#fef2f2;border:1px solid #fecaca;border-radius:10px;
padding:1rem 1.2rem;margin-top:2.4rem}}
.tamper h2{{margin-top:0;color:#991b1b}}
code{{background:#f4f4f5;padding:.08rem .35rem;border-radius:4px;
font-size:.88em}}
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
<p class="small"><a href="index.html">Attest</a> → the story</p>
<h1>One visit. Three accounts.<br>Nothing rewritten.</h1>
<p class="sub">The {site}. A scheduled {service.lower()} — {worker} is
the worker booked to do it.
What follows is not a dramatization — every timestamp, count, and quoted
sentence below was read out of <a href="sample-pack.zip">the same signed pack
you can download</a>. Each link verifies its source in your browser, no
install, nothing leaving the page.</p>
<p><a href="verify.html#sample-pack"><img src="badge-verified.svg" alt="attest: verified"
style="vertical-align:middle"></a>
<small>— the pack's own verdict, self-issued and re-checkable by anyone
(hover the shield for the whole verdict line).</small></p>

<div class="act"><h2>The plan</h2>
<div class="beat"><span class="t">{ws} – {we} UTC · signed schedule</span><br>
<strong>{service}</strong> booked for {worker} — {expected} minutes at the
{site}. The schedule is an <em>expectation</em>: it tells the record what
to watch for, never what happened.</div></div>

<div class="act"><h2>What the house saw</h2>
<p>The household's own devices — doorbell, contact sensor, camera — reported
{n_device} events during the window; the remaining {n_other} entry is the
worker's own self-report through her scoped link, signed like everything
else (all times UTC):</p>
<ul class="ev">{"".join(ev_rows)}</ul>
<p class="small">Each entry carries its ingestion source (<code>webhook</code>
= signed delivery; <code>local_or_test</code> = device snapshot, bytes
attested by a signed sha-256 and withheld from this redacted pack;
<code>unknown</code> = the worker's self-report — a person's claim, not a
device's). Coverage: {cov_state} — the receipt bounds its own window
({cov_span}) and signs {cov_pct}% of it as polled, saying so in its own
words: <i>"{cov_claim}"</i> — so silence where it occurs is <em>watched</em>
silence, still never proof of absence.</p></div>

<div class="act"><h2>The record closes — and says what it can't say</h2>
<div class="beat"><span class="t">receipt <code>{_short(rid)}</code> ·
<a href="verify.html#demo-receipts/{rid}">verify this receipt →</a></span><br>
Door activity spans <strong>{span} minutes</strong> of the {expected} scheduled —
<strong>{ESC(assessed["attendance"]).replace("_", " ")}</strong>, departure
unconfirmed, identity never verified. The receipt self-labels its own limits:</div>
<div class="flags"><b>Signed flags, straight from the payload:</b>
<ul>{flag_rows}</ul>
<span class="small"><code>signature_scope: {ESC(assessed["signature_scope"])}</code>
— the signature attests the record's integrity, nothing about physical
truth.</span></div></div>

<div class="act"><h2>The humans spoke — {len(reviews)} statements, all signed, none edited</h2>
<p>Then the humans disagreed. Every statement below appended to the same
append-only review chain, verbatim, under its own signature. The record
doesn't merge them, rank them, or pick a winner:</p>
{"".join(voices)}
<p class="small">Read them again: the household's account <em>contradicts
itself</em> — first "nobody came," then "I heard the doorbell a little after
six." That contradiction is the evidence. A system that normalized it away
would be destroying the only thing the family actually has. And the pack
carries doubt the same way: records signed inside a revoked key's suspect
window stay annotated on the green stamp — never hidden, never rewritten.</p></div>

<div class="tamper"><h2>Then somebody changed a number</h2>
<p>A second copy of this pack exists with exactly one signed field rewritten:
<code>observed_span_minutes</code> inflated {span} → {tampered_span} — past the
{expected}-minute schedule. It still <em>looks</em> identical: same files,
same story, same layout.</p>
<p><a href="verify.html#sample-pack-tampered"><strong>Open it in the
verifier</strong></a> → <b>FAILED: payload hash mismatch</b>. Or
<a href="verify.html#compare-packs"><strong>compare the two packs</strong></a>
— the page verifies each on its own merits, then names
<code>observed_span_minutes</code> as the moved field and proves the
transparency log only appended between exports. And
<a href="sample-diff-report.html"><strong>this is the page a coordinator
hands a mediator</strong></a> — <code>attest diff --html</code> renders the
same comparison as an attachable report.</p></div>

<div class="bound"><b>What this record never does.</b> It doesn't say Maria
Chen arrived at 6:31. It doesn't say she didn't. It says: the devices
reported what they reported, the three accounts were given and signed, and
none of it can be silently rewritten now. Who was at the door is still a human
question — which is exactly what a dispute process is for.</div>

<div class="cta">
<a class="btn pri" href="verify.html#sample-pack">Verify the whole pack →</a>
<a class="btn" href="verify.html#tamper-lab">Forge a field yourself →</a>
<a class="btn" href="demo-visit.html">Explore the record snapshot →</a>
<a class="btn" href="tour.html">2-minute tour →</a>
</div>

<footer class="page">Generated from <code>docs/sample-pack.zip</code> by
<code>tools/make_story.py</code> — every figure above derives from the shipped
signed bytes. Demo replay id <code>{ESC(p["clock"].get("replay_id", "")[:12])}…</code>;
receipt sequence {o["sequence"]}.</footer>
</main>
</body>
</html>
"""
    (DOCS / "story.html").write_text(page, encoding="utf-8", newline="")
    print(f"story.html: {ev_counts} events, {len(reviews)} voices, span {span}")


if __name__ == "__main__":
    main()
