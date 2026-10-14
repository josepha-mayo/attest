"""Regenerate the static demo snapshots in docs/ from the pack-demo runtime.

Serves the demo store on a loopback port, fetches the pages a judge can
browse without installing anything, rewrites live-only routes to inert
``data-dead`` markers (or to the static sibling where one exists), and
writes docs/demo-*.html + docs/demo-integrity.json.

    ATTEST_ADMIN_TOKEN=... python tools/make_snapshots.py

Run from the repo root. Requires the demo store at data-pack-demo/.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
DATA = ROOT / "data-pack-demo"
PORT = 8931
BASE = f"http://127.0.0.1:{PORT}"

CONTESTED = "vis_70e42116a4cf"  # the trilateral dispute the tour walks through

PAGES = {
    "/": "demo-dashboard.html",
    # The site page carries the day-strip visual — per-day coverage lines
    # with interruption marks and the live-view session band. It is the
    # clearest single-picture answer to "what does this actually record?"
    "/sites/site_a55d249ad6dd": "demo-site.html",
    f"/visits/{CONTESTED}": "demo-visit.html",
    f"/visits/{CONTESTED}/brief": "demo-visit-brief.html",
    f"/visits/{CONTESTED}/household": "demo-household.html",
    f"/visits/{CONTESTED}/household?lang=es": "demo-household-es.html",
    "/integrity": "demo-integrity.html",
}
JSON_PAGES = {"/integrity.json": "demo-integrity.json"}


def _scoped_pages(auth: str) -> dict[str, str]:
    """Mint a fresh family link + worker review link on the contested visit via
    the running server's admin API (it is the store's single writer — minting
    in-process would race it). Tokens live only in the local demo store; the
    committed HTML keeps the scoped URLs as live-app realism."""
    minted: dict[str, str] = {}
    tokens: dict[str, str] = {}
    for endpoint, names in (
        ("family-link", ["demo-family.html", "demo-family-es.html"]),
        ("review-link", ["demo-worker.html", "demo-worker-es.html"]),
    ):
        req = urllib.request.Request(
            f"{BASE}/api/visits/{CONTESTED}/{endpoint}",
            method="POST",
            headers={"Authorization": auth},
        )
        path = json.loads(urllib.request.urlopen(req, timeout=10).read())["path"]
        minted[path] = names[0]
        tokens[names[0]] = path.rsplit("/", 1)[-1]
        if len(names) > 1:
            minted[f"{path}?lang=es"] = names[1]
            tokens[names[1]] = tokens[names[0]]
    return minted, tokens


INERT = "live deployment only — inert in this snapshot"
INERT_ES = "solo en un despliegue en vivo — inerte en esta captura"
FORM_NOTE = "This form is inert in the snapshot — on a live deployment it posts a signed entry."
FORM_NOTE_ES = (
    "Este formulario está inerte en la captura — en un despliegue en vivo publica una entrada firmada."
)
PRINT_TIP = "print — works in this snapshot"
PRINT_TIP_ES = "imprimir — funciona en esta captura"

# A quoted attribute value — either quote style. A double-quoted value may
# hold single quotes (onclick="…key==='Enter'…") and vice versa; matching
# [^"']* inside would truncate mid-attribute and leave markup garbage.
_ATTRV = r"(?:\"[^\"]*\"|'[^']*')"

# Links that resolve to a shipped static sibling instead of going inert.
SIBLING = [
    # The shipped sample export IS this demo store's case pack (media redacted,
    # signatures intact) — pack buttons get the real artifact, not a dead link.
    ('href="/sites/site_a55d249ad6dd/pack.zip?redact_media=1"', 'href="sample-pack.zip"'),
    ('href="/sites/site_a55d249ad6dd/pack.zip"', 'href="sample-pack.zip"'),
    (f'href="/visits/{CONTESTED}/pack.zip?redact_media=1"', 'href="sample-pack.zip"'),
    (f'href="/visits/{CONTESTED}/pack.zip"', 'href="sample-pack.zip"'),
    (f'href="/visits/{CONTESTED}/household?lang=es"', 'href="demo-household-es.html"'),
    (f'href="/visits/{CONTESTED}/household"', 'href="demo-household.html"'),
    (f'href="/visits/{CONTESTED}/brief"', 'href="demo-visit-brief.html"'),
    (f'href="/visits/{CONTESTED}"', 'href="demo-visit.html"'),
    ('href="/sites/site_a55d249ad6dd"', 'href="demo-site.html"'),
    ('href="/receipts.json"', 'href="demo-receipts.json"'),
    ('href="/verify-pack"', 'href="verify.html"'),
    # /verify is the journal-receipt route — its static equivalent is the
    # receipts-index deep link, not the bare pack verifier.
    ('href="/verify"', 'href="verify.html#demo-receipts"'),
    ('href="/integrity.json"', 'href="demo-integrity.json"'),
    ('href="/integrity"', 'href="demo-integrity.html"'),
    ('href="/about"', 'href="index.html"'),
    ('href="/"', 'href="demo-dashboard.html"'),
]


# An attribute value may legitimately contain ">" — plain [^>]* truncates the
# tag early. This tail treats quoted spans as opaque.
TAG_TAIL = r"(?:[^>\"']|\"[^\"]*\"|'[^']*')*"


def _dead_anchor(match: re.Match[str], inert: str) -> str:
    """<a … href="/live/route" …> → <a … data-dead="/live/route" title="…" …>.

    href can sit after class/download/etc., so the whole tag is matched and
    the href located inside it — first-attribute assumptions miss real markup.
    """
    tag = match.group(0)
    m = re.search(r"(?<![-\w])href=[\"'](/[^\"'#]*)[\"']", tag)
    if not m:
        return tag
    path = m.group(1)
    body = tag.replace(m.group(0), "", 1)
    tm = re.search(r'title="([^"]*)"', body)
    tip = f"{inert} — {tm.group(1)}" if tm else inert
    if tm:
        body = body.replace(tm.group(0), "", 1)
    # A dead anchor's click handlers are dead code — strip them so the
    # snapshot carries no live JS at all.
    body = re.sub(r"\sonclick=" + _ATTRV, "", body)
    return body[:-1] + f' data-dead="{path}" title="{tip}">'


SNAP_CSS = (
    "<style>"
    "a[data-dead]{opacity:.55;cursor:not-allowed;text-decoration:line-through}"
    "[disabled]{cursor:not-allowed}"
    ".snap-note{font-size:12px;color:var(--muted,#5c6b7a);margin:4px 0 8px}"
    "@media print{.snap-banner{display:none}}"
    "</style>"
)

BANNER = (
    '<div class="snap-banner" style="background:#f9edd4;border-bottom:1px solid #d9a83c;color:#6b4d0f;'
    'font:13px/1.5 system-ui,sans-serif;padding:8px 16px;text-align:center">'
    "Snapshot of the live <code>attest demo</code> product — served from a local "
    "Ring emulator. Struck-through links and disabled controls are live-app "
    "routes. Run <code>attest demo</code> for the real thing; "
    '<a href="index.html" style="color:#6b4d0f">back to the demo page</a>.</div>'
)

BANNER_ES = (
    '<div class="snap-banner" style="background:#f9edd4;border-bottom:1px solid #d9a83c;color:#6b4d0f;'
    'font:13px/1.5 system-ui,sans-serif;padding:8px 16px;text-align:center">'
    "Captura estática del producto <code>attest demo</code> en vivo — servida "
    "desde un emulador Ring local. Los enlaces tachados y los controles "
    "deshabilitados son rutas de la aplicación en vivo. Ejecuta "
    '<code>attest demo</code> para la versión real; <a href="index.html" '
    'style="color:#6b4d0f">volver a la página de demostración</a>.</div>'
)


def snapshot(
    html: str,
    *,
    page: str,
    dashboard: bool = False,
    token: str | None = None,
) -> str:
    # The -es pages get Spanish disclosure chrome — an English "why is this
    # dead" tooltip on a Spanish page fails WCAG's language-of-parts rule.
    es = page.endswith("-es.html")
    inert = INERT_ES if es else INERT
    form_note = FORM_NOTE_ES if es else FORM_NOTE
    print_tip = PRINT_TIP_ES if es else PRINT_TIP
    # Scoped tokens are real grants in the local demo store — commit a stable
    # placeholder instead so pages are deterministic and no live token is
    # published (the grants are useless outside this machine regardless).
    if token:
        html = html.replace(token, "scoped-demo-link")
    # Media bytes ship as docs/demo-media/<role>.png — the live route names
    # carry a content digest the snapshot strips to a stable filename.
    html = re.sub(r'src="/visits/[^"/]+/media/([^"/]+)"', r'src="demo-media/\1"', html)
    html = re.sub(r'src="/family/[^"/]+/media/([^"/]+)"', r'src="demo-media/\1"', html)
    html = re.sub(r'src="/media/([^"/]+)"', r'src="demo-media/\1"', html)
    html = re.sub(r"demo-media/([A-Za-z_]+)\.[0-9a-f]{8,}\.png", r"demo-media/\1.png", html)
    # Language toggle between the page's own two snapshots — each scoped
    # surface pairs with its sibling, not the coordinator's household pages.
    lang_pair = {
        "demo-family": ("demo-family.html", "demo-family-es.html"),
        "demo-worker": ("demo-worker.html", "demo-worker-es.html"),
    }
    en_pair, es_pair = next(
        (pair for stem, pair in lang_pair.items() if page.startswith(stem)),
        ("demo-household.html", "demo-household-es.html"),
    )
    html = html.replace('href="?lang=es"', f'href="{es_pair}"')
    html = html.replace('href="?lang=en"', f'href="{en_pair}"')
    for old, new in SIBLING:
        html = html.replace(old, new)
    # Per-receipt downloads resolve to the shipped corpus, not a dead route.
    html = re.sub(r'href="/receipts/([A-Za-z0-9_]+)\.json"', r'href="demo-receipts/\1.json"', html)
    # onclick row navigation to the contested visit lands on the snapshot;
    # navigation to any other live route is stripped (the row stays, the
    # keyboard handler keeps its preventDefault but goes nowhere).
    html = html.replace(f"location.href='/visits/{CONTESTED}'", "location.href='demo-visit.html'")
    html = html.replace(f'location.href="/visits/{CONTESTED}"', 'location.href="demo-visit.html"')

    # Rows that navigated on click must lose every link affordance once the
    # handler is gone — a pointer-cursor row that does nothing reads as
    # broken, not curated. Contested-visit rows already point at the sibling.
    def _dead_row(m: re.Match[str]) -> str:
        attrs = m.group(1) + m.group(3)
        body = m.group(4)

        def _unclass(cm: re.Match[str]) -> str:
            rest = " ".join(t for t in cm.group(1).split() if t != "link")
            return f' class="{rest}"' if rest else ""

        attrs = re.sub(r"\sclass=[\"']([^\"']*)[\"']", _unclass, attrs)
        attrs = re.sub(r"\stabindex=[\"']0[\"']", "", attrs)
        attrs = re.sub(r"\srole=[\"']link[\"']", "", attrs)
        # Attribute values may nest the other quote style — onkeydown bodies
        # carry 'Enter'/' ' literals inside double quotes.
        attrs = re.sub(r"\sonkeydown=" + _ATTRV, "", attrs)
        tm = re.search(r'title="([^"]*)"', attrs)
        tip = f"{inert} — {tm.group(1)}" if tm else inert
        if tm:
            attrs = attrs.replace(tm.group(0), "", 1)
        # Stripped attributes leave whitespace-only line fragments behind —
        # collapse them so the emitted <tr> isn't trailing-whitespace noise.
        attrs = re.sub(r"[ \t]*\n[ \t]*", " ", attrs)
        # The row goes nowhere now — a "Open record →" cell would promise a
        # click that does nothing.
        body = re.sub(
            r"<td[^>]*>(?:(?!</td>).)*Open record(?:(?!</td>).)*</td>",
            "<td></td>",
            body,
            flags=re.S,
        )
        return f'<tr{attrs} data-dead="{m.group(2)}" title="{tip}">{body}</tr>'

    html = re.sub(
        r"<tr\b((?:[^>\"']|\"[^\"]*\"|'[^']*')*?)onclick=[\"'](?:[^\"']*?)location\.href\s*=\s*['\"](/[^'\"]*)['\"](?:[^\"']*?)[\"']((?:[^>\"']|\"[^\"]*\"|'[^']*')*?)>((?:(?!</tr>).)*?)</tr>",
        _dead_row,
        html,
        flags=re.S,
    )
    html = re.sub(
        r"""\sonclick=(?:"location\.href\s*=\s*['"]/[^'"]*['"]"|'location\.href\s*=\s*['"]/[^'"]*['"]')""",
        "",
        html,
    )
    html = re.sub(r"location\.href\s*=\s*['\"]/[^'\"]*['\"]", "", html)
    # Every other live route becomes inert, with the disclosure title.
    html = re.sub(r"<a\b" + TAG_TAIL + r">", lambda m: _dead_anchor(m, inert), html)
    # The dashboard's live-runtime JS needs snapshot treatment first so the
    # generic disabled pass below leaves these custom titles alone:
    if dashboard:
        # auto-reload fetches identical bytes on a static host — never fire it.
        html = re.sub(r"setInterval\(\(\)\s*=>\s*{", "if (false) setInterval(() => {", html)
        html = re.sub(
            r'<button id="refresh-toggle"([^>]*)>',
            r'<button id="refresh-toggle"\1 disabled title="' + inert + ' — nothing reloads here">',
            html,
        )
        # The agent-brief button POSTs to /api/triage — inert on Pages like
        # every other live control.
        html = re.sub(
            r'<button id="triage-run"([^>]*)>',
            r'<button id="triage-run"\1 disabled title="' + inert + '">',
            html,
        )
    # Form targets pointing at live routes can't reach anything on a static
    # host — strip the attribute so no judge-facing markup advertises a live
    # submit. The scoped-demo-link placeholder is renamed to data-action so
    # the token-redaction mechanism stays visible without looking submittable.
    # (A non-route action like "#" is inert either way and stays.)
    html = re.sub(r'\saction=(["\'])(?!/(?:family|review)/scoped-demo-link)[^"\']*\1', "", html)
    html = re.sub(
        r'\saction=(["\'])((?:/(?:family|review)/scoped-demo-link)[^"\']*)\1',
        r' data-action="\2" title="' + inert + '"',
        html,
    )
    # The form element itself still invites a submission attempt — it gets
    # the same disclosure as its disabled controls. title= is invisible to
    # keyboards and touch, so a short visible note goes in too.
    html = re.sub(
        r"<form\b(?![^>]*\btitle=)(" + TAG_TAIL + r")>",
        r'<form\1 title="' + inert + '">',
        html,
    )
    html = re.sub(
        r"(<form\b" + TAG_TAIL + r">)",
        r"\1<p class='snap-note'>" + form_note + "</p>",
        html,
    )

    def _disable(m: re.Match[str]) -> str:
        tag, attrs = m.group(1), m.group(2)
        # A control whose ONLY handler is window.print() genuinely works on a
        # static host — leave it live, but title it honestly so the one
        # armed control in the snapshot is self-describing. ("Contains
        # window.print" would also exempt a handler that prints then POSTs.)
        oc = re.search(r'\sonclick=["\']([^"\']*)["\']', m.group(0))
        if oc and oc.group(1).strip().rstrip(";") in ("window.print()", "print()"):
            if "title=" not in m.group(0):
                return m.group(0)[:-1] + ' title="' + print_tip + '">'
            return m.group(0)
        # "Already disabled" is checked on the attribute list with quoted
        # values blanked out — a title or aria-label containing the word
        # "disabled" must not make a live control look pre-disabled.
        bare = re.sub(r'"[^"]*"|\'[^\']*\'', '""', attrs)
        if re.search(r"\sdisabled([\s>=/]|$)", bare):
            return m.group(0)
        # an existing functional title gets the disclosure merged in, like
        # _dead_anchor does — a bare disabled control with a live-looking
        # tooltip reads as a bug, not a snapshot.
        tm = re.search(r'title="([^"]*)"', attrs)
        if tm:
            attrs = attrs.replace(tm.group(0), f'title="{inert} — {tm.group(1)}"', 1)
            return f"<{tag}{attrs} disabled>"
        return f'<{tag}{attrs} disabled title="{inert}">'

    html = re.sub(
        r"<(input|select|textarea|button)(" + TAG_TAIL + r")>",
        _disable,
        html,
    )
    # Dead code can't run: script blocks that fetch live routes or navigate
    # are wrapped in if (false) — the buttons they listen to are disabled
    # already, this is belt-and-braces so a source-read finds nothing armed.
    html = re.sub(
        r"<script>((?:(?!</script>).)*?(?:fetch\(|location\.href)(?:(?!</script>).)*?)</script>",
        r"<script>if (false) {\1}</script>",
        html,
        flags=re.S,
    )
    m = re.search(r"<body\b" + TAG_TAIL + r">", html)
    assert m, "snapshot page has no <body> tag — disclosure banner was not injected"
    html = html[: m.end()] + (BANNER_ES if es else BANNER) + html[m.end() :]
    h = re.search(r"</head\s*>", html)
    assert h, "snapshot page has no </head> tag — dead-link styling was not injected"
    html = html[: h.start()] + SNAP_CSS + html[h.start() :]
    return html


def main() -> int:
    env = dict(os.environ, ATTEST_DATA_DIR=str(DATA), ATTEST_REPLAY_MODE="true")
    env.setdefault("ATTEST_ADMIN_TOKEN", "snapshot-run-admin-token-32chars!!")
    # Arm webhook intake so /integrity reports the deployment's real posture —
    # the demo store was populated through the signed-webhook path, and an
    # "intake: OFF" banner on the flagship self-audit page is a lie by omission.
    env.setdefault("ATTEST_RING_WEBHOOK_KEY", "snapshot-demo-webhook-key-32chars!!")
    exe = ROOT / ".venv" / "Scripts" / "attest.exe"
    proc = subprocess.Popen(
        [str(exe), "serve", "--port", str(PORT)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"{BASE}/healthz", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            print("server did not come up", file=sys.stderr)
            return 1
        import base64

        auth = "Basic " + base64.b64encode(f"admin:{env['ATTEST_ADMIN_TOKEN']}".encode()).decode()
        pages = {**PAGES, **JSON_PAGES}
        tokens: dict[str, str] = {}
        try:
            extra, tokens = _scoped_pages(auth)
        except Exception as e:
            # A silent skip would ship four missing pages looking like success.
            print(f"scoped-link mint FAILED: {e}", file=sys.stderr)
            return 1
        pages.update(extra)
        for route, name in pages.items():
            req = urllib.request.Request(BASE + route, headers={"Authorization": auth})
            html = urllib.request.urlopen(req, timeout=10).read().decode("utf-8")
            if name.endswith(".html"):
                html = snapshot(
                    html,
                    page=name,
                    dashboard=name == "demo-dashboard.html",
                    token=tokens.get(name),
                )
            (DOCS / name).write_bytes(html.encode("utf-8"))
            print(f"{name} <- {route} ({len(html)} chars)")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    return 0


if __name__ == "__main__":
    sys.exit(main())
