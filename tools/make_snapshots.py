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

# Links that resolve to a shipped static sibling instead of going inert.
SIBLING = [
    (f'href="/visits/{CONTESTED}/household?lang=es"', 'href="demo-household-es.html"'),
    (f'href="/visits/{CONTESTED}/household"', 'href="demo-household.html"'),
    (f'href="/visits/{CONTESTED}/brief"', 'href="demo-visit-brief.html"'),
    (f'href="/visits/{CONTESTED}"', 'href="demo-visit.html"'),
    ('href="/receipts.json"', 'href="demo-receipts.json"'),
    ('href="/verify-pack"', 'href="verify.html"'),
    ('href="/verify"', 'href="verify.html"'),
    ('href="/integrity"', 'href="demo-integrity.html"'),
    ('href="/about"', 'href="index.html"'),
    ('href="/"', 'href="demo-dashboard.html"'),
]


def _dead_anchor(match: re.Match[str]) -> str:
    """<a … href="/live/route" …> → <a … data-dead="/live/route" title="…" …>.

    href can sit after class/download/etc., so the whole tag is matched and
    the href located inside it — first-attribute assumptions miss real markup.
    """
    tag = match.group(0)
    m = re.search(r'(?<![-\w])href="(/[^"#]*)"', tag)
    if not m:
        return tag
    path = m.group(1)
    body = tag.replace(m.group(0), "", 1)
    tm = re.search(r'title="([^"]*)"', body)
    tip = f"{INERT} — {tm.group(1)}" if tm else INERT
    if tm:
        body = body.replace(tm.group(0), "", 1)
    return body[:-1] + f' data-dead="{path}" title="{tip}">'


BANNER = (
    '<div style="background:#f9edd4;border-bottom:1px solid #d9a83c;color:#6b4d0f;'
    'font:13px/1.5 system-ui,sans-serif;padding:8px 16px;text-align:center">'
    'Snapshot of the live <code>attest demo</code> product — served from a local '
    'Ring emulator. Run <code>attest demo</code> for the real thing; '
    '<a href="index.html" style="color:#6b4d0f">back to the demo page</a>.</div>'
)


def snapshot(
    html: str,
    *,
    page: str,
    dashboard: bool = False,
    token: str | None = None,
) -> str:
    # Scoped tokens are real grants in the local demo store — commit a stable
    # placeholder instead so pages are deterministic and no live token is
    # published (the grants are useless outside this machine regardless).
    if token:
        html = html.replace(token, "scoped-demo-link")
    # Media bytes ship as docs/demo-media/<role>.png — the live route names
    # carry a content digest the snapshot strips to a stable filename.
    html = re.sub(
        r'src="/visits/[^"/]+/media/([^"/]+)"', r'src="demo-media/\1"', html
    )
    html = re.sub(r'src="/family/[^"/]+/media/([^"/]+)"', r'src="demo-media/\1"', html)
    html = re.sub(r'src="/media/([^"/]+)"', r'src="demo-media/\1"', html)
    html = re.sub(
        r'demo-media/([A-Za-z_]+)\.[0-9a-f]{8,}\.png', r"demo-media/\1.png", html
    )
    # Language toggle between the page's own two snapshots — each scoped
    # surface pairs with its sibling, not the coordinator's household pages.
    lang_pair = {
        "demo-family": ("demo-family.html", "demo-family-es.html"),
        "demo-worker": ("demo-worker.html", "demo-worker-es.html"),
    }
    en, es = next(
        (pair for stem, pair in lang_pair.items() if page.startswith(stem)),
        ("demo-household.html", "demo-household-es.html"),
    )
    html = html.replace('href="?lang=es"', f'href="{es}"')
    html = html.replace('href="?lang=en"', f'href="{en}"')
    for old, new in SIBLING:
        html = html.replace(old, new)
    # Per-receipt downloads resolve to the shipped corpus, not a dead route.
    html = re.sub(
        r'href="/receipts/([A-Za-z0-9_]+)\.json"', r'href="demo-receipts/\1.json"', html
    )
    # onclick row navigation to the contested visit lands on the snapshot;
    # navigation to any other live route is stripped (the row stays, the
    # keyboard handler keeps its preventDefault but goes nowhere).
    html = html.replace(f"location.href='/visits/{CONTESTED}'", "location.href='demo-visit.html'")
    html = html.replace(f'location.href="/visits/{CONTESTED}"', 'location.href="demo-visit.html"')
    html = re.sub(r' onclick="location\.href=\'/[^\']*\'"', "", html)
    html = re.sub(r"location\.href='/[^']*'", "", html)
    # Every other live route becomes inert, with the disclosure title.
    html = re.sub(r"<a\b[^>]*>", _dead_anchor, html)
    # The dashboard's live-runtime JS needs snapshot treatment first so the
    # generic disabled pass below leaves these custom titles alone:
    if dashboard:
        # auto-reload fetches identical bytes on a static host — never fire it.
        html = html.replace("setInterval(() => {", "if (false) setInterval(() => {")
        html = re.sub(
            r'<button id="refresh-toggle"([^>]*)>',
            rf'<button id="refresh-toggle"\1 disabled title="static snapshot — nothing reloads here">',
            html,
        )
        # The agent-brief button POSTs to /api/triage — inert on Pages like
        # every other live control.
        html = re.sub(
            r'<button id="triage-run"([^>]*)>',
            rf'<button id="triage-run"\1 disabled title="{INERT}">',
            html,
        )
    # Form controls can never submit on a static host — disable them all, and
    # strip the POST targets so nothing tries to hit a live route.
    html = re.sub(r' action="[^"]*"', ' action=""', html)
    def _disable(m: re.Match[str]) -> str:
        tag, attrs = m.group(1), m.group(2)
        if "title=" in attrs:
            return f"<{tag}{attrs} disabled>"
        extra = f' disabled title="{INERT}">' if tag == "button" else " disabled>"
        return f"<{tag}{attrs}{extra}"

    html = re.sub(
        r"<(input|select|textarea|button)(?![^>]*disabled)([^>]*)>", _disable, html
    )
    html = html.replace("<body>", "<body>" + BANNER, 1)
    return html


def main() -> int:
    env = dict(os.environ, ATTEST_DATA_DIR=str(DATA), ATTEST_REPLAY_MODE="true")
    env.setdefault("ATTEST_ADMIN_TOKEN", "snapshot-run-admin-token-32chars!!")
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

        auth = "Basic " + base64.b64encode(
            f"admin:{env['ATTEST_ADMIN_TOKEN']}".encode()
        ).decode()
        pages = {**PAGES, **JSON_PAGES}
        tokens: dict[str, str] = {}
        try:
            extra, tokens = _scoped_pages(auth)
            pages.update(extra)
        except Exception as e:
            print(f"scoped-link mint skipped: {e}", file=sys.stderr)
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
