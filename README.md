# Attest

[![CI](https://github.com/josepha-mayo/attest/actions/workflows/ci.yml/badge.svg)](https://github.com/josepha-mayo/attest/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Tamper-evident visit records for home services — what the Ring devices observed, what the worker reported, what a human concluded. Signed, reviewable, verifiable offline.**

A caregiver says she was there Tuesday. The family says nobody came. Today that dispute is "he said / she said." Attest replaces it with a signed record that keeps the evidence apart from the conclusions: door-camera and contact-sensor observations, how much of the window the pipeline actually watched, the worker's own account, and the coordinator's review — each linkable, each checkable without trusting Attest itself.

Built for the Amazon Developer Hackathon (Ring track; AWS Builder + Open Source mini-challenges). A working prototype with honest boundaries — not an "electronic visit verification" system under 42 U.S.C. §1396b(l)(5)(A), and never a claim of attendance. The proposed customer is a household or service coordinator reviewing a scheduled visit alongside the worker's own account.

Why this problem is real: visit-verification records today are *editable*. New York's comptroller found **$14.5B paid against 82M personal-care visits with no matching EVV record** — and the EVV entries that did exist could be manually adjusted invisibly to the state (Ohio's auditor found 34% of entries manually adjusted). Attest's answer: an append-only signed chain where every party's account is preserved verbatim and every edit attempt is detectable. And where incumbent EVV tracks *the worker's phone* (GPS at check-in — spoofable, and the documented "ankle monitor" privacy backlash), Attest anchors observation to *the household's own premises* — a camera at that address, not a location claim — plus volunteered statements. Private home services (cleaners, aides, dog walkers) have no EVV mandate and no shared record at all; that's the gap.

**What makes it different.** Attendance tools answer with a verdict; Attest ships evidence you don't have to trust. The export pack **verifies itself** — open it in a browser or a stock Python install and every record re-checks, with no Attest dependency and no trust in the issuer. Silence is signed too: receipts attest *how much of the window was watched*, so "we checked and saw nothing" is provably different from "we weren't watching." The dispute loop is bilateral — the worker's words land in the same signed chain the coordinator concludes on, and appends never rewrite. And the project names exactly what it cannot prove (identity, attendance, completeness of a hidden tail) in the record boundary, the threat model, and a live tamper battery that fails against itself.

**See it in 30 seconds — no install:** [verify a real signed pack in your browser](https://josepha-mayo.github.io/attest/verify.html) (one-click bundled sample, or drop any exported pack/receipt — the pure-JS verifier does Ed25519 + hash checks locally), or check [our signed `verify-live` sweep against the real Ring API](https://josepha-mayo.github.io/attest/live-sweep-receipt.json). Then `attest demo` — one command boots emulator + server + an eight-day story with a printed dashboard URL.

## What the record means

- A schedule records an expectation, not the identity of a person at the camera.
- Ring motion, button, and contact-sensor events are observations. They do not establish direction of travel, identity, continuous presence, or work performed.
- A check-in is a self-report made through a visit-specific link. It is not independent identity or location verification.
- The observed interval measures time between received observations, not time worked.
- A door cycle followed by motion is only a candidate departure. Closing a record sends it for review; it does not certify departure.
- No matching observations means attendance is unknown, not that the worker failed to show up. A missing event can reflect connectivity, consent, recording, or ingestion gaps.
- Ed25519 signatures and a hash chain protect record integrity under an externally trusted issuer key. They do not prove the underlying observations or conclusions are true. A chain alone cannot detect deletion of its entire tail without an external checkpoint.

Model limits worth stating plainly: **one active visit per site** — two overlapping workers at one property share a visit record (the prototype matches arrivals to the open visit, not per-worker). Coordinator statements are signed under the deployment's single admin identity ("Workspace coordinator"), not yet a multi-user identity system. Both are named in the record boundary text; neither is hidden.

The full trust model — every attack path and its detection — is in [THREATMODEL.md](THREATMODEL.md). `attest attack-demo` executes the tamper battery live. Every piece of real Ring API friction hit during the build (token lifetime, the undocumented media redirect, localhost-unverifiable webhooks, missing event types) is documented in [FRICTIONLOG.md](FRICTIONLOG.md) — the product itself is built on honest records, so the build log holds to the same standard.

## How it fits together

```text
Ring Partner API                    ATTEST                              Human review
────────────────                    ──────                              ────────────

webhooks ────▶ durable inbox ──▶ HMAC verify ──▶ dedupe + bind ──▶ visit engine
(camera, door,    (202 before                        │                │
 contact sensor,   processing)                       │                ├─ snapshots → sha256 into receipt
 lifecycle hooks)                                    │                ├─ Ring History corroboration
                                                   │                ├─ coverage: % watched + why the
history poller ────┘  (Ring-side record,            │                │   channel stopped (lifecycle
  labelled, never                                   │                │   events → journaled rows)
  conflated with webhooks)                          │                └─ close → Ed25519 receipt
                                                   │                     (schema-v2 payload, hash-chained)
                                                   │
worker link (24h, single-use, hashed) ──▶ statement ──▶ per-visit review chain ──▶ anchored to the
coordinator ──▶ statement / signed resolution ──────▶ same chain ──▶ original receipt hash
family link (7d, multi-use, hashed) ────▶ household account ───────▶ same chain
                                                                      (every voice kept verbatim,
                                                                       never edited, never merged)

attest anchor ──▶ signed checkpoint (journal head + chain head)
              ──▶ S3 custody · OpenTimestamps ──▶ "the record existed before this Bitcoin block"

pack.zip ──▶ signed manifest + per-visit bundles + site attestations + media
        ──▶ index.html / verify.html / verify_case.py / attest verify — checkable with no Attest install
```

The signing key itself can be wrapped under an AWS KMS CMK (`ATTEST_KMS_KEY_ID`) or — on Windows, with no AWS dependency — under the OS user's DPAPI master key (`ATTEST_KEY_CUSTODY=dpapi`, bound to user + machine; the two postures are mutually exclusive). Rotating it is a signed chain event (`attest rotate-key`): the retiring key signs a `key_rotation` receipt endorsing its successor — the ledger's pivot — so receipts on both sides verify under one pinned key and the successor countersigns consent via `key_adoption`. Packs carry the rotation links: a pinned pre-rotation key still verifies a post-rotation pack, and a key that merely *appears* in a pack never becomes trusted. Compromise response is the signed counterpart (`attest revoke-key` / `POST /api/admin/revoke-key`): the live issuer signs a `key_revocation` receipt declaring a retired key's signatures suspect after a chosen instant — nothing is erased and the chain still verifies, while every verifier (server, embedded Python, browser JS, Lambda) annotates how many records sit inside the suspect window. Only the in-effect key can revoke, so a compromised key can't smear its own successor. Summaries and the weekly triage brief run on Bedrock/Strands when reachable and label their fallback honestly when not.

## Implemented

- Ring Partner API client via the companion [ring-sandbox](https://github.com/josepha-mayo/ring-sandbox) project.
- HMAC-verified webhook intake persisted in a separate SQLite inbox before a `202` acknowledgement. A background worker verifies the signature again and processes events with account-to-site checks. Leases recover interrupted deliveries; failures back off and move to a failed state after five attempts. Intake is tested independently of slow visit transactions. Two independent replay defenses: `request_id` dedupe tombstones (never purged by default) plus a freshness window on the HMAC-covered `meta.time` — a captured delivery replayed past `ATTEST_WEBHOOK_MAX_AGE_S` (default 1h) is refused even if its tombstone is gone.
- Event History polling with human-motion and doorbell results merged in chronological order. History-derived observations are labelled as history, not authenticated webhook deliveries.
- One ingestion source is bound per site. Switching between history and webhooks is rejected pending reconciliation; their identifiers are not interchangeable and cross-source deduplication is not yet implemented.
- Atomic event processing, check-in consumption, and receipt issuance in SQLite. Failed processing rolls back the consumed marker and database changes. Out-of-order events are retained for review instead of rewriting an existing signed record.
- Observations matched to schedules without assigning the scheduled worker as the observed person's identity.
- Visit-scoped check-in grants: random tokens, only a hash persisted, 15-minute expiry, one use. Issuing a replacement invalidates the prior grant. Legacy worker-wide links no longer authenticate.
- Best-effort snapshots with the returned media timestamp, not a fabricated capture time. Missing media is flagged. History records for the interval are attached where available.
- Insert-only signed receipts. Schema v2 binds the receipt ID, visit ID, issuance timestamp, sequence, and previous hash into the signed payload.
- Authenticated dashboard, media, exports, and administration. Private responses are not cached. Cross-origin writes are rejected. URL access logging is disabled by the CLI to avoid logging check-in links.
- Bedrock Converse integration with explicit per-record provenance: actual summary source, model when used, and fallback reason. A configured provider is not evidence of a successful model invocation.
- Explicit local replay mode with a persistent, monotonic event clock. It refuses real Ring endpoints, existing non-replay data, clock rewinds, and future simulation times. Check-in event time and receipt closure use the replay clock; grant expiry, statement receipt, and signature issuance use real time and are recorded separately.
- Worker/coordinator review and correction flow. Each statement is signed in a per-visit review chain anchored to the original receipt hash. Original observations and original signatures remain unchanged. Worker review links are hashed, single-use, scoped to the signed scheduled worker and visit, and expire after 24 hours.
- Signed coordinator resolutions close the loop: `record_upheld` / `account_accepted` / `inconclusive` append the terminal conclusion after the worker's words without editing them — a newer worker statement re-opens the record. Resolved records leave the attention queue. Resolutions carry an optional coded `reason_code` from a fixed taxonomy (EVV-style coded exceptions — schedule difference, device fault, subscription lapse, participant unavailable, …), signed into the review payload with a `coordinator_stated_explanation_not_verified_cause` qualifier, suggested flag-first in the resolve form, exported as `resolution_*` CSV columns, and aggregated as a signed `resolution_reasons` histogram on period digests.
- Agency exports: `GET /sites/{id}/schedule.ics` publishes the schedule feed (calendar-subscribable; honest disclaimer — expectations, not attendance) and `GET /sites/{id}/visits.csv` exports the visit register pinned to receipt hashes (observed spans and check-in lag, `worker_self_reported` naming, formula-injection-safe cells). Every signed receipt carries a six-element statutory crosswalk (`service_type`, `service_date`, `individual`, `provider`, `service_times_observed`, `visit_times`) with per-element basis qualifiers like `scheduled_expectation` vs `camera_event_window` — a mapping, never a compliance claim.
- Consent revocation: disconnecting a Ring source tombstones the binding, signs a `source_disconnected` receipt naming what was unbound, and stops both ingestion and Event History polling. One-way; reconnecting is a new site.
- Authenticated setup screens for device discovery, site binding, worker creation, and schedule creation/cancellation. Device permissions and camera/contact capabilities are checked. Duplicate identifiers and ambiguous arrival windows are rejected. Used schedules cannot be rewritten through cancellation.
- Strands agent triage over Bedrock: the weekly brief reads the ledger through real tools (sites, records, integrity) and labels whether the agent or the deterministic fallback wrote it.

## 60-second demo

Clone Attest. From the Attest directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt -e ".[dev]"
.\.venv\Scripts\attest demo
```

(ring-sandbox resolves from PyPI — `pip install` pulls it automatically. To hack on the emulator alongside, clone it as a sibling directory and add `-e "../ring-sandbox[server]"` to the install line.)

One command boots the in-process Ring emulator, the Attest server, and an 8-day `--story` replay — an on-time visit, a late arrival, a mid-visit camera blackout, a mid-visit Ring plan lapse (the signed coverage attributes the silence to `subscription_deactivated`, a billing fact), a no-observation day (the schedule lapses with no events — never claimed as a no-show), a departure-unconfirmed visit, an unmatched observation, and a mid-window coordinator live view — then prints a ready Basic-auth dashboard URL. No Ring account, no credentials, no env vars; everything is clearly labeled simulated. `--data-dir DIR` keeps the runtime; `--days`/`--story` reshape it; `--open` launches the dashboard in a browser; `--lan` binds on all interfaces and prints LAN URLs so a phone on the same network can do the door-step QR scan for real; `--chaos` duplicates and jitters the emulator's webhook deliveries so dedupe and ordering are exercised live while the story stays deterministic. The dashboard's Integrity posture page self-audits the deployment — chain, journal, key custody, webhook intake posture — and `/integrity.json` serves the same audit machine-readable for scripted checks.

## Local development on Windows

From the Attest directory (ring-sandbox resolves from PyPI; to develop the emulator alongside, clone it as a sibling and add `-e "../ring-sandbox[server]"` to the install line):

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt -e ".[dev]"
$env:ATTEST_ADMIN_TOKEN = [System.Net.NetworkCredential]::new("", (Read-Host "Private admin password (32+ characters)" -AsSecureString)).Password
$env:ATTEST_REPLAY_MODE = "true"
$env:ATTEST_DATA_DIR = ".\data-replay-" + [guid]::NewGuid().ToString("N")
$env:ATTEST_RING_BASE_URL = "http://127.0.0.1:8787"
$env:ATTEST_RING_ACCESS_TOKEN = "sandbox-token"
# The server verifies inbound webhook HMACs with this key and `attest replay`
# signs simulated deliveries with it — both processes must see the same value.
$env:ATTEST_RING_WEBHOOK_KEY = [guid]::NewGuid().ToString("N")
$env:ATTEST_POLL_HISTORY_SECONDS = "0"
$env:ATTEST_SUMMARIZER = "template"
Start-Process .\.venv\Scripts\ring-sandbox.exe -ArgumentList "serve"
Start-Process .\.venv\Scripts\attest.exe -ArgumentList "serve"
.\.venv\Scripts\attest replay home_aide_visit --speed 60 --auto-checkin
```

Open `http://127.0.0.1:8000`. The browser's HTTP Basic login uses username `admin` and the private password configured above. The replay runner seeds one demo site/worker/schedule, advances the shared clock, and sends signed simulated events through the durable inbox. `--auto-checkin` deliberately simulates a worker self-report; omit it to use **Issue a check-in link** manually during replay. A visible banner and signed clock metadata identify the simulation.

Choose one setup path per fresh runtime: either let `attest replay` seed it, or use **Setup & schedules** to start the replay clock and register sites/workers/schedules yourself. The CLI will not overwrite an existing setup. For camera-only replay choose `camera_only_visit`; `no_show` tests the honest `no_observation` result. Use a fresh private runtime for each scripted scenario instead of deleting previous data.

The emulator is an independent local test tool, not Amazon's official Playground. Its default images are generated placeholders and its default MP4 is not playable video. Local tests are not proof that the full official Ring integration works.

For coordinated demos, use `attest replay`, not the standalone `ring-sandbox play` command. The runner waits for each persisted delivery before advancing time. Automatic idle sweeping is disabled in replay mode; the runner closes remaining observations explicitly for review. Link expiry is never frozen or extended by the replay clock.

Multi-day demos: `attest replay home_aide_visit --days 3 --no-show-day 1 --worker-review dispute` produces a week-style dashboard — two observed visits, one honest `no_observation`, and a signed worker dispute — in one command. The replay clock only ever simulates the past, so `--days N` starts N days back.

Story mode: `--days 8 --story observed,late,blackout,sub_lapse,no_show,early_out,unmatched,liveview` cycles named day-patterns — on-time, late arrival (+25 min), a camera blackout mid-visit, a no-observation day, departure-unconfirmed, out-of-window activity that produces an unmatched visit *and* a lapsed schedule, a mid-visit Ring plan lapse whose silence the signed coverage attributes to `subscription_deactivated` (a billing fact, not a device fault), and a coordinator live-view session — yielding a realistic mixed-outcome week in one command.

## Reviewing and correcting a record

1. Open a record; if it is still active, choose **Close observations for review**. Closing does not certify a departure.
2. Choose **Request worker's account** to create a private, visit-scoped review link — shown as a shareable URL and a QR code for the door-step scan (the code carries the absolute URL the server was reached at, so a phone on the same network resolves it — `attest demo --lan` binds the demo on all interfaces for exactly this). The worker can confirm their account, dispute an interpretation, or add a correction and optional reported interval.
3. Append a coordinator statement. The authenticated workspace administrator is recorded as the coordinator; this is not yet a multi-user identity system.
4. Export **original + review chain**, then upload the bundle at `/verify`. Verification checks signatures, revision ordering, and links to the supplied original under the deployment's pinned public key. The same check runs offline: `attest verify bundle.json --key <issuer-public-key>` (omit `--key` to verify against the key embedded in the receipt).

Export surfaces: `GET /visits/{id}/pack.zip` (single-visit dispute pack), `GET /sites/{id}/pack.zip` (whole-site case pack), or `attest export` without a server. Every pack embeds a stdlib-only verifier **and** `verify.html` — a zero-install browser verifier that re-implements the canonicalization, SHA-256, and Ed25519 checks in dependency-free JavaScript, so a reviewer can verify the pack by dragging the .zip itself onto the page — stored and deflate entries are read in-browser via `DecompressionStream`, media files are matched by content hash — fully offline. The pack's `index.html` browser opens with a **day-by-day strip of the whole exported window** — scheduled windows, watched coverage, interruption-marked gaps, observations, and the worker's self-reported check-ins — assembled only from verified signed payloads, so the picture can never show more than the receipts attest. `attest verify pack.zip` runs the same checks from the CLI without unzipping. The same verifier runs hosted at [josepha-mayo.github.io/attest/verify.html](https://josepha-mayo.github.io/attest/verify.html) — check any exported pack with no install at all (the hosted copy is byte-identical to the generated one; a test keeps it in sync; `docs/sample-pack.zip` is a small redacted pack the landing page offers for a zero-install try). Site packs also carry the site's *attestations* — coverage certificates, period digests, prior exports, signed `verify-live` API-sweep reports, `key:*` rotation/adoption receipts, and a source-disconnect receipt if consent was revoked — as `attestations/*.json` pinned by the signed manifest, so "was anyone watching?" travels with the evidence. Add `?redact_media=1` (or `attest export --redact-media`) to withhold media bytes while preserving the signed sha256 digests — the pack stays verifiable and the verifier reports media as withheld. `GET /visits/{id}/brief` renders a **printable case brief** — one page a customer can hand to a mediator or attach to a filing: record state, the source-by-source table, every voice verbatim, the signed anchors (receipt hash, issuer key, chain position), and the steps to verify the export pack independently. Media bytes are never on the sheet — the signed sha256 digests are — so the page is safe to hand over. `attest diff old.zip new.zip` compares two exports: appended visits/reviews are reported as normal drift; a vanished visit, an altered signed payload, or a removed review is flagged as an anomaly. `attest attack-demo` runs a real tamper battery against the local store (forge a row, delete a row, erase/truncate the journal, re-sign under a foreign key, forge a key-rotation pivot to an attacker key, replay a webhook, insert out-of-band, retimestamp index columns, swap media bytes) and rolls each back — nothing persists. And because five verifier implementations only matter if they *agree*, `tests/vectors/` is a committed conformance corpus — Wycheproof-style fixed packs (clean, rotated, revoked-with-suspect-window, tampered, smuggled, orphaned-pivot) with an `expected.json` oracle that `tests/test_conformance.py` runs through the server checker, both embedded Python verifiers, and the browser JS lib under node. A verifier that drifts from the oracle fails CI, whatever surface it runs on; regenerate with `tools/make_vectors.py` when the format deliberately changes.

Two more integrity surfaces: `attest coverage --site S --from T0 --to T1` issues a signed coverage attestation for an arbitrary interval — poll count, fraction of the window actually watched, events seen, explicit gaps — so "silence" is never conflated with "unwatched". Ring lifecycle webhooks (`device_offline`, `device_removed`, `subscription_deactivated`, `app_integration_removed`, and their restoring counterparts) journal as `coverage_events` rows and are signed into coverage reports as `interruptions`: a watched-but-quiet window where the camera itself reported offline reads *explained* — a recorded cause, still never proof of absence. `attest anchor --out anchor.json` writes a standalone signed file pinning the journal head and receipt-chain head at that instant; `attest verify anchor.json` checks it. `--publish s3://bucket/key` also uploads the anchor with its sha256 and payload hash stamped into object metadata — verified live — so the checkpoint gets custody outside the deployment (versioned bucket recommended). `--timestamp` also notarizes the anchor on the public OpenTimestamps calendars (writes `anchor.json.ots`) — once the calendar commits to Bitcoin, anyone can prove the anchor existed before that block with the free `ots` tool; `attest stamp FILE` does the same for any file and `attest stamp --upgrade FILE.ots` refreshes a pending proof. `attest verify` reports a sibling `.ots` file's status automatically. Anchors let a third party hold a checkpoint that later truncation can't silently bypass. `attest status` audits a whole runtime offline: journal integrity, receipt chain, coverage count, inbox — exits non-zero on failure, and `--json` emits the same audit machine-readable (parity with a live server's `/integrity.json`). `attest doctor` preflights the *deployment* rather than the store — admin token, webhook intake posture, replay-mode leakage, key custody (plaintext/KMS/DPAPI, plus stray-artifact mismatches), data-dir writability, the single-writer lock's current holder, TLS on the public base URL, and the media-origin allowlist — each check prints its remediation, `--json` is machine-readable, and any FAIL exits non-zero so it gates CI. `attest verify` also accepts an `http(s)://` URL — the artifact self-verifies cryptographically, so transport trust isn't required — e.g. `attest verify https://josepha-mayo.github.io/attest/sample-pack.zip` checks the hosted sample pack with no download step. `attest verify-live` turns one fresh Ring token into a timestamped official-API evidence report — users/me, app-integration state, subscriptions, devices, Event History, media download, and a real WHEP open/close — with per-check PASS/FAIL/SKIP and `--out report.json`; only checks marked PASS may be described as verified. `--sign` chains the report itself into the runtime ledger as a `verification_report` receipt (`--out` then writes the signed receipt — `attest verify` checks it), so the evidence cannot be edited to upgrade a fail to a pass.

`attest digest --from T0 --to T1` (or **Sign records digest** on a site page) signs a *period digest* — a chain-linked receipt counting the records written in the interval (observed / no-observation / unmatched, worker statements and disputes, resolved records and median time-to-resolution) and pinning the exact receipt set summarized. It's a statement about the ledger, never about physical presence — the weekly report a coordinator can hand upstream without handing over footage. On a live server the digest also runs on a cadence (`ATTEST_DIGEST_INTERVAL_S`, default 7 days): each sweep continues the chain exactly from the previous digest's window end — the ledger summarizes itself with no operator, and a skipped week leaves a visible gap rather than silently merging.

`attest explain <id> --json` emits the full plain-language explain as structured data — sources, anchors, review chain, derived stance — for scripted checks.

`GET /visits/{id}/household` renders the **household view** — the same record in plain language for the family: one glanceable state, the observed facts, the worker's own words, the coordinator's conclusion, and the full claim boundary (observation ≠ attendance; silence ≠ absence). The coordinator console answers "what does the operation need?"; the household view answers "was anyone at my mother's door on Tuesday?" **Share the household view** on the visit page issues a scoped, hashed, 7-day link (`/family/{token}`, QR-rendered) — the family opens the record itself, no admin credentials, no footage beyond that visit's own. The link is read **and append**: the family can add the household's own account (`POST /family/{token}/statement`) — what they saw, heard, or know, signed into the same chain verbatim as a third voice. It stays self-reported (identity never claimed verified), never alters the worker/coordinator stance, and a household account that contradicts the observation queues a human look — flagging the disagreement, never adjudicating it. That's the product's whole premise made trilateral: camera, worker, and household each on the record, none rewritten. The household/family page is fully localized — `?lang=es` renders it in Spanish (the family often isn't an English-first reader — that's half the caretaking story); signed statements always stay verbatim in the language they were written. Accessibility follows WCAG AA — ≥4.5:1 text contrast, visible focus rings, skip link, keyboard-operable table rows, `prefers-reduced-motion` honored (dashboard auto-refresh pauses), and `prefers-contrast` support.

The site page can broker a **live view** over Ring's WHEP endpoint — a coordinator opens a temporary stream, the browser negotiates WebRTC directly with the device's session endpoint, and Attest journals the session (site, device, opened/closed, state, failure reason) as signed-adjacent provenance. A live-view session overlapping a coverage window is copied into the signed coverage payload — it proves a stream was established at a time, never that anyone watched it, what it showed, or who was in frame. Raw session rows are retention-purgeable; the signed claim outlives them.

Corrections are separate human statements, not edits to camera evidence. Verification establishes integrity of the supplied chain, not attendance, truth of a statement, or completeness against a hidden/deleted tail. Never publish review/check-in links or personal records in the demo video.

## Ring integration status

**Verified against the live Playground (2026-09-15):** `users/me`, `devices`, Event History (three real `on_demand` entries from Playground motion triggers), media download via the 303 redirect to `*.phoenix.devices.amazon.dev` (a real 68 KB JPEG), and the full poll → visit → snapshot → signed-receipt flow (receipt `rcpt_…` cites real Ring history event ids).

**Expanded 2026-09-30 with a signed sweep:** `verify-live --sign` ran users/me, app-integration, subscriptions, devices, device status, Event History, media download, and WHEP against the real API — 5 pass / 3 fail (the fails are honest Playground scope limits: `ava.v1:read` tokens get 403 on app-integrations and 422 on subscriptions; WHEP needs streaming hardware on the account). The media check rode a real redirect to `download-eu-south-2.prod.phoenix.devices.amazon.dev` — proof the regional-host allowlist matters. The signed report itself ships at [`docs/live-sweep-receipt.json`](docs/live-sweep-receipt.json) — `attest verify` it, or drop it on the [hosted verifier](https://josepha-mayo.github.io/attest/verify.html): the signature proves the report is exactly what the API returned, and can't be edited to upgrade a fail to a pass. Findings folded back into the product: the API ignores the `event_types` history filter so the poller maps `event_type` client-side, and `on_demand` records (media requests) are kept as their own evidence kind — never mislabeled as doorbell/motion, and never allowed to open a visit (our own snapshot fetches would otherwise loop). The emulator now also writes `on_demand` entries on media requests.

**Not yet verified:** webhook delivery (a Playground token cannot reach a localhost URL), contact-sensor ingestion (no sensor exists in the Playground), and a live `ding`/`motion` event arriving through the real path — the Playground simulator only offers Package/Vehicle/Motion triggers, which history records as `on_demand`.

To attempt live polling, set these variables in the process environment before starting Attest and running `attest seed`:

- `ATTEST_REPLAY_MODE=false` in a separate non-replay runtime.
- `ATTEST_RING_BASE_URL=https://api.amazonvision.com`
- `ATTEST_RING_ACCESS_TOKEN` to a current authorized token, supplied locally rather than in a public command or chat.
- `ATTEST_POLL_HISTORY_SECONDS=15`
- `ATTEST_DATA_DIR` to a separate private runtime directory.
- `ATTEST_ADMIN_TOKEN` to the same private admin password used by the server and seed command.

The token must have access to the time range being queried. A successful empty poll does not demonstrate event delivery. Sensor support is Early Access and is not assumed available to Playground accounts.

## AWS integration status

Install the `aws` extra for boto3 and `botocore[crt]`, which supports `aws login` credentials. Set `ATTEST_SUMMARIZER=bedrock`, `ATTEST_AWS_REGION`, and `ATTEST_BEDROCK_MODEL_ID` for a model your account is permitted to invoke.

The default model is `us.amazon.nova-lite-v1:0`, a first-party multimodal model that needs no
use-case form. Latest live check on this account: Anthropic models still require the Anthropic
use-case submission, and Nova calls are authorized but return `ThrottlingException` (daily
free-tier token cap reached — retry after the cap resets or the account is upgraded). No
successful AWS model invocation has been demonstrated yet. The application identifies template
fallback separately from successful Bedrock generation; local fallback tests do not qualify as a
live AWS integration demonstration.

**KMS key custody (verified live):** `ATTEST_KMS_KEY_ID` envelope-encrypts the Ed25519
signing key — the PEM on disk is AES-256-GCM wrapped under a KMS data key, and unwrapping
requires a live `Decrypt` call with the matching encryption context, so every key use is a
CloudTrail-audited event and a stolen data directory contains nothing signable. Verified
end-to-end against a real CMK (GenerateDataKey → wrap → Decrypt → sign). Without the setting
the key is stored as a plain PEM as before. On Windows deployments with no AWS dependency,
`ATTEST_KEY_CUSTODY=dpapi` wraps the PEM under the OS user's DPAPI master key
(`attest-ed25519.key.dpapi`) — a stolen data directory yields a blob that's inert on any
other host or account. Migration is identity-preserving in both modes: a plaintext key is
*wrapped*, never silently regenerated.

**S3 checkpoint custody (verified live):** `attest anchor --publish s3://bucket/key` uploads
the signed anchor to S3 with the file SHA-256 and payload hash in object metadata — external
custody for the checkpoint, verified against a versioned, public-access-blocked bucket.

**Agent triage (Strands + Bedrock):** install the `agent` extra, then `attest triage` (or
**Run agent brief** on the dashboard, `POST /api/triage`) has a Strands agent write the
week's "needs attention" brief by reading the ledger through real tools — list sites,
list records, inspect a record's evidence/coverage/stance, check chain + journal health.
The system prompt forbids presence/absence claims, and the output always labels its source:
`strands-agent` with the model id, or `deterministic` with the reason the agent path was
unavailable. The deterministic fallback is the same computation the dashboard renders, so
triage never blocks on model access.

## Verification

```powershell
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\ruff check src tests
.\.venv\Scripts\ruff format --check src tests
```

Tests include rejected authentication, expired/reused links, concurrent arrivals, rollback after failure, source-switch rejection, late events, observation-versus-attendance semantics, history ordering, receipt/review tampering, setup validation, and fallback provenance. Socket-level tests run the CLI through real local emulator/Attest servers for sensor, camera-only, and no-observation scenarios, then append and verify worker/coordinator reviews.

A fresh published checkout of both repositories passed 293 Attest tests and 77 companion tests in a new Windows Python 3.14 environment. The GitHub Actions workflow runs both suites, lint, format checks, a tracked-runtime-file guard, and wheel builds across Windows/Linux with Python 3.11/3.14. Actions, the companion commit, and `requirements-dev.txt` dependency pins make the run reproducible. CI does not receive live Ring or AWS credentials.

## Before deployment or submission

- Load-test durable webhook intake against Ring's response deadline in a networked deployment — intake ack + a 40-delivery burst are test-covered, but production latency is unmeasured. Failed deliveries surface on the dashboard and replay via `attest deliveries --requeue` or `/api/webhook-queue/requeue`; retention purges non-chain rows.
- Validate the review workflow with actual households/workers, including disputed and missing observations, accessibility, and notification delivery.
- Validate the coordinated demo visually and replace placeholder media with permitted, clearly labelled demonstration footage.
- Complete OAuth/consent lifecycle (source disconnect is shipped; account-level revocation is the deployer's OAuth action), multi-user authorization, and deployment secret management. Local HTTP Basic is a development access boundary, not a complete production identity system. Use HTTPS outside loopback.
- Verify live webhook delivery, sensor ingestion, and a real `ding`/`motion` event (the Playground cannot generate them); plus an actual AWS invocation without fallback.
- Validate customer usefulness and hackathon rules; prepare the separate open-source contribution, product feedback, friction log, and under-three-minute video.

Runtime databases, media, private keys, tokens, and personal identifiers must not be published. Keep runtime folders out of Git. Changing ignore rules does not remove files already committed. Legacy demo records are preserved locally and may contain earlier unsupported claims; use a fresh private runtime directory when testing the corrected semantics.

## Judging criteria map

How this project sits against the hackathon's four criteria:

- **Tech Implementation** — real `api.amazonvision.com` calls (server-to-server OAuth-shaped client, webhook HMAC-SHA256 verification, `meta.request_id` idempotency, Event History polling, media download behind validated redirects) plus five AWS touchpoints: KMS envelope-encrypts the signing key (live-verified), S3 holds published anchors (live-verified), a **Lambda function verifies uploaded packs with the pinned stdlib verifier — never the pack's own embedded script** (live-verified: clean pack `ok:true`, forged pack `ok:false`), Bedrock generates summaries with honest fallback provenance, and a Strands agent triages the week by reading the ledger through tools — with a deterministic fallback that labels which source wrote the brief. The integrity layer is Ed25519 + hash-chained receipts + a hash-chained mutation journal + OpenTimestamps Bitcoin notarization — each independently verifiable offline.
- **Design** — a coherent coordinator workflow: dashboard triage → visual timeline (schedule vs. watched coverage vs. observations) → review/issue links → export a pack that verifies itself in a browser with zero install. Worker-facing pages show the same timeline the coordinator sees before they sign.
- **Potential Impact** — disputed-visit claims are a real field-service problem (cleaners, caregivers, contractors) with no product anchored to the household's own Ring events; the Ring Appstore is the named beyond-hackathon venue, and the Configure→Certify→Publish path is understood. `ring-sandbox` is independently useful to every developer integrating the Partner API (published on PyPI).
- **Quality of the Idea** — the rubric's "creative" ring, not the "obvious" one: caretaking monitoring + business-system integration + event-based triggers. The differentiated bet is *honest uncertainty as a product feature* — the record refuses to call motion "presence" or silence "absence," and signs exactly how much of the window was watched.

MIT licensed.
