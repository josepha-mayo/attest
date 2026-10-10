# Ring Appstore listing — DRAFT

> **Status:** pre-submission working draft, held to the repo's own standard — every claim below is
> backed by shipped code and tests, or named as unverified. Submission is blocked on the open items
> at the bottom. This is a hackathon prototype, not a released product.

## App name

**Attest**

**Tagline:** Tamper-evident visit records for home services — what the devices observed, what the
worker reported, what a human concluded. Records, not verdicts.

**Category (draft):** Business systems / caretaking — for households and service coordinators
scheduling cleaners, aides, dog walkers, and similar visitors. The operator is the household or its
coordinator; Attest is self-hosted software that connects to the household's own Ring account.

## What it does

Attest watches a scheduled service window through the household's own Ring devices — doorbell
presses, motion events, contact-sensor open/close — and closes the visit as an Ed25519-signed,
hash-chained receipt. The receipt records the scheduled expectation, the observations that arrived,
how much of the window the pipeline actually watched (`history_poll_coverage`, including any signed
explanation for a quiet channel), and whether a worker self-report arrived. It does not conclude
that anyone was present.

Three voices are kept separate in one append-only chain: device observations (HMAC-verified webhook
deliveries and Event History polls, each labelled by source); the worker's own account (delivered
through a visit-scoped, single-use, expiring link — a self-report, never identity proof); and the
household's account (a scoped family link that appends what the family saw or knows, verbatim, in
the language it was written — the household view localizes with `?lang=es`). A coordinator reviews
the record and signs a terminal resolution (`record_upheld` / `account_accepted` / `inconclusive`,
with an optional coded reason recorded as a stated explanation, never a verified cause). Appends
never rewrite; a newer worker statement re-opens a resolved record.

When a dispute happens, the export is the evidence. A dispute pack is a zip carrying the signed
bundle, media bytes, and two dependency-free verifiers — a stdlib-only Python script and a pure-JS
browser page — so anyone re-checks every record offline with no Attest install and no trust in the
issuer. `?redact_media=1` withholds media bytes behind their signed sha256 digests. Receipts also
commit to a transparency log with signed checkpoints, so a validly-signed record the deployment
never logged fails closed rather than passing quietly.

## Permissions / API access requested, and why

Scope note: development used an `ava.v1:read`-scoped Playground token. What that least-privilege
token could and could not reach is recorded in FRICTIONLOG.md and the signed live sweep
(`docs/live-sweep-receipt.json`). Entries mark which surfaces are required, which are optional, and
which the read scope blocked.

- **Signed webhook deliveries** (`ding`/`motion`/`contact` observations plus `device_*`,
  `subscription_*`, `app_integration_*` lifecycle events) — the primary observation channel. Intake
  verifies the HMAC before a `202` ack into a durable inbox, dedupes on `meta.request_id`
  (tombstones kept indefinitely by default), and enforces a freshness window on the HMAC-covered
  `meta.time` (default 3600 s). No shipped default webhook key: unconfigured intake fails closed.
  Lifecycle events journal as signed coverage facts — a recorded reason a channel went quiet.
- **Event History** — corroboration, and the fallback ingestion path for token-restricted accounts;
  history-derived observations are labelled as history, never conflated with webhook deliveries.
  Every poll is journaled, which is what lets a receipt attest how much of a window was watched.
- **Media / snapshots** — best-effort arrival/departure snapshots fetched through the regional
  `*.phoenix.devices.amazon.dev` redirect (credentials never forwarded to a redirect target). Each
  digest is signed into the receipt; bytes are re-verified at serve time and tampered media returns
  `410`. Snapshots carry the API-returned timestamp, never a fabricated capture time.
- **Devices, device status, capabilities** — setup-time discovery: camera/contact capabilities and
  permissions are checked before a site is bound; duplicate or ambiguous identifiers are rejected.
- **Subscriptions** — plan state matters to an evidence system: a lapsed plan suppresses observation
  delivery, so the record must tell "nothing happened" from "nothing was entitled." *Blocked under
  `ava.v1:read`* — the surface answered `422`, an authorization denial shaped like a validation
  error (FRICTIONLOG.md #14); Attest treats any 4xx scope denial as a coverage gap, never a site fact.
- **App integrations** — required to create and activate the integration that enables webhook
  delivery (create → `awaiting` → PATCH `{"status": "completed"}`; the state machine is documented
  only in community Q&A — FRICTIONLOG.md #10). *Blocked under `ava.v1:read`* — mutations answered `403`.
- **WHEP live view** — *optional, coordinator-initiated only.* The app brokers a WebRTC session; the
  journaled session proves a stream was established at a time — never that anyone watched, what it
  showed, or who was present. Live frames never enter visit evidence, sessions are disclosed to the
  household, and a disconnected site refuses. Observed `500` on Playground: streaming needs real
  hardware on the account.
- **`users/me`** — account reachability check at setup.

Known account prerequisite: third-party partner access requires a temporary pause in TAKE, and
E2EE-enrolled devices restrict partner access further (FRICTIONLOG.md #5) — the listing flow will
need to explain this to customers.

## Data handling — what leaves the household boundary

- **Local-first.** Runtime state is SQLite under one deployment-controlled data directory (a
  single-writer lock prevents split-brain signing). Nothing is published anywhere by default;
  outbound traffic is to the household's own Ring account API, plus explicitly configured extras.
- **Media is digest-pinned, not chain data.** Bytes live under the media root (0600 files / 0700
  directory on POSIX, atomic writes); signed payloads carry sha256 digests only. Bytes can be
  withheld from any export while the digests — and the record — still verify.
- **Exports are explicit operator actions** (`pack.zip` per visit or per site, or `attest export`):
  the only data-sharing artifact the system produces — a deliberate act, never telemetry, never sync.
- **Retention is two-phase.** `attest retention` previews a purge and issues an apply token — a
  sha256 of the exact candidate set — that refuses (`409`) if anything changed since preview.
  Retention purges raw operational rows (deliveries, expired grants, late events, media files, poll
  rows, coverage events, live-view sessions); dedupe tombstones are kept by default; signed claims
  survive the raw rows they were built from; chain-linked records are never deleted in place.
- **Disconnect is a tombstone, and it is one-way.** Revoking a site's Ring source signs a
  `source_disconnected` receipt naming what was unbound, stops ingestion and Event History polling,
  and ends live-view access. Reconnecting creates a new site. Deliveries arriving after disconnect
  are acknowledged but never bound or journaled.
- **Links are scoped, hashed, and expiring.** Worker check-in: 15-minute, single-use. Worker review:
  24-hour, single-use, bound to the scheduled worker and visit. Household view+statement: 7-day,
  multi-use until expiry, revocable (`family-link/revoke` journal-deletes the grant), statements
  capped at 10 per visit. Only token hashes are stored — the raw token exists in the issuance URL —
  and URL access logging is disabled so links can't leak through logs.
- **Optional network paths are opt-in and labelled.** Bedrock summaries and the Strands triage brief
  run only when configured; every generated artifact records its true source (model id, or template
  fallback + reason). KMS/DPAPI key custody, S3 anchor publishing, and OpenTimestamps notarization
  are operator-invoked extras.

## What this app does NOT do

These are architectural boundaries, printed on every record — not missing features.

- **Not attendance verification, not EVV.** Attest is not an electronic visit verification system
  under 42 U.S.C. §1396b(l)(5)(A) and claims no compliance certification. Observed intervals are not
  time worked. A receipt carries a six-element statutory crosswalk with per-element basis qualifiers
  (`scheduled_expectation` vs `camera_event_window`) — a mapping a reviewer can check, never a
  compliance claim.
- **Silence is not absence.** No matching observations means attendance is *unknown* — a missing
  event can reflect connectivity, consent, entitlement, recording, or ingestion gaps. Signed
  coverage attestations say how much of a window was watched; `device_offline` and
  `subscription_deactivated` events are journaled so post-incident quiet reads *explained*, never
  *absent*.
- **Observation is not identity.** A schedule is an expectation; a camera or sensor event does not
  establish identity, direction of travel, continuous presence, or work performed. A check-in link
  click is a self-report — and it can never open a record: the server rejects
  (`checkin_precedes_observation`) any self-report timestamped before the first device observation.
- **No continuous tracking.** No background location, no GPS, no tracking of the worker's phone —
  observation is anchored to the household's own devices at the service address, during scheduled
  windows.
- **A signature proves integrity, not physical truth** — a record is unaltered since issuance under
  the issuer's key; not that the keyholder is honest or that events happened. Detecting a dishonest
  deployment is itself designed (transparency log, external anchors, witness cosigning, monitor).
- **Model limits, stated on the record:** one active visit per site (overlapping workers share a
  record); one ingestion source per site; coordinator statements sign under the deployment's single
  admin identity, not yet a multi-user identity system.

## Reviewer notes — how to verify these claims

- **`attest demo`** — one command boots the Ring emulator, the server, and an eight-day
  mixed-outcome story (on-time, late, mid-visit camera blackout, mid-visit plan lapse, a
  no-observation day, departure unconfirmed, unmatched activity, a coordinator live view). No Ring
  account or credentials needed; it prints a dashboard URL.
- **Zero-install verification** — `docs/verify.html` (also hosted) verifies any exported pack
  in-browser: the bundled sample verifies green; its doctored twin fails red (`payload hash
  mismatch`); a three-attack gallery (deleted record, smuggled file, forged verifier) fails at three
  different layers.
- **The signed live-API sweep** — `docs/live-sweep-receipt.json` is the `verify-live --sign` report
  from the real `api.amazonvision.com` run (2026-09-30): 5 pass / 3 fail — the fails are the
  scope-blocked app-integrations (`403`), subscriptions (`422`), and hardware-less WHEP (`500`)
  described above. The signature proves the report is what the API returned.
- **`JUDGE.md`** (or `attest judge`) — the full ten-minute verification path. `attest attack-demo`
  runs twenty-one real tamper attempts against a live store, all caught; `attest status` /
  `/integrity` is the deployment's self-audit; `attest doctor` is the deployment preflight.
- `THREATMODEL.md` states the trust model and every detection path; `FRICTIONLOG.md` documents all
  17 real API frictions hit during the build, including the scope denials this listing discloses.

## Open items before real submission

These are unsolved today and would be disclosed in certification review:

- **Deployment authentication.** A single admin token over HTTP Basic is the current access
  boundary — a development posture, not production identity. Multi-user coordinator identities are
  not built.
- **Production OAuth.** The RFC 6749 refresh grant and 401-retry are implemented and
  emulator-verified; the real token endpoint is unexercised. TAKE/E2EE enrollment boundaries need
  user-facing explanation.
- **Live webhook delivery.** Verified against an emulator implementing the documented scheme; the
  Playground cannot reach localhost, so real Ring-cloud delivery, contact-sensor ingestion, and a
  real `ding`/`motion` event are still unverified (history polling is the verified path).
- **Bedrock inference.** Wired and provenance-labelled, but every model/region throttled at
  verification time (zero on-demand quota on this account; a Service Quotas increase is the fix).
  Demos run on the labelled template fallback.
- **Intake load headroom.** Webhook burst handling is test-covered; production latency against
  Ring's response deadline is unmeasured.
- **Customer validation.** The review/dispute workflow, accessibility (WCAG AA posture: contrast,
  focus, keyboard, reduced-motion), `?lang=es` surfaces, and notification delivery have not been
  validated with real households or workers.
- **Roadmap items named in the repo:** named-identity household accounts, multi-source ingestion
  with explicit reconciliation, and export-and-archive retention for chain-linked records.
