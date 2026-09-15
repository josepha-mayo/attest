# Attest

**A reviewable record of doorstep observations and worker self-reports.**

Attest is an early prototype for the Amazon Developer Hackathon's Ring track. It is not a completed submission, an EVV-compliant system, or proof of attendance. The proposed customer is a household or service coordinator reviewing a scheduled visit alongside the worker's own account.

## What the record means

- A schedule records an expectation, not the identity of a person at the camera.
- Ring motion, button, and contact-sensor events are observations. They do not establish direction of travel, identity, continuous presence, or work performed.
- A check-in is a self-report made through a visit-specific link. It is not independent identity or location verification.
- The observed interval measures time between received observations, not time worked.
- A door cycle followed by motion is only a candidate departure. Closing a record sends it for review; it does not certify departure.
- No matching observations means attendance is unknown, not that the worker failed to show up. A missing event can reflect connectivity, consent, recording, or ingestion gaps.
- Ed25519 signatures and a hash chain protect record integrity under an externally trusted issuer key. They do not prove the underlying observations or conclusions are true. A chain alone cannot detect deletion of its entire tail without an external checkpoint.

## Implemented

- Ring Partner API client via the companion [ring-sandbox](https://github.com/josepha-mayo/ring-sandbox) project.
- HMAC-verified webhook intake, with account-to-site checks.
- Event History polling with human-motion and doorbell results merged in chronological order. History-derived observations are labelled as history, not authenticated webhook deliveries.
- One ingestion source is bound per site. Switching between history and webhooks is rejected pending reconciliation; their identifiers are not interchangeable and cross-source deduplication is not yet implemented.
- Atomic event processing, check-in consumption, and receipt issuance in SQLite. Failed processing rolls back the consumed marker and database changes. Out-of-order events are retained for review instead of rewriting an existing signed record.
- Observations matched to schedules without assigning the scheduled worker as the observed person's identity.
- Visit-scoped check-in grants: random tokens, only a hash persisted, 15-minute expiry, one use. Issuing a replacement invalidates the prior grant. Legacy worker-wide links no longer authenticate.
- Best-effort snapshots with the returned media timestamp, not a fabricated capture time. Missing media is flagged. History records for the interval are attached where available.
- Insert-only signed receipts. Schema v2 binds the receipt ID, visit ID, issuance timestamp, sequence, and previous hash into the signed payload.
- Authenticated dashboard, media, exports, and administration. Private responses are not cached. Cross-origin writes are rejected. URL access logging is disabled by the CLI to avoid logging check-in links.
- Bedrock Converse integration with explicit per-record provenance: actual summary source, model when used, and fallback reason. A configured provider is not evidence of a successful model invocation.

## Local development on Windows

Clone Attest and ring-sandbox into sibling directories. From the Attest directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e "../ring-sandbox[server]" -e ".[dev]"
$env:ATTEST_ADMIN_TOKEN = [System.Net.NetworkCredential]::new("", (Read-Host "Private admin password (32+ characters)" -AsSecureString)).Password
Start-Process .\.venv\Scripts\ring-sandbox.exe -ArgumentList "serve"
Start-Process .\.venv\Scripts\attest.exe -ArgumentList "serve"
.\.venv\Scripts\attest demo
.\.venv\Scripts\ring-sandbox play short_visit --speed 20
```

Open `http://127.0.0.1:8000`. The browser's HTTP Basic login uses username `admin` and the private password configured above. Open an observation record and choose **Issue a check-in link** to obtain a link for the scheduled worker. Share it privately; never put it in a public demo recording.

The emulator is an independent local test tool, not Amazon's official Playground. Its default images are generated placeholders and its default MP4 is not playable video. Local tests are not proof that the full official Ring integration works.

Scenario timestamps currently use a back-dated virtual clock while a real check-in uses wall-clock time. A conflicting check-in is flagged, not silently presented as a successful clean visit. A coordinated replay clock and review workflow remain to be built.

## Ring integration status

The earlier live probe verified device discovery, user lookup, an empty history response, and media error responses against the official Playground. It exposed one camera and no contact sensor to the tested token. The typed client's nullable audio capabilities were fixed from that response.

**Not yet verified:** an official Playground event reaching Attest, a successful media download, or a full official event-to-receipt demo. Do not describe those paths as completed.

To attempt live polling, set these variables in the process environment before starting Attest and running `attest seed`:

- `ATTEST_RING_BASE_URL=https://api.amazonvision.com`
- `ATTEST_RING_ACCESS_TOKEN` to a current authorized token, supplied locally rather than in a public command or chat.
- `ATTEST_POLL_HISTORY_SECONDS=15`
- `ATTEST_DATA_DIR` to a separate private runtime directory.
- `ATTEST_ADMIN_TOKEN` to the same private admin password used by the server and seed command.

The token must have access to the time range being queried. A successful empty poll does not demonstrate event delivery. Sensor support is Early Access and is not assumed available to Playground accounts.

## AWS integration status

Install the `aws` extra for boto3 and `botocore[crt]`, which supports `aws login` credentials. Set `ATTEST_SUMMARIZER=bedrock`, `ATTEST_AWS_REGION`, and `ATTEST_BEDROCK_MODEL_ID` for a model your account is permitted to invoke.

The previous live attempts failed: Anthropic required a use-case submission; Nova returned throttling. The cause of the Nova quota error has not been established. No successful AWS model invocation has been demonstrated. The application now identifies template fallback separately from successful Bedrock generation. Local fallback tests do not qualify as a live AWS integration demonstration.

## Verification

```powershell
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\ruff check src tests
.\.venv\Scripts\ruff format --check src tests
```

Tests include rejected authentication, expired/reused check-in links, concurrent arrivals, rollback after failure, source-switch rejection, late events, observation-versus-attendance semantics, history ordering, receipt tampering, and fallback provenance.

## Before deployment or submission

- Replace slow synchronous webhook processing with durable intake and background enrichment to meet Ring's response deadline.
- Add a worker/coordinator review and correction workflow without rewriting signed evidence.
- Coordinate replay clocks and distinguish every local scenario from live data in the demo.
- Complete OAuth/consent lifecycle, retention/deletion, multi-user authorization, token refresh, and deployment secret management. Local HTTP Basic is a development access boundary, not a complete production identity system. Use HTTPS outside loopback.
- Finish runtime-input limits and media-redirect hardening, fresh-clone verification, and CI.
- Verify live Ring events/media and an actual AWS invocation without fallback.
- Validate customer usefulness and hackathon rules; prepare the separate open-source contribution, product feedback, friction log, and under-three-minute video.

Runtime databases, media, private keys, tokens, and personal identifiers must not be published. Keep runtime folders out of Git. Changing ignore rules does not remove files already committed. Legacy demo records are preserved locally and may contain earlier unsupported claims; use a fresh private runtime directory when testing the corrected semantics.

MIT licensed.
