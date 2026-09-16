# Project working rules

- This is an unfinished Ring hackathon prototype, not an attendance-verification or EVV-compliant product.
- Keep Attest private until the owner authorizes publication after another data/security review. Runtime SQLite files were removed from published main history; never reintroduce them or push the old history.
- Never commit runtime data, media, private keys, access tokens, authorization codes, or personal account data. Use explicit staging paths and inspect the staged file list. Runtime folders must be ignored even when their names differ from `data/`.
- Preserve the user's local runtime data. Do not reset demo databases or keys without specific approval.
- Keep observations, scheduled expectations, worker self-reports, model output, and human conclusions separate. Observed intervals are not time worked; missing events are not proof of absence. A signature authenticates record integrity under a trusted key, not physical truth.
- Worker-wide check-in tokens are legacy data only. Authentication uses visit-scoped, hashed, expiring, single-use grants. Private routes require ATTEST_ADMIN_TOKEN; CLI access logging is disabled to avoid leaking URL tokens.
- One ingestion source is bound per site. Cross-source deduplication is not implemented; switching requires explicit reconciliation. Late events must not silently mutate signed records.
- Successful local emulator tests are not successful official Playground integration tests. Live Playground verification (2026-09-15) covered users/me, devices, Event History, media download via the phoenix.devices.amazon.dev redirect, and a poll → visit → snapshot → signed-receipt run. Still unverified: webhook delivery (Playground can't reach localhost), contact-sensor ingestion, real ding/motion events (Playground only surfaces on_demand), and live AWS inference.
- Use PowerShell syntax on this Windows workspace. Do not use bash heredocs.

## Verification

Run from this repository:

- `.\.venv\Scripts\python -m pytest -q`
- `.\.venv\Scripts\ruff check src tests`
- `.\.venv\Scripts\ruff format --check src tests`
- `git diff --check`

The sibling ring-sandbox project has the same commands in its own environment. Its pytest fixtures auto-load through a pytest11 entry point; do not also register that plugin in conftest.py.

Install both editable projects together with the pinned tested set: `.\.venv\Scripts\python -m pip install -r requirements-dev.txt -e "../ring-sandbox[server]" -e ".[dev]"`. `requirements-dev.txt` is the reproducibility lock; regenerate it after deliberate dependency upgrades. The client's `send(stream=True)` and manual redirect handling require httpx>=0.28.

Windows requires tzdata for zoneinfo. aws-login credentials require botocore[crt]. Availability of an inference profile does not imply model access or quota.

Fresh published source checkouts passed all 66 Attest and 12 companion tests in an isolated Windows Python 3.14 environment. CI runs Windows/Linux and Python 3.11/3.14 without live service credentials. Its companion revision and action versions are pinned; update the companion pin only with matching integration verification. The tracked-runtime-file guard is a publication safety control, not a comprehensive secret scanner.

## Known follow-up work

Deployment authentication, live AWS inference, webhook delivery verification, customer validation, product feedback, and the submission video remain unfinished. Failed deliveries can be returned to pending via `POST /api/webhook-queue/requeue` or `attest deliveries --requeue`; `attest deliveries` inspects the inbox. Worker/countersign state is derived from the signed review chain (`countersign_status`) and never signed into payloads. Every poll writes a `poll_observations` row; receipts carry `history_poll_coverage` attesting how much of the window was watched (silence ≠ absence). Poll rows are retention-purgeable — the signed claim outlives the raw log. `GET /visits/{id}/pack.zip` exports a dispute pack: bundle + media + a stdlib-only verifier (`disputepack._VERIFIER` mirrors ledger canonicalization — keep them in sync). `attest verify bundle.json` runs the same checks offline. The client supports an RFC 6749 refresh grant (`ATTEST_RING_REFRESH_TOKEN`, `ATTEST_RING_CLIENT_ID`, `ATTEST_RING_TOKEN_URL`); on 401 it refreshes once and retries, persisting rotated tokens under the `ring_auth` store setting. Production OAuth endpoints are not yet verified — the refresh path is exercised against the emulator only. Media redirects are manually validated: JSON endpoints never follow redirects, media redirects only reach same-origin or `ring_media_origins` allowlisted HTTPS hosts, never carry credentials, and bodies are byte-capped. Request bodies, verification inputs, and link/ID path parameters are size-bounded. `attest retention` / `GET /api/retention` preview lifecycle candidates; `attest retention --apply TOKEN` / `POST /api/retention/apply` delete only the previewed non-chain set (deliveries, grants, dedupe keys, late events, media files) when the confirm token matches — chain-linked visits/receipts are never deleted in place. Webhook intake acknowledges a durable separate inbox before background processing; official deadline/load validation and failed-delivery replay tooling remain pending.

Coordinated replay is now explicit (`ATTEST_REPLAY_MODE=true`) and only accepts loopback Ring emulators in a fresh runtime; `attest replay` also resets the emulator's world so stale history cannot bind the site to the wrong ingest source. `attest replay home_aide_visit --speed 60 --auto-checkin` seeds a local case and waits for delivery processing before advancing its persisted event clock. Multi-day demos: `--days N` creates one schedule per day (the clock starts N days back — replay time can never exceed wall time), `--no-show-day K` plays no events so the schedule lapses to `no_observation`, and `--worker-review confirm|dispute` posts a worker statement on the most recent observed visit. The replay drives `POST /api/poll` between steps so `poll_observations` coverage rows land on the logical timeline. Grant expiry, statement-received time, and signature issuance always use wall time. Do not convert an existing runtime between wall and replay modes.

Worker/coordinator reviews append signed per-visit review chains anchored to the original receipt hash; never rewrite original visits/receipts when correcting an account. Worker review links bind to the scheduled worker captured in the original signed payload, not a later mutable schedule. Setup APIs are create-only, validate device access/relationships, and reject ambiguous arrival windows. Cancellation preserves an unused schedule; used schedules require review instead.
