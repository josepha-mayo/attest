# Attest

**Proof of visit, from the door.** Attest turns Ring doorbell, camera and contact-sensor events into signed, hash-chained receipts that show a home-service worker actually showed up, when, and for how long.

Built for the Ring track of the Amazon Developer Hackathon 2026 (categories: business systems, access control, caretaking).

## The problem

Millions of home visits a day are paid for on trust: home health aides, cleaners, dog walkers, contractors. When there's a dispute ("I was there three hours" / "the camera says forty minutes") nobody has a neutral record. In US Medicaid home care this is a legal requirement — the 21st Century Cures Act mandates **Electronic Visit Verification** for personal-care services — and today it's done with phone GPS check-ins that are easy to spoof and hard to audit.

The Ring doorbell is already at the door. Attest makes it the witness.

## How it works

```
Ring webhook ──► /webhooks/ring (HMAC verified) ──► VisitEngine ──► SQLite
     │                                                  │
     │  motion_detected(human) / button_press /         ├─ opens a Visit matched to a Schedule
     │  contact_sensor_faulted|cleared                   ├─ pulls arrival/departure snapshots via
     │                                                  │  POST /media/image/download, stores sha256
     └──────────────────────────────────────────────────┤
                                                        ├─ worker taps a one-time check-in link (no biometrics)
                                                        ├─ door open→close + person leaving = departure
                                                        ├─ Bedrock (or template) writes a 3-sentence summary
                                                        └─ issues an Ed25519-signed, hash-chained Receipt
```

- **Arrival**: `motion_detected` with `sub_type=human` on the door camera, a `button_press`, or the door contact sensor faulting inside a scheduled window (± grace).
- **Check-in**: the worker opens `/checkin/<token>` on their phone and confirms. Identity comes from consent, not face recognition. Snapshots are stored as evidence and hashed, never analysed for who someone is.
- **Departure**: with a door contact sensor bound, the door opens and closes and then a person is seen leaving. On a camera-only site, the last person seen at the door followed by quiet is recorded as an *inferred* departure and flagged as such. Duration is compared to the schedule and flagged (`duration_shortfall`, `late`, `no_checkin`, `no_show`, `unscheduled`, `inferred_departure`).
- **Two ingest paths**: signed webhooks at `/webhooks/ring`, or — for accounts that can't receive webhooks yet, like Playground tokens — a poller over `GET /v1/history/devices/{id}/events` that turns new `motion.human` / `ding` history events into the same v1.1 event shape (`ATTEST_POLL_HISTORY_SECONDS=15`). History event ids double as `request_id`, so switching from polling to webhooks later never double-counts.
- **Corroboration**: every receipt also embeds the Ring Event History records for the visit window, so an auditor can re-check the webhook evidence against Ring's own record.
- **Receipt**: canonical JSON of the facts and every piece of Ring evidence (event type, `request_id`, device, media sha256) → SHA-256 → Ed25519 signature, with `prev_hash` linking to the previous receipt. Verify offline at `/verify` or with `attest.ledger.verify_receipt`.

### Ring API surface used

| Endpoint | Purpose |
|---|---|
| Webhooks `motion_detected`, `button_press`, `contact_sensor_*` | arrival / activity / departure cues (HMAC `X-Signature` verified over raw bytes, `request_id` idempotency) |
| `GET /v1/devices?include=capabilities` | bind a site to its door camera and contact sensor |
| `POST /v1/devices/{id}/media/image/download` (`latest_in_range`) | arrival and departure snapshots; follows the 303 to the pre-signed URL |
| `GET /v1/users/me` | account id recorded in the receipt |
| `GET /v1/history/devices/{id}/events` (`event_types=motion.human,ding`, cursor pagination) | webhook-less ingest (poller) and per-receipt reconciliation of evidence against Ring's own history |

Ring calls go through [`ring-sandbox`](../ring-sandbox), a typed client + offline emulator built alongside this project and released separately under MIT.

### AWS

Summaries are produced by **Amazon Bedrock** through the Converse API (`ATTEST_SUMMARIZER=bedrock`), sending the visit facts plus the arrival/departure snapshots. The system prompt forbids identity, demographic, or emotional inference — the model describes the visit, not the person. If Bedrock is unavailable the receipt is still issued with a deterministic template summary; issuance never depends on the LLM.

## Run against the real Ring API (Playground)

```bash
# Generate a token at https://developer.amazon.com/ring/console/playground (30-minute lifetime)
ATTEST_RING_BASE_URL=https://api.amazonvision.com ATTEST_RING_ACCESS_TOKEN=eyJ... \
ATTEST_POLL_HISTORY_SECONDS=15 attest serve
attest seed --ring-url https://api.amazonvision.com     # binds the Playground doorbell as a camera-only site
```

Then simulate Motion / doorbell events in the Playground UI; the poller picks them up from Event History and the visit opens. Snapshots are requested from the media endpoint and attached when Ring has a recording for that window (the Playground returns `416 MEDIA_NOT_FOUND` otherwise; receipts are issued either way). Device discovery, users, history and the media error paths were verified 2026-09-15 against the Playground's Doorbell Pro; recorded response shapes live in `ring-sandbox/fixtures/`.

## Run the demo offline (no Ring hardware or token)

```bash
# terminal 1 — Ring emulator (or point ATTEST_RING_BASE_URL at api.amazonvision.com with a Playground token)
pip install -e ../ring-sandbox[server]
ring-sandbox serve

# terminal 2 — Attest
pip install -e .[aws]
attest serve

# terminal 3 — seed a site/worker/schedule, register the webhook, then replay a visit
attest demo
ring-sandbox play home_aide_visit --speed 60    # a 90-minute visit in ~90 seconds
ring-sandbox play short_visit --speed 20        # 12 minutes -> duration_shortfall flag
```

Open `http://127.0.0.1:8000` for the dashboard and the printed `/checkin/...` link on a phone-sized window.

Replayed scenarios carry back-dated Ring timestamps (a 90-minute visit spans 90 virtual minutes ending just before now) while the worker's check-in is stamped in real time, so in a compressed replay the check-in can read as later than the virtual departure. Against live Ring webhooks both clocks are the same clock.

Environment (`.env` or `ATTEST_*`): `RING_ACCESS_TOKEN`, `RING_BASE_URL`, `RING_WEBHOOK_KEY`, `SUMMARIZER=template|bedrock`, `AWS_REGION`, `BEDROCK_MODEL_ID`, `TIMEZONE`, `DATA_DIR`.

## Tests

```bash
pytest
```

The engine tests drive the state machine with real v1.1 webhook payloads; the app tests go signed-webhook → check-in → receipt → tamper → verify over HTTP against the in-process emulator.

## What this is not

- Not surveillance. No face recognition, no identity inference, snapshots are evidence for the household's own record.
- Not a claims system. Receipts are portable JSON an agency can verify with the deployment's public key; integrating with a state EVV aggregator is future work.

MIT licensed.
