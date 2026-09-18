# Attest — threat model and trust boundaries

This document states what Attest's records prove, what they deliberately do
not prove, and how each tamper path is detected. It is written for reviewers,
judges, and the pre-publication security review — not as marketing.

## The one-sentence model

A valid Attest signature proves that **a signed record has not been altered
since issuance under a specific issuer key** — integrity, not physical truth.

Everything else follows from that.

## Trust anchors

| Anchor | Held by | What it proves | What it does not prove |
| --- | --- | --- | --- |
| Ed25519 issuer key | The deployment (optionally KMS-envelope-encrypted) | Records signed under it are unaltered | That the key holder is honest, or that events happened |
| Receipt chain (sequence + `prev_hash`) | Inside the store | A receipt was issued in a position after another | That earlier receipts exist elsewhere |
| Journal hash chain + `journal_head` pins in receipts | Inside the store | Mutations since a receipt's issuance are detectable; tail truncation is signature-detectable | The journal's completeness before the first pin |
| Signed anchors (`attest anchor`) | **Outside** the store — a file, an S3 object | The journal/receipt state existed at issuance | Anything after the anchor unless another anchor exists |
| Worker review links | Hashed, expiring, single-use, visit-scoped grants | A statement arrived through a link issued for this visit and this scheduled worker | The worker's identity — a stolen link signs a stolen statement |
| Media digests | Inside signed payloads | The bytes presented hash to what the record declared | That the bytes show what anyone claims they show |

## What the records are

Each visit produces a signed receipt whose payload captures, at issuance:

- the scheduled window and the scheduled worker (an *expectation*)
- observed evidence with event kinds and timestamps (*observations*)
- worker check-in time if one arrived (*a self-report*)
- `history_poll_coverage` — how much of the window the pipeline actually
  watched, including failed polls (*coverage honesty*)
- `journal_head` — the mutation-log tip at issuance (*integrity pin*)
- the summary and its provenance — template, model name, or fallback reason
  (*a generated artifact, labeled*)

Reviews — worker statements and coordinator assessments — are appended in a
separate per-visit signed chain anchored to the original receipt hash.
Originals are never rewritten; corrections are new signed entries.

## Attack paths and their detection

`attest attack-demo` executes each of these inside a rolled-back transaction
against a live store:

| Attack | Detection |
| --- | --- |
| Forge or edit a visit row | Receipt signature/payload hash mismatch on verification |
| Delete an evidence row | Signed evidence list no longer matches store contents |
| Edit a mid-chain journal entry | `verify_journal` chain break at that position |
| Truncate the journal's tail | `journal_head` pins in later receipts name a head that no longer exists |
| Re-sign a receipt under a foreign key | Signature fails under the pinned issuer key |
| Replay a delivered webhook | `seen_requests` dedupe; delivery lands rejected in the durable inbox |
| Insert a row out-of-band | Journal continuity and receipt-pin mismatches |
| Drop a file from an exported pack | Verifier reports missing media or missing bundle explicitly |
| Drop or swap a record inside a case pack | Signed `case_export` manifest names the exact visit→hash map; mismatch fails closed |
| Rewrite a signed case manifest | `manifest_sha256` inside the signed receipt no longer matches |
| Forge a `redaction.json` naming undelivered digests | Fails closed — withheld digests must match signed evidence |
| Swap issuer keys in a pack | Public key is inside every signed payload and the manifest; compare out-of-band |

Two paths need an **external anchor** to be provable: truncating the journal
before the earliest pin, and wholesale replacement of store + receipts + key
together. Anchors exist for exactly this; `--publish s3://` gives them custody
outside the deployment's control, and `--timestamp` / `attest stamp` notarize
the file's digest on public OpenTimestamps calendars — once the calendar's
Merkle root lands in a Bitcoin block, the `.ots` proof attests the anchor
*existed at that time*, verifiable by anyone with the free reference tool.
Backdating an anchor is then provable against a clock neither we nor the
deployment controls.

## Privacy model

- Media bytes are export artifacts, not chain artifacts. The chain carries
  sha256 digests; bytes live under the media root and can be withheld.
- Selective disclosure (`?redact_media=1`, `attest export --redact-media`)
  withholds bytes behind a `redaction.json` marker while preserving every
  signed digest — a coordinator can review the record without receiving
  footage. Redaction lists that name digests absent from signed evidence
  fail closed.
- Review-link tokens are stored hashed; the raw token exists only in the URL
  shown at issuance. CLI access logging is disabled so URLs are not logged.
- Retention (`attest retention`) purges only non-chain data — deliveries,
  grants, dedupe keys, late events, media files. Signed records are never
  deleted in place.

## Deliberate non-claims

These are architectural boundaries, not missing features:

- **Not attendance verification.** Observed intervals are not time worked.
- **Not absence detection.** A silent window means nothing was observed —
  coverage attestations exist to say how much was even watched.
- **Not identity verification.** Worker statements are accounts delivered
  through scoped links; schedules describe expectations, not people.
- **No cross-source deduplication.** One ingestion source is bound per site;
  switching requires explicit reconciliation.
- **Late events never mutate signed records.** They are retained and labeled
  as late-arriving.
- **A configured summarizer is not a successful invocation.** Every summary
  records its actual source and fallback reason.

## Key custody

- `ATTEST_KMS_KEY_ID` envelope-encrypts the Ed25519 key: the on-disk PEM is
  AES-256-GCM wrapped under a KMS data key with a fixed encryption context.
  Unwrapping requires a live `Decrypt` — every unwrap is a CloudTrail event.
  A KMS path that cannot reach KMS fails loudly rather than downgrading to a
  plaintext key.
- Without KMS, the key is a file with owner-only permissions in the data dir.

## Ingestion boundary

- JSON endpoints never follow redirects. Media redirects resolve only to
  same-origin or `ring_media_origins`-allowlisted HTTPS hosts, never carry
  credentials, and bodies are byte-capped.
- Webhook intake acknowledges into a durable inbox before processing;
  processing is idempotent on `request_id`.
- Request bodies, verification inputs, and path parameters are size-bounded.
- `ATTEST_ADMIN_TOKEN` gates private routes; worker routes accept only
  visit-scoped link tokens.

## Known open items

- Deployment authentication beyond the single admin token is not built —
  this is a single-operator prototype.
- Webhook signature validation against official Ring delivery is unverified
  (the Playground cannot reach localhost); the inbox verifies HMAC keys for
  emulator deliveries.
- Contact-sensor ingestion is implemented but not verified against official
  hardware.
- Bedrock summarization is wired and provenance-labeled; live inference was
  quota-limited at verification time, so shipped demos run on the labeled
  template fallback.
