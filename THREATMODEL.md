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
  watched, including failed polls (*coverage honesty*), plus any Ring lifecycle
  events (`device_offline`, subscription or link changes) recorded in the
  window — a signed *reason* the channel went quiet, still never absence
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
| Replay a delivered webhook | `seen_requests` dedupe plus a signed-body freshness window: `meta.time` is HMAC-covered, so a verbatim replay past `webhook_max_age_s` (default 1h) is rejected even if its tombstone was purged; retention keeps tombstones by default (`retention_seen_days=0`) |
| Deliver a webhook with a forged HMAC | Signature verification at intake and again in the worker; with no `ATTEST_RING_WEBHOOK_KEY` configured, intake fails closed (503 / rejected) rather than trusting nothing |
| Swap media bytes on disk after signing | Serve-time digest check — bytes that fail the signed sha256 return 410 on both admin and family-link paths |
| Insert a row out-of-band | Journal continuity and receipt-pin mismatches |
| Update a denormalized index column directly (token_hash, visit_id, state, polled_at, coverage_events.at, liveview_sessions.opened_at) | `verify_journal` re-derives every index column from the signed body and flags divergence; `late_events.site_id` is bound into the journaled row hash itself — residual: for a late_events row journaled after the last receipt pin, rewriting the whole tail could hide a site_id change, since no second check covers it — the same tail-truncation boundary anchors exist to close |
| Drop a file from an exported pack | Verifier reports missing media or missing bundle explicitly |
| Drop or swap a record inside a case pack | Signed `case_export` manifest names the exact visit→hash map; mismatch fails closed |
| Drop, swap, or smuggle a site attestation in a case pack | The manifest's signed `attestations` list pins receipt_id + visit_id + payload_hash; every verifier checks signature + manifest equality, and a file the list does not name fails closed |
| Smuggle a file the manifest never names (top-level, inside a listed visit dir, or a media member whose bytes hash to no signed digest) | Every verifier (server, embedded `verify_case.py`, `verify.html`/`index.html`, `packdiff`) whitelists pack members and digest-checks media — any unlisted file fails the pack |
| Forge a resolution's coded reason post-signature (relabel the coordinator's stated explanation) | The `reason_code` rides inside the signed review payload — the journal flags the row edit and the bundle signature fails verification |
| Rewrite a signed case manifest | `manifest_sha256` inside the signed receipt no longer matches |
| Forge a `redaction.json` naming undelivered digests | Fails closed — withheld digests must match signed evidence |
| Swap issuer keys in a pack | Public key is inside every signed payload and the manifest; compare out-of-band |
| Splice markup/script into a tampered pack's narrative fields | Every interpolated field is entity-escaped, and a bundle that fails signature verification renders only its FAILED verdict row — statements, timeline, and the plain-language view never render untrusted content |
| Corrupt a stored row's body in place (crash the read surfaces into silence) | `StoreCorrupt` fails every read closed — the CLI exits with one error line and browser surfaces render a styled 500 pointing at `/integrity`; `verify_journal`'s body-hash + index re-derivation names the divergent row. No surface silently skips the row (that would hide evidence) |
| Corrupt a `settings` body to break boot/status | Same `StoreCorrupt` path — a non-dict or unparseable settings row is corruption, not a default |
| Enable KMS on a deployed plaintext key to rotate the issuer silently | The existing PEM is wrapped in place (same identity); the wrapped record lands before the plaintext is removed, and unreachable KMS fails before anything is touched — key identity can never change without a signed-chain break that `verify_chain` reports |
| Flood the inbox with far-future event timestamps to exhaust its retry budget | `NotYetAdmissible` reschedules to the admissibility instant — early arrivals never dead-letter, and terminal `failed` still requires five real processing failures |
| Point `attest journal`/`status` at a missing or empty runtime to print a false "intact" verdict | Both refuse before opening — SQLite must not mint an empty store on a verify path |
| Submit a coverage/digest request with an inverted window to mint a vacuous signed claim | Refused (`end <= start` raises before signing) — the deployment's key never signs an empty claim |
| Truncate signed coverage payloads via the store's 500-row listing cap | Signed reads pass `limit=None` — a cap that dropped later "restored" events would over-explain gaps |
| Feed a malformed bundle member to `attest diff` to mask other anomalies | Malformed members are flagged per-record; the diff still reports every other anomaly |
| Pack a zip with duplicate member names or `..`/absolute/drive-qualified paths (shadow a verifying member, escape the pack root on unzip) | `check_member_names` fails the whole pack — duplicates are ambiguous across extractors and traversal segments dodge prefix whitelists; enforced identically by `packdiff.load_artifact`, the server's `_verify_pack`, and the browser verifier's `readZipEntries` |
| Re-send a delivered `request_id` with different bytes or signature (replay probe or upstream key drift) | The inbox refuses with no write — a legitimate retry repeats the same signature under the same id; a changed body or signature under a known id always means something is wrong |
| Forge a `key_rotation` receipt pivoting the issuer to an attacker key | Only a rotation signed by the retiring key pivots — `verify_chain` verifies the receipt under the current chain key first, so an attacker-signed rotation breaks the chain at its own position before any pivot applies |
| Graft an attacker key as a trusted issuer *predecessor* (mint "attacker key retired into the victim key") | Endorsement is self-serve, so ancestor hops additionally require a `key_adoption` receipt countersigned by the successor naming the exact rotation — the victim key never consented, so the attacker key never enters `trusted_issuer_keys` and pack verification keeps rejecting it |

## Signing-key rotation

`attest rotate-key` retires the deployment signing key: the retiring key signs
a `key_rotation` receipt endorsing its successor, the successor lands under the
same custody posture (plaintext, KMS-wrapped, or DPAPI), then countersigns a
`key_adoption` receipt naming the exact rotation (id + payload hash).
`verify_chain` reads the rotation as a pivot — receipts before it verify under
the old key, receipts after under the new — and pack verifiers extend
pinned-key trust across the handoff through `trusted_issuer_keys` /
`descendant_issuer_keys`.

Both forgery directions are covered: a pivot signed by anyone but the retiring
key breaks chain verification outright, and an ancestor claim without the
successor's countersigned adoption never enters the trusted set — endorsement
alone is self-serve, consent is not. What rotation does **not** prove: that
either key was or stayed uncompromised. A compromise discovered after the fact
is a revocation problem; rotation is the continuity story, not the rescue.

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
  grants, late events, media files; dedupe tombstones are kept by default
  (opt-in purge via `retention_seen_days`). Signed records are never
  deleted in place.
- Family links are revocable (`family-link/revoke` journal-deletes the
  grant) and household appends are capped at 10 per visit — a shared link
  can't flood the 500-entry review chain and freeze the worker channel.

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
  Enabling KMS on a deployment whose plaintext `attest-ed25519.key` already
  exists wraps that same key — issuer identity is preserved, the plaintext
  PEM is removed only after the wrapped record is written, and a KMS outage
  fails before either file is touched.
  Unwrapping requires a live `Decrypt` — every unwrap is a CloudTrail event.
  A KMS path that cannot reach KMS fails loudly rather than downgrading to a
  plaintext key.
- `ATTEST_KEY_CUSTODY=dpapi` is the AWS-free middle ground (Windows only):
  the PEM wraps under the OS user's DPAPI master key via `CryptProtectData`
  (UI forbidden — a service never prompts) and stores as
  `attest-ed25519.key.dpapi`. The blob is bound to this user on this
  machine — a stolen data directory yields an inert blob on any other
  host or account, with no CloudTrail equivalent (the trade: local custody,
  no audit trail). Migration mirrors KMS: a plaintext PEM is wrapped, not
  replaced, so issuer identity survives enabling custody. DPAPI on a
  non-Windows host fails loudly, and configuring both KMS and DPAPI is a
  hard error — protection postures never combine or silently pick one.
- Without KMS or DPAPI, the key is a PEM file in the data dir — written
  `chmod 600` (owner-only) on POSIX; on Windows it inherits the data dir's
  ACLs, so deploy under a service-account directory or use custody there.
- `attest rotate-key` makes rotation a chain event, not a config swap: the
  retiring key first signs a `key_rotation` receipt naming the successor (the
  ledger's pivot — `verify_chain` verifies pre-pivot receipts under the old
  key and post-pivot under the new), `persist_signer_key` atomically writes
  the successor under the same custody posture (the old key survives until
  the new one is durable), and the successor countersigns via `key_adoption`.
  A pinned `--key` may sit on either side of a rotation — verifiers walk the
  signed endorsements (`trusted_issuer_keys` backward, `descendant_issuer_keys`
  forward) and never trust a key that merely shows up in a pack.

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
- Contact-sensor ingestion is implemented but not verified against official
  hardware.
- Bedrock summarization is wired and provenance-labeled; live inference was
  quota-limited at verification time, so shipped demos run on the labeled
  template fallback.
