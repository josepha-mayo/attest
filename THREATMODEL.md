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
| Signed anchors (`attest anchor`) | **Outside** the store — a file, an S3 object | The journal/receipt state existed at issuance, plus the log's Merkle head as an external STH | Anything after the anchor unless another anchor exists |
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
| Replace the pack's own verifier script with a forged always-green copy (the strongest social-engineering attack on offline verification — membership whitelists check names, never bytes) | `verifier_manifest.json` is an issuer-signed receipt pinning each tool member's sha256 (`verify_case.py`/`verify_bundle.py`, `verify.html`, `index.html`, `README.txt`): a scope graft, a foreign signer, a pinned member absent, or a tool present-but-unpinned all fail — enforced identically by `app._verify_tools_pin`, embedded `check_tools`, `packdiff.check_tools_pin`, and the browser `checkTools`. Packs predating the member pass unpinned — optional when absent, mandatory when present |
| Present a validly-signed receipt the deployment never logged (a genuine receipt grafted from another export, or a signature that verifies but has no history) | `log_checkpoint.json` carries a signed Merkle Tree Head (an RFC 6962-style `log_checkpoint` receipt) plus an inclusion audit path per pack receipt: membership in the published log is provable in O(log n), so a dropped proof or a grafted audit path fails identically on `app._verify_log_pin`, embedded `check_log`, `packdiff.check_log_pin`, and the browser `checkLog`. Only issuer-lineage receipts owe proofs — a foreign-signed pool entry is inert and can't fail a pack by existing. Checkpoints are receipts but never leaves (no self-reference); review-chain entries anchor to the proven original's hash instead of logging directly. Legacy packs without the member pass with the log line absent |
| Quietly rewrite log history between two checkpoints | `attest consistency`/`GET /api/log/consistency?first=N` serves an RFC-style consistency proof binding the earlier signed head into the later tree — a forked or truncated log can't bridge them; every checkpoint after the first also embeds a signed `extends` bridge to its predecessor inside the payload, so the chain self-proves continuity offline (`attest verify new.json --against old.json`) and the monitor + live cross-check verify that signed bridge before asking for any served proof — a checkpoint claiming our pinned size from a different root is a signed self-contradiction, not a network problem; `attest monitor` (a third-party watchdog any auditor can run, `--once` for CI) pins a signed head and requires each later checkpoint to extend it by proof, so a regressed, forked, foreign-signed, or unsigned replacement head fails loudly rather than repinning |
| Serve a victim's verifier a forked log the world never sees (per-victim split view — the pack's own checkpoint is genuine but commits to a log tree the deployment only shows this victim) | `attest verify pack.zip --issuer-url <deployment-url>` (URL form, not doc file) cross-checks the pack's signed head against the deployment's *live* `/api/log/head` after the pack verifies: same head or a proof-bridged extension reports `live_log.same_log`; a same-size different-root head is an unforgeable fork and fails the verify; a regressed head, a postdated pack head, or a malformed bridge is reported honestly (undecidable → never a pass, fork/regress → hard fail). The structural fix is witness cosigning: `attest checkpoint --witness <url>`/`attest export --witness` collects counter-signatures from independent Attest deployments (`POST /api/witness/cosign` — each witness pins the issuer's last-seen head and signs only a checkpoint it proves extends its pin), so a per-victim fork can't carry the same cosigs the public head does |
| Flood the witness endpoint with cosign requests to bloat the witness ledger (each request writes a signed receipt) | The witness POST is unauthenticated by design (a public cosigning service, like a CT witness) but shares the per-IP rate budget — floods get 429 JSON; body size is middleware-capped, malformed docs are 422'd, an unbridgeable head 409s without writing anything, the requester's key_receipts pool is bounded (unbounded signature-walk input would be a CPU amplifier), and the pin-check → sign → repin section is a single store transaction so concurrent offers can't double-sign divergent heads or collide on sequence. Browser-cross-site posts are refused like every write surface. Residual: an issuer can poison ITS OWN pin on a witness (a self-signed checkpoint with an absurd tree_size) and lock itself out of future cosigs there — self-inflicted, needs the issuer's key, unrecoverable by design (a reset would be a repin without continuity — the thing witnesses exist to refuse) |
| Race parallel cosign offers to make a witness attest two divergent heads, or collide receipt sequences into 500s | `witness_cosign` wraps pin-read → sequence-allocate → sign → pin-write in one `store.transaction()` (RLock + BEGIN IMMEDIATE) — the same serialization `@atomic` gives every engine writer — so offers are strictly ordered; the second sees the first's committed pin and sequence. The requester's `key_receipts` lineage pool is capped at 64 entries: real lineages are single-digit hops, but every candidate costs an Ed25519 verification |
| Rotate the issuer key (or claim an ancestor) to mint a fresh witness pin slot — the forked head arrives under a "new" issuer and signs without any continuity check | Witness pin slots key on the issuer family's ROOT (`ledger.lineage_root` — the oldest consented-pivot ancestor), not the claimed tip: every alias the certified lineage contains resolves to one slot, so a rotated tip offering a fork gets the same 409 any fork gets. Pre-canonical pins migrate: on first contact under the new scheme the newest family-member legacy slot is adopted, continuity-checked, repinned under the root, and tombstoned out of `/api/witness/heads`. Cosigs stamp `subject_issuer` as the root, so verifiers match the identity however the tip changes. Residual: a doc that hides its own rotation history presents only its claimed key — indistinguishable from a genuinely new issuer under any requester-supplied-identity scheme |
| Inflate "cosigned by N" with duplicate cosigs, repeat signers, or the issuer's own sock-puppet key | Every verifier surface (`check_cosignatures`/`_cosig_count`/browser `checkLog`) counts DISTINCT witnesses only: one receipt id counts once, one signer key counts once, and a cosig signed inside the issuer's own certified lineage is self-vouching — excluded entirely. The named-witness gate (`--witness-key` raw keys, `--witness-url` resolving deployments via their own issuer docs — rotation-surviving, `--witness-threshold N` for k-of-n) lets the verifier require specific independent parties, not just a count |
| Fork visible to one observer only — the deployment shows monitor A the true log and witness W a fork (or vice versa), so each check passes alone | `GET /api/witness/heads` publishes every issuer head a witness has counter-signed — each pin served with its signed cosignature receipt, so the view is verifiable evidence, not an unsigned claim a MITM or dishonest endpoint could invent — and `attest monitor <log> --witness <w>` cross-views them under the witness's certified issuer lineage: two observers signing the same (size, root) means one log was served to both; same size with different roots is an unforgeable divergence that fails the cycle, a view whose signed receipt verifies but contradicts itself (bad signature, subjects disagreeing with the pin, foreign subject issuer) is 'dishonest' — a verified lie that freezes repins like a divergence — while merely unestablishable views report 'unverifiable', never silently compared — the gossip-layer check a single-monitor deployment can never make |
| Witness double-speak — serve cosig A to one auditor and cosig B to another, then deny one ever existed | The witness's own attestations are leaves in ITS OWN transparency log: the cosign endpoint self-checkpoints that log on the spot and returns `witness_anchor` (the witness's signed checkpoint + the cosig's inclusion proof), `/api/witness/heads` carries the anchor per pin, and `compare_views` verifies it — a second contradicting attestation can't hide, it would need the witness to fork its own published log too. An anchor present-but-forged is 'dishonest'; an absent one is an honest 'not yet anchored'. And the monitor pins the witness's own log head too (`witness_logs` in the state file): the served anchor must provably reconcile with that pin, so a per-victim anchor checkpoint over a private witness fork — which verifies fine in isolation — is reported dishonest instead of passing. Packs carry the anchor too (`cosig_anchors` in the checkpoint doc): an offline verifier proves 'the witness attested this' was committed to a log the witness signs — and a packed anchor that doesn't verify fails the pack, since a claimed anchor is either verifiable or a lie |
| Deployment serves different transparency-log histories to different export requesters | `attest diff` compares the SIGNED tree heads two packs carry: identical heads agree, adjacent heads bridge via the checkpoint's own embedded extends proof, and same-size different-root is a provable fork — the issuer signed two histories at one tree size. Non-adjacent heads reconcile *offline* too: every exported `log_checkpoint.json` embeds `chain` — up to 32 prior signed checkpoint receipts, each verified under the issuer lineage with its own `extends` bridge — so `diff` walks the newer pack's chain hop-by-hop until it reaches the older head (proven append-only growth, no network), collides with a same-size different-root member (a provable fork *inside* the chain itself), or reports the older export's head as newer-than-current (a drift verdict that reads "earlier export or replayed regression — undecidable offline" rather than claiming either). Heads with no chain path between them still report honestly unbridged — only `attest consistency` against the live deployment decides those. The residual: a deployment that issues two divergent heads *between* every exported checkpoint presents chains that don't reach — unresolved, never green |
| k-of-n witness policy undermined by one rotated witness (old+new keys counting as two witnesses) | `--witness-threshold` counts distinct witness *identities*: every lineage key resolved from a `--witness-url` doc maps back to that deployment's name, so one cooperating witness's two keys still count once. Revoked lineage keys are excluded from the named requirement — a declared-suspect key can still sign but can never vouch |
| Starve or crash the watcher — serve malformed/non-object bodies, a wiped `tree_size:0` head, or unreachable witness endpoints so the monitor dies, reads green, or quietly unpins the witness's own log | Every fetch is type-guarded before use: a non-object head, issuer doc, witness pin, or consistency body fails the cycle, never the process — and a committed malformed-input corpus (`_MALFORMED*` in `tests/test_logmonitor.py`) sweeps every hostile JSON shape through `check`/`compare_views`/`live_check`/`witness_cosign` plus the pack-doc member readers (`check_cosignatures`/`check_cosig_anchors`/`check_log_pin` and their embedded-verifier twins) on every run, so a crash here is a test failure, not a production incident. Served proof fields are typed strictly — a `"5"` or `true` tree size is not the number 5 on any surface — and a signed tree head whose root decodes to anything but 32 bytes is malformed even under a valid signature. The same-bytes-same-verdict contract is engineered explicitly, not assumed: JSON-integer checks share `Number.isInteger` semantics (integral floats in, bools/strings out, Python `\d`'s Unicode digits excluded), hex fields decode contiguous-only on every surface (Python's `fromhex` whitespace leniency is an inconsistency, so it's banned), tree sizes bound at 2³¹-1 because the browser's bitwise proof arithmetic can't represent more, and parser `RecursionError`/UTF-8 failures convert to controlled cycle failures rather than watch-killers. Canonicalization is byte-parity too: `json_loads`/`parseKeep` share the strict JSON number grammar (`01`, `+5`, `5.`, `.5`, `NaN`, `Infinity` are rejected on every surface — a lenient side would hash different bytes than the signer committed), the browser canonicalizer re-derives CPython float `repr` and round-trips integers through `BigInt` so `payload_hash` never depends on which engine canonicalized, object maps are `Object.create(null)` so a `__proto__` member can't vanish from a signed dict, and base64 decoders match `atob`'s reject-anything-not-in-the-alphabet strictness (`validate=True` on every untrusted Python decode). Receipt *model* typing mirrors pydantic exactly (`_pyModelInt`/`_py_model_int` gate `revision`/`sequence` on the ASCII-digit grammar pydantic applies — no Unicode digits, no truncation of `5.5`), `issued_at` parses only inside an ISO-instant gate with aware/naive comparison parity, an attestation receipt must equal its manifest filename (`attest_receipt_<id>.json`) on every verdict surface, a signed checkpoint's embedded `extends` bridge must self-verify wherever the head is checked, served consistency docs carry `first`/`tree_size` headers pinned by integer-equality on monitor, pack, and browser paths alike, issuer-doc `key_receipts` are bounded, and unsigned rotation-pool members are inert-skipped — they can never grant trust, so malformed or foreign-signed entries can't poison an otherwise valid pack either. Key-rotation lineage walks resolve deterministically (`min(previous_key)` ancestor, highest-sequence consented descendant) because pool order is attacker-controlled — every verifier must derive the same trusted set from the same bytes. Any residual exception inside a cycle still lands in the journal as an `unverifiable` observation, so being attacked mid-cycle is itself evidence rather than a gap. A wiped or unsigned head reads healthy only on first contact — with a pin it ALERTs (a returned-to-zero log is a replaced log, not an empty one). Witness-log pins in monitor state survive outage cycles and repinning (a failed wlog check can never orphan the pin the anchor check depends on), and a witness-log contradiction journals as 'alert' with the verbatim served head embedded like any other alert. Cycles that never reached the deployment still journal — an outage is durable evidence, not a silent gap in the trail |
| A monitor catches a fork/divergence but the catch exists only as a stdout line — detection that isn't itself evidence an arbitrator can verify | `attest monitor --journal` signs every cycle into the monitor operator's own runtime as a `monitor_observation` receipt (the cycle's outcome, the served and pinned heads, and — on alert outcomes — the verbatim served doc + witness pin the contradiction lives in). `attest checkpoint --out doc.json --include monitor:` exports the trail as one self-verifying document: signed checkpoint + the embedded receipts + each one's inclusion proof + optional witness cosigs, verified offline by `attest verify doc.json` like any log doc — an alert receipt proves 'this observer was served this contradictory material at this instant', never which party lied. `monitor:*` receipts ride site packs as attestations too, so a deployment that monitors as well as serves keeps its watch on the record |
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
| Pack a zip a permissive extractor accepts but the verifier can't read identically (bzip2/lzma members Python's `zipfile` would open, ZIP64 records, or a member that decompresses past memory) | The shared verification envelope is stored/deflate only: `BoundedZip` and `readZipEntries` reject any other compression method, any ZIP64 marker (version-needed ≥ 45 or 0xFFFFFFFF sentinels), every member past 64 MiB, and 256 MiB total decompressed — a member the verifier cannot read fails the pack, it never vanishes |
| Ship a browser verifier that never parses — an escape cooked inside the Python source string (a literal `\n` inside a regex class is a `SyntaxError`) silently kills the whole script, and a dead verifier is a social-engineering asset ("offline check errored? trust it anyway") | The emitted JS is driven under Node by `tests/test_parity_r6.py` — a parse failure is a test failure before it is a shipped artifact — and `verify.html`/the sample pack are regenerated whenever `verifyjs.py` moves, pinned in sync by the suite |
| Re-send a delivered `request_id` with different bytes or signature (replay probe or upstream key drift) | The inbox refuses with no write — a legitimate retry repeats the same signature under the same id; a changed body or signature under a known id always means something is wrong |
| Forge a `key_rotation` receipt pivoting the issuer to an attacker key | Only a rotation signed by the retiring key pivots — `verify_chain` verifies the receipt under the current chain key first, so an attacker-signed rotation breaks the chain at its own position before any pivot applies |
| Graft an attacker key as a trusted issuer *predecessor* (mint "attacker key retired into the victim key") | Endorsement is self-serve, so ancestor hops additionally require a `key_adoption` receipt countersigned by the successor naming the exact rotation — the victim key never consented, so the attacker key never enters `trusted_issuer_keys` and pack verification keeps rejecting it |
| Run a second `attest serve` or offline signer against a live runtime dir (split-brain: two in-memory signers diverge, a rotate on one leaves the other signing under the retired key, and competing writes race the journal) | Every mutating command holds an exclusive advisory writer lock (`attest.lock`, OS byte-range, non-blocking) for its lifetime — a second writer fails fast naming the lock file and the recorded pid; read-only commands never take it, and the OS releases on exit or crash. The lock is advisory, not a sandbox: an attacker who can delete the file can already rewrite the store directly |
| Flood `/webhooks/ring` or the grant-link POSTs to starve the intake worker or fill the dedupe/review tables | Per-client-IP token buckets run in the outermost middleware, before a byte of the body is read — webhooks 300/min, grant links 30/min, 0 disables; the 429 is styled for household-facing surfaces and JSON for machines. Buckets are per-worker: horizontal scaling needs a shared limiter upstream (documented in `config.py`) |
| Revoke the healthy successor key from a compromised retired key, append a forged `key_revocation` that names itself the tip, or graft a self-signed revocation at sequence 0 ahead of the honest chain inside a pack's lifecycle pool | `revoked_issuer_keys`/`revokedKeys` track the in-effect issuer through consented pivots (same walk as `verify_chain`) — a revocation carries authority only when signed by the key in force at its position AND naming a key the lineage already produced. Position can never confer authority: sequence is self-asserted, so in adversarial pools (pack `key_rotations.json`, issuer-document `key_receipts`) the walk anchors at the verified issuer's lineage root instead of the pool's first receipt — a grafted foreign root or a retired-key smear is simply not the in-effect signer and is ignored |
| Compromise discovered after rotation — declare the retired key's output untrustworthy | `issue_key_revocation` signs a `key_revocation` receipt under the live issuer naming the key + `suspect_after` instant. Verifiers (server, embedded Python, JS, Lambda) annotate suspect-window record counts as a trust overlay — integrity verdicts never flip, nothing is erased, and the revocation itself is a chained receipt that travels in packs |
| Serve a forged `attest.issuer/1` document to substitute an attacker issuer pin for `--issuer-url` verification | The document is *transport-trusted*, not self-verifying — it is a discovery channel, not a signature: remote loads are HTTPS-only (loopback excepted), byte-capped, and schema-checked, and the doc's own `boundary` field states the caveat. A MITM can substitute the issuer key on a compromised channel — that is why `--key` (a fingerprint exchanged out of band) remains the zero-trust path, and the doc cannot make bad crypto pass: the `key_receipts` inside are ordinary signed receipts verified under the pinned issuer like everything else — a doc smuggling a forged pivot fails the same consented-walk checks as any pack |
| Exfiltrate key material via the public `/.well-known/attest-issuer.json` endpoint | Nothing secret is served: issuer keys are *public* verification material that travel inside every exported pack and appear on the integrity page. The endpoint exposes `issuer_key`, signed `key:*` receipts, and the chain tip — no private key, no tokens, no record bodies. It is auth-exempt by design (verification must not require the system's own credentials), and it is GET-only so it sits outside the POST rate-limit budget |
| Split the verifiers on hostile-literal envelope fields — a `sequence` spelled `"5"` or `5.0` that lax coercion accepts on one surface and not another, an integer past 2⁵³ that rounds equal under `JSON.parse` but differs exactly in Python, an ISO instant `Date.parse` reads in local time or accepts with a year-0/calendar-rollover Python rejects, or a `prev_hash` that is absent rather than explicitly null | Envelope integer fields are strict at the model layer itself — `Receipt.sequence` and `ReviewEntry.revision` accept only real JSON integers on every surface (digit strings and booleans are malformed, never coerced); the browser verifier keeps each literal's verbatim spelling so integers beyond 2⁵³ compare through BigInt with Python's arbitrary-precision semantics; ISO instants are validated against a shared ASCII-only grammar with explicit calendar bounds and naive-vs-aware instant math — no `Date.parse`, so no engine or timezone dependence; `prev_hash` distinguishes absent from explicit `null` exactly like the required-nullable model field; a review bundle's `original_receipt` anchor must be exactly `{id, hash}` so unsigned extra keys cannot ride inside a verified anchor; and a manifest listing a `visit_id`/`receipt_id` twice, as a non-string, or naming an unsafe member path fails closed everywhere |
| Forge a receipt with no private key — OpenSSL's ref10-family Ed25519 accepts non-canonical point encodings (`y ≥ p`, sign-bit-set `x = 0`) the browser's `decodePoint` rejects, and under those small-order keys the equation `S·B = R + h·A` is satisfiable with `S = 0`, `R =` identity — a whole-pack forgery that verifies on every Python surface but not in the browser | A canonicality gate (`_canonical_point`, matching `decodePoint` byte-for-byte — `y < p`, `x = 0 ⟹ sign = 0`, `S < L`) runs before OpenSSL on every native verify path, and the embedded `_point` applies the same checks: all surfaces reject the forgery vectors identically. Envelope defaults can't split verdicts either — `Receipt.id` is required (no silent mint), `signature_receipt: null` reads as absent everywhere, malformed base64 is a clean `signature invalid` rather than a crash, media digests are collected only from `payload.evidence` (a `media_sha256` nested elsewhere is inert, never a smuggle-mask or a phantom "missing"), `media_withheld` is compared against `redaction.json` even when the marker is absent (absent ≡ nothing withheld), withheld digests must be a subset of the signed evidence on every surface, manifest-vs-member compares never skip on absent fields, `attest diff` bounds the zip's *declared* size and now sha256-hashes media members like every other surface, pack-controlled map keys (`visit_id`, `revoked_key`) write only into `Object.create(null)` maps so a `__proto__` member can't read back as `Object.prototype`, lifecycle-pool sorts order sequences by verbatim-literal BigInt so `2⁵³` and `2⁵³+1` can't collide mid-walk, and the extracted-pack member sweeps fail closed on every unlisted file — non-`.json` members, plain files under `visits/`, and subdirectories included, with no marker-file precondition |

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
alone is self-serve, consent is not. Crash safety is designed the same way:
an adoption that never landed leaves the rotation inert (the chain stays
under the retiring key, later receipts still verify, and a retried rotate
can still pivot), `engine.signing_barrier()` holds the store write lock
across pivot→persist→adopt so no issuance can slip a retired-key signature
into the gap, and `resume_pending_adoptions()` at every server boot and
`rotate-key` run countersigns any unconsented pivot endorsing the current
signer — the wreckage of a crashed rotate completes instead of stranding.
What rotation does **not** prove: that either key was or stayed
uncompromised — rotation is the continuity story, not the rescue. A
compromise discovered after the fact is handled by `key_revocation` (above):
the live issuer declares the retired key's signatures suspect after a
declared instant. Both mechanisms annotate; neither erases — a revoked key's
records still verify cryptographically, they just carry the suspect flag.

Two paths need an **external anchor** to be provable: truncating the journal
before the earliest pin, and wholesale replacement of store + receipts + key
together. Anchors exist for exactly this; `--publish s3://` gives them custody
outside the deployment's control, and `--timestamp` / `attest stamp` notarize
the file's digest on public OpenTimestamps calendars — once the calendar's
Merkle root lands in a Bitcoin block, the `.ots` proof attests the anchor
*existed at that time*, verifiable by anyone with the free reference tool.
Backdating an anchor is then provable against a clock neither we nor the
deployment controls. Even the proof-upgrade path can't be redirected: pending
attestation URIs inside a `.ots` file are attacker-controlled input, so the
upgrader follows only `https://` URIs whose host ends in a trusted calendar
suffix (`opentimestamps.org`, `eternitywall.com`, `catallaxy.com`).

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
