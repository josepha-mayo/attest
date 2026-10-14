# Judging Attest

Attest replaces "he said / she said" home-service disputes with a signed,
self-verifying evidence record. This is the fastest honest path through it.

> **Sixty seconds, three links:**
> [VERIFIED](https://josepha-mayo.github.io/attest/verify.html#sample-pack) →
> [FAILED](https://josepha-mayo.github.io/attest/verify.html#sample-pack-tampered) →
> [forge it yourself](https://josepha-mayo.github.io/attest/verify.html#tamper-lab).
> Then, if you want the reflexive one:
> [verify *this hosting site*](https://josepha-mayo.github.io/attest/verify.html#verify-site)
> — the marketing page holds itself to the same evidence standard.
> Everything below is depth behind those stamps.

## Zero install — the hosted demo (≈10 minutes)

0. **[The two-minute tour](https://josepha-mayo.github.io/attest/tour.html)** —
   if you'd rather look than click: twelve self-playing beats, every frame the
   live artifact (verdicts stamp inside the iframes for real), pausable and
   keyboard-navigable. The beats the submission video follows. If you'd rather
   *read*:
   [the story the signed bytes tell](https://josepha-mayo.github.io/attest/story.html)
   — the contested visit retold entirely from the shipped pack (every quote
   deep-links to its verification), ending where the tampered twin begins.
1. [Green **VERIFIED** stamp](https://josepha-mayo.github.io/attest/verify.html#sample-pack)
   — deep link; the verifier fetches the bundled pack and runs the moment the
   page opens. Read the verdict rows: 9 records, two issuer keys linked through
   a signed rotation, **6 records annotated "signed by a revoked key inside its
   suspect window"** (6 *visit records* — the deployment's `/integrity` page
   counts 9 *receipts* in the same window, since one record's lifecycle spans
   several receipt types). Integrity holds *and* inherited doubt is reported,
   never hidden. Everything is computed in your browser; nothing uploads.
2. [Red **FAILED** stamp](https://josepha-mayo.github.io/attest/verify.html#sample-pack-tampered)
   — same pack, but someone inflated the contested visit's observed span to 135.25 minutes — past its 90-minute schedule. The
   signature catches it: `payload hash mismatch`. Then click **"name what
   changed"** under the verdict — the verifier diffs the failed bundle against
   the shipped clean pack and names the forged field itself:
   `observed_span_minutes: 65.25 → 135.25`. Detection becomes diagnosis — and
   the page still refuses to say which copy is *true*; that part is the
   dispute's job. The same field-level diff exists on the CLI:
   `attest diff docs/sample-pack.zip docs/sample-pack-tampered.zip` names
   `observed_span_minutes` — appended records are normal drift; altered or
   vanished records are flagged, and a same-size/different-root log fork is
   called a fork. `--html report.html` writes the
   [mediator-attachable version](https://josepha-mayo.github.io/attest/sample-diff-report.html)
   (shipped pre-rendered) — one verification pass, text + page + `--json`
   all render the same event stream. **Or drop two packs onto the page at once** (one click:
   [verify.html#compare-packs](https://josepha-mayo.github.io/attest/verify.html#compare-packs))
   — "the copy the agency produced" vs "the copy I kept": each verifies on its
   own merits, then their signed membership is diffed member-by-member and the
   two signed log heads are reconciled (same head, proven append-only growth
   via the embedded bridge — or a provable fork). Two packs that both verify
   and still aren't the same records is the whole point. And when the two
   packs were exported *weeks apart* — the real dispute shape — the heads
   aren't even adjacent: [verify.html#compare-earlier](https://josepha-mayo.github.io/attest/verify.html#compare-earlier)
   walks the newer pack's embedded `chain` of signed checkpoint receipts
   hop-by-hop and still proves append-only growth **offline**
   ([the written report](https://josepha-mayo.github.io/attest/sample-growth-report.html));
   `attest diff docs/sample-pack-earlier.zip docs/sample-pack.zip` is the
   same reconcile on the CLI. An older head arriving inside a *newer*
   export flips to the honest drift verdict — "earlier export or replayed
   regression, undecidable offline" — never a false green.
3. **The attack gallery** — the same page offers three more one-click attacks,
   each caught by a *different* layer:
   deleted record → `missing or invalid bundle` ·
   smuggled file → `not in the signed manifest` ·
   forged always-green verifier stub → `issuer-signed pin`.
   The pack defends its own checker. Beside the gallery,
   [pipeline.svg](https://josepha-mayo.github.io/attest/pipeline.svg) maps the
   seven verification gates — each attack pinned to the gate that kills it.
4. [Verify it *pinned*](https://josepha-mayo.github.io/attest/verify.html#sample-pack-pinned)
   — one click fetches the pack **and** the issuer doc this site serves and
   verifies the pack against a trust anchor that didn't arrive inside it.
   That's the "don't trust Attest" story made literal: the anchor comes over a
   different surface (a GitHub-Pages-hosted `.well-known` doc), and the signed
   lifecycle receipts extend that pin across the mid-history rotation.
5. [The verifier verifies itself](https://josepha-mayo.github.io/attest/verify.html#verify-self)
   — one click hashes the page's *own bytes* and compares them to the
   issuer-signed `verify.html` pin inside the bundled pack: **PINNED** means
   the hosted tool is the exact bytes the issuer pinned at export;
   **PIN MISMATCH** means the checker was swapped. It honestly discloses its
   own limit — a hostile page could rewrite the check — and names the
   stronger path (the pack's own `verify_case.py`). One click further:
   [the whole site attests itself](https://josepha-mayo.github.io/attest/verify.html#verify-site)
   — `site-manifest.json` is a signed receipt pinning every shipped artifact's
   sha256; the page verifies the manifest, then hashes all 399 files against
   it: **SITE VERIFIED** or **SITE TAMPER**, drifted files named.
6. [Signed real-API sweep](https://josepha-mayo.github.io/attest/verify.html#live-sweep-receipt)
   — the `verify-live --sign` report from the actual `api.amazonvision.com`
   run, auto-verified in your browser on load like everything else.
7. [The caught fork](https://josepha-mayo.github.io/attest/verify.html#divergence-checkpoint)
   — the split-demo evidence doc: a signed `monitor_observation` recording two
   irreconcilable signed views of one log (witness pinned one root, monitor the
   other), itself proven inside a signed tree head. The math is real; only the
   endpoints are simulated.
8. [The whole gauntlet](https://josepha-mayo.github.io/attest/verify.html#gauntlet)
   — one click verifies all nine shipped artifacts in oracle order (green
   pack, its older sibling from the pre-chain export, doctored twin, three
   attacks, real-API sweep, signed fork, Bitcoin anchor) and prints **ORACLE AGREEMENT 9/9** — every verdict landing where
   the shared oracle put it, each round's full detail under a collapsible.
9. After the green stamp, click **open index.html** — the pack carries its own
   record browser that re-verifies every record and renders the timelines.
   Scroll to `vis_70e42116a4cf` (the contested visit): the voices line flags
   that the household accounts *disagree* — a literal he-said/she-said,
   signed, never merged. One of them even carries a visible typo-correction:
   the household re-sent its statement after a garbled character, and the
   record kept **both** — corrections append, nothing rewrites. The anchors
   table maps the Cures Act's six EVV elements to what this record actually
   establishes — corroboration, not submission. Times render in *your* local
   zone; hover for the signed UTC literal.
10. **The product face, zero install**: static snapshots of the running demo —
   [the coordinator dashboard](https://josepha-mayo.github.io/attest/demo-dashboard.html),
   [the contested visit](https://josepha-mayo.github.io/attest/demo-visit.html)
   (divergence callout, signed worker dispute),
   [the household view](https://josepha-mayo.github.io/attest/demo-household.html)
   ([en español](https://josepha-mayo.github.io/attest/demo-household-es.html)),
   [the scoped family link](https://josepha-mayo.github.io/attest/demo-family.html)
   ([en español](https://josepha-mayo.github.io/attest/demo-family-es.html)) —
   exactly what a texted `/family/` token opens, including its own
   statement form (inert in the snapshot),
   [the worker's scoped review link](https://josepha-mayo.github.io/attest/demo-worker.html)
   ([en español](https://josepha-mayo.github.io/attest/demo-worker-es.html)),
   [the printable brief](https://josepha-mayo.github.io/attest/demo-visit-brief.html),
   and [the deployment's signed self-audit](https://josepha-mayo.github.io/attest/demo-integrity.html)
   (the revoked key's suspect window is annotated there — 9 receipts in scope,
   inherited doubt reported rather than erased).
   `attest verify pack.zip --badge verdict.svg` also renders verdicts as SVG shields
   (see [badge-verified.svg](https://josepha-mayo.github.io/attest/badge-verified.svg)
   — generated by the CLI, not drawn by hand).
11. **The raw layer**: [demo-receipts.html](https://josepha-mayo.github.io/attest/demo-receipts.html)
   — all 325 signed receipts of the demo deployment, drawn as the literal hash
   chain (each edge a `prev_hash` link), each row a one-click `verify.html`
   deep link — or [all 325 at once](https://josepha-mayo.github.io/attest/verify.html#demo-receipts).
   New to the math? [anatomy.html](https://josepha-mayo.github.io/attest/anatomy.html)
   decomposes any of the 325 field-by-field — what the signature covers, what
   `prev_hash` chains, and what a valid signature can never prove.
12. **The adversarial corpus**: [vectors.html](https://josepha-mayo.github.io/attest/vectors.html)
   — 42 Wycheproof-style conformance packs the shared oracle says must pass or
   fail (grammar traps: bool/string/fractional `leaf_index`, padded hex,
   2^40 tree_size; +5 more pinning vectors in the repo's tests). Each a
   `verify.html` deep link landing on the predicted verdict.
13. **The tamper lab**: [verify.html#tamper-lab](https://josepha-mayo.github.io/attest/verify.html#tamper-lab)
   — stop trusting our staged attacks and commit your own. Pick a signed field
   in the sample pack, type any value; the page rebuilds a real zip around your
   edit (byte-faithful — rewriting the field to its *own* value still passes),
   hands you the doctored pack to download, and the signature refuses it.
   The strongest kind of demo: the adversary is you.
14. **AWS, verified live**: [index.html#aws](https://josepha-mayo.github.io/attest/index.html#aws)
   — Lambda re-verifies the pack with our pinned verifier (never the pack's own
   copy — a tampered pack can't tamper with its own check), KMS envelope-encrypts
   the signing key (every unwrap a CloudTrail event), S3 holds anchors the
   deployment can't rewrite. Bedrock + Strands are wired end-to-end and label
   their fallback honestly — every record says which voice wrote it.
   And outside AWS entirely: [anchor-demo.json](https://josepha-mayo.github.io/attest/anchor-demo.json)
   is a real signed journal-head anchor sitting under a real
   [OpenTimestamps submission](https://josepha-mayo.github.io/attest/anchor-demo.json.ots)
   — "this record existed before that Bitcoin block," pending the calendar's
   commit; `attest verify docs/anchor-demo.json` re-checks it and the `.ots`
   digest sidecar.

## With the repo (8 minutes)

```bash
pip install -e .   # or see README for the pinned dev set
attest judge       # this walkthrough, in your terminal
attest demo        # boots emulator + server + an eight-day story, prints a URL
```

- **Dashboard → the contested visit** → the record shows the source-divergence
  callout (65 min between first observation and worker check-in) and the
  worker's signed dispute — three voices (devices, worker, household) kept
  separate in the same signed chain.
- **`/integrity`** → the deployment auditing itself: receipt chain, mutation
  journal, transparency head, key custody, webhook posture — each signed, and
  `/integrity.json` serves it machine-readable.
- **`?lang=es`** → household, worker, and public surfaces localize —
  accessibility is a Ring priority category.
- **Download `pack.zip`, unzip, open `index.html`** — every record
  self-verifies from `file://`, with a plain-language family view.
- **Pin the issuer out-of-band** — `docs/.well-known/attest-issuer.json` is the
  demo deployment's signed issuer doc (hosted on Pages as a downloadable —
  the well-known convention is origin-rooted, which project pages can't
  serve). `attest verify pack.zip --issuer-url docs/.well-known/attest-issuer.json`
  verifies the pack against a trust anchor that didn't come from inside it.
- **`attest tamper-demo`** — five seconds: forges a visit's state inside a
  transaction, prints `verify_journal` catching it, rolls the transaction
  back. The mutation journal's elevator pitch.
  *(Both `tamper-demo` and `attack-demo` open a store directly — they need
  `ATTEST_DATA_DIR` pointing at it and the single-writer lock free, so
  Ctrl+C the running demo first. `attest demo` prints the exact
  `$env:ATTEST_DATA_DIR=…` line to paste.)*
- **`attest attack-demo`** — twenty-one real tamper attempts against the store
  (forge, delete, mid-chain erase, key swap, media swap, forging a signed
  resolution's reason code, …); on the demo store all twenty-one are
  applicable, all caught, all rolled back. Attacks whose preconditions a
  store lacks report SKIPPED — they're never counted as catches.
- **`attest verify pack.zip --witness-url W --witness-threshold 2`** — don't
  just collect witness cosignatures: *require* k-of-n named witnesses to have
  vouched for the pack's log head. Rotated witness keys count once; a revoked
  lineage key never counts; the issuer can't vouch for itself.
- **`attest monitor <log-url> --journal`** — the auditor keeps its own signed
  trail: every watch cycle (including outages and unverifiable heads) mints a
  `monitor_observation` receipt you can export and verify. Detection that is
  itself evidence.
- **`attest status`** and **`attest doctor`** — the deployment's self-audit and
  preflight.
- **`attest export --tamper-twin twin.zip --attack forged-verifier`** — mint
  your own hostile pack; the built-in self-check refuses it before it ships.
- **`attest demo --revoke-day 6`** — replays the compromise drill live: the
  deployment rotates mid-story, the successor revokes the retired key, and its
  records stay valid but carry the suspect-window annotation — the same overlay
  the sample pack's verdict rows show.

## Scoring map — where each criterion's evidence lives

| Criterion | The evidence to look at |
|---|---|
| **Tech Implementation** | The repo *calls* Ring at runtime — signed webhooks, Event History, media+snapshots through the regional redirect, devices/capabilities, app-integrations, subscriptions, WHEP. Five AWS touchpoints (Bedrock — multimodal, snapshots re-hashed before they reach the model — Strands, KMS, S3, Lambda) — KMS/S3/Lambda verified live. The nine-artifact `#gauntlet` (ORACLE AGREEMENT 9/9) plus pinned-verify, self-verify, site-verify, per-receipt, and 42 vector deep links on the hosted verifier, 21 real attacks (all 21 caught on the demo store), conformance vectors pinning four verifier paths (server `_verify_pack`, both embedded stdlib verifiers, and the browser JS under node) to one oracle — the AWS Lambda and the pack's own `index.html` browser run the same pinned verifier bytes. `extras/ci/` is the adoption story: a zero-install workflow that verifies a pack, plus an opt-in twin gate (`vars.TAMPERED_PACK`) that requires its doctored twin to fail. |
| **Design** | Three audiences, three honest readings of one signed record: coordinator console (corroboration + coverage), worker scoped link (QR, no account), household view (plain language + family voice). Verified packs hand you their own record browser — and `story.html` + `attest diff --html` turn the same signed data into the narrative a family reads and the report a mediator attaches. |
| **Potential Impact** | Home-service disputes are a real recurring cost; Ring-track priorities named business systems + caretaking. The Appstore path is argued from the privacy posture itself: disconnect tombstones, retention, scoped links, redaction. |
| **Quality of the Idea** | The non-obvious move: don't certify presence — attest the *record*. Missing events are never absence; outages are signed explanations; even the issuer can't fork its log undetected. The honesty boundary is the product. |

**Bonuses:** [FRICTIONLOG.md](FRICTIONLOG.md) holds 17 entries in the required
schema (task → expected vs actual → severity → workaround → suggestion), and
[ring-sandbox](https://github.com/josepha-mayo/ring-sandbox) is the Open Source
mini-challenge entry — the SDK + emulator Ring doesn't ship.

## What to read

- [THREATMODEL.md](THREATMODEL.md) — every attack path and its detection,
  including the limits (the honesty is the point).
- [FRICTIONLOG.md](FRICTIONLOG.md) — every real friction with the Ring Partner
  API hit during the build, documented for the product feedback criterion.
- `tests/vectors/` — Wycheproof-style conformance vectors every CI-gated
  verifier path must judge identically.
- [SECURITY.md](SECURITY.md) — the disclosure path and scope notes.

## The honest boundary (it's a feature, not a caveat)

- A camera observation is not attendance; silence is not absence; a link click
  is not identity. The record says what each claim does and does not establish.
- A signature proves record integrity under a pinned key — not physical truth.
  That's why receipts also commit to a public-verifiable transparency log with
  witness cosignatures: even the issuer can't quietly fork its own history.
- This is a prototype: not an EVV product, not attendance verification.
