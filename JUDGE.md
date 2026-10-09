# Judging Attest in ten minutes

Attest replaces "he said / she said" home-service disputes with a signed,
self-verifying evidence record. This is the fastest honest path through it.

## Zero install — the hosted demo (2 minutes)

1. [Green **VERIFIED** stamp](https://josepha-mayo.github.io/attest/verify.html#sample-pack)
   — deep link; the verifier fetches the bundled pack and runs the moment the
   page opens. Everything is computed in your browser; nothing uploads.
2. [Red **FAILED** stamp](https://josepha-mayo.github.io/attest/verify.html#sample-pack-tampered)
   — same pack, but someone doctored the recorded 12-minute stay to 82. The
   signature catches it: `payload hash mismatch`.
3. **The attack gallery** — the same page offers three more one-click attacks,
   each caught by a *different* layer:
   deleted record → `missing or invalid bundle` ·
   smuggled file → `not in the signed manifest` ·
   forged always-green verifier stub → `issuer-signed pin`.
   The pack defends its own checker.
4. [Signed real-API sweep](https://josepha-mayo.github.io/attest/verify.html#live-sweep-receipt)
   — the `verify-live --sign` report from the actual `api.amazonvision.com`
   run, auto-verified in your browser on load like everything else.
5. After the green stamp, click **open index.html** — the pack carries its own
   record browser that re-verifies every record and renders the timelines.

## With the repo (8 minutes)

```bash
pip install -e .   # or see README for the pinned dev set
attest demo        # boots emulator + server + an eight-day story, prints a URL
```

- **Dashboard** → the contested visit shows the source-divergence callout and
  the worker's signed dispute — three voices (devices, worker, household) kept
  separate in the same signed chain.
- **Download `pack.zip`, unzip, open `index.html`** — every record
  self-verifies from `file://`, with a plain-language family view.
- **`attest attack-demo`** — twenty-one real tamper attempts against the store
  (forge, delete, mid-chain erase, key swap, media swap, …) — all caught, all
  rolled back.
- **`attest status`** and **`attest doctor`** — the deployment's self-audit and
  preflight.
- **`attest export --tamper-twin twin.zip --attack forged-verifier`** — mint
  your own hostile pack; the built-in self-check refuses it before it ships.

## What to read

- [THREATMODEL.md](THREATMODEL.md) — every attack path and its detection,
  including the limits (the honesty is the point).
- [FRICTIONLOG.md](FRICTIONLOG.md) — every real friction with the Ring Partner
  API hit during the build, documented for the product feedback criterion.
- `tests/vectors/` — Wycheproof-style conformance vectors all five verifier
  surfaces must judge identically.

## The honest boundary (it's a feature, not a caveat)

- A camera observation is not attendance; silence is not absence; a link click
  is not identity. The record says what each claim does and does not establish.
- A signature proves record integrity under a pinned key — not physical truth.
  That's why receipts also commit to a public-verifiable transparency log with
  witness cosignatures: even the issuer can't quietly fork its own history.
- This is a prototype: not an EVV product, not attendance verification.
