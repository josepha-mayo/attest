# Contributing

Attest is a hackathon prototype — issues and focused PRs are welcome. The
short version: **every verifier surface must agree on the same bytes**, so a
change to the signing, canonicalization, or verification rules is a change
to *all* of them.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt -e ".[dev]"
```

`requirements-dev.txt` is the reproducibility lock — regenerate it after a
deliberate dependency upgrade, don't hand-edit.

## Verification before a PR

```powershell
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\ruff check src tests
.\.venv\Scripts\ruff format --check src tests
git diff --check
```

Fresh checkouts pass 755 of 757 collected tests (2 platform-gated skips).
A PR that adds a verification rule without a conformance vector
(`tests/vectors/<name>/pack.zip` + `expected.json` — build one by
exporting a pack and doctoring it, then pinning the expected verdict and
the detail substring the fail must contain) will be asked for one.

## The parity contract (read this before touching crypto)

Five implementations of the same checks must stay byte-for-byte equivalent:

| Surface | File |
|---|---|
| Server checker | `src/attest/reviews.py`, `src/attest/ledger.py` |
| Embedded pack verifier | `disputepack._VERIFIER` / `_CASE_VERIFIER` |
| Browser verifier | `src/attest/verifyjs.py` → `docs/verify.html` |
| Pack's record browser | `disputepack` `index.html` JS lib (shared slice) |
| Diff/compare | `src/attest/packdiff.py` |

Canonical JSON, strict-integer rules, `prev_hash` chaining, the ISO-instant
grammar, Ed25519 strictness gates, and Merkle proof handling all have twins
in every column. If a rule moves, move it in all five — `tests/test_parity_*`
and `tests/test_conformance.py` run every surface over the same vector packs
and treat disagreement as a bug in the verifier, never in the vector.

## Generated artifacts

`docs/` is a published demo surface — the hosted verifier at
`josepha-mayo.github.io/attest/` *is* the site. After changing verifier
code or the demo store's contents, re-sync in this order:

1. `tools/make_snapshots.py` — demo pages (mints grants → receipts)
2. `tools/make_receipts_page.py` — `demo-receipts.*` + `chain.svg`
3. `attest export --redact-media --witness <w> --out docs/sample-pack.zip
   --tamper-twin docs/sample-pack-tampered.zip --tamper-visit vis_70e42116a4cf`
   (the pack embeds `verify.html` byte-for-byte — it drifts on any
   `verifyjs.py` change)
4. attack gallery: `--tamper-twin --attack {missing-record,smuggled-file,forged-verifier}`
5. `tools/make_story.py` + `attest diff docs/sample-pack.zip
   docs/sample-pack-tampered.zip --html docs/sample-diff-report.html`
   (story/diff both read the pack pair — drift on every pack regen; the diff
   exits 1 by design)
6. `attest verify docs/sample-pack.zip --badge docs/badge-verified.svg ...`
7. `attest anchor --out docs/anchor-demo.json --timestamp` (anchor + `.ots`
   together — a stale sidecar pins an old head)
8. `tools/make_site_manifest.py --key <key>` — **always last**; it pins the
   sha256 of every shipped artifact.
9. Sweep hard-coded counts (receipt total, checkpoint size, artifact count)
   across README/JUDGE/DEVPOST/docs — they drift on every export.

`tests/test_verifyjs.py` guards all of it: hosted-copy sync, manifest
freshness, pack-embedded bytes, the gauntlet oracle.

## Things that are never accepted

- Runtime data, media, private keys, tokens, personal account data — see
  `AGENTS.md` for the deliberate-artifact exceptions (sample packs, signed
  demo artifacts, generated docs).
- Claims a signature can't support. Receipts prove integrity under a key —
  never physical truth, attendance, identity, or who was right.
- Unverifiable AWS claims. If it wasn't called live, it says so (the docs
  already do — keep the honesty).

## Where to start

`attest judge` prints the self-guided judge path; `JUDGE.md` maps every
claim to its artifact; `THREATMODEL.md` lists what the design deliberately
doesn't defend.
