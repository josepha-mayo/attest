# Verifier conformance vectors

Fixed evidence packs that every Attest verifier must judge identically —
the same discipline Wycheproof vectors bring to crypto implementations.
`pack.zip` is real exported evidence; `expected.json` is the shared oracle:

- `kind`: `bundle` (single-visit dispute pack) or `case` (site case pack)
- `pin`: `"declared"` (self-consistency under the pack's own issuer) or an
  explicit base64 Ed25519 public key — pinning the retired key exercises
  the rotation lineage
- `verdict`: `ok` or `fail` — integrity verdicts are identical everywhere
- `detail_contains`: fragments the human-readable detail must carry
- `js`: browser-lib expectations when the check is algorithm-level —
  `bundle_ok`, `trusted_count` (issuer lineage width), `suspect_count`
  (records inside a revoked key's suspect window)

Regenerate with `tools/make_vectors.py` when the pack format changes —
never hand-edit the zips. The vectors are the contract: a verifier that
disagrees with `expected.json` is wrong, whatever surface it runs on.
