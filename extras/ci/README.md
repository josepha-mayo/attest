# Verify evidence packs in CI — zero install

Every Attest pack embeds `verify_case.py`, a **stdlib-only** Python verifier
(no `pip install`, no network, no third-party code — pure RFC 8032 Ed25519
implemented from the spec). A CI job needs exactly two steps: unzip the pack,
run the embedded script. The verifier fails closed on tampered payloads,
missing members, smuggled files, forged signatures, and even a doctored copy
of itself — the issuer-signed `verifier_manifest.json` pins every tool's
sha256, so the pack defends against a forged always-green verifier riding
inside itself.

Copy `verify-pack.yml` into `.github/workflows/` (or translate the three
lines to your CI of choice) and point `PACK` at the artifact under review.

Set the `TAMPERED_PACK` repo variable to a deliberately-doctored twin
(`attest export --tamper-twin`) and the workflow gains a negative gate:
the twin *must* fail, so CI proves the check has teeth rather than just
printing OK.

The same gate works with the full CLI where the package is installed —
`attest verify pack.zip --json` emits `{ok, kind, detail, pinned, warnings}`
and exits non-zero on failure, so a pipeline can gate on `.ok` without
parsing prose. `attest verify pack.zip --badge badge.svg` emits a verdict
shield the job summary can render.
