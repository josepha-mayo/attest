# Security policy

Attest's security model — and its explicit boundaries — are documented in
[THREATMODEL.md](THREATMODEL.md). The short version: receipts prove record
integrity under a pinned issuer key; they do not prove identity, attendance,
or physical truth, and the threat model names what the design does not
cover rather than papering over it.

## Reporting a vulnerability

This is a hackathon-stage private project. Report suspected issues via a
private channel to the maintainer (GitHub private vulnerability reporting or
direct contact), not in a public issue — the repo's records may describe a
real deployment's evidence pipeline.

Please include: the surface (Python verifier, browser verifier, server,
embedded pack tooling), a minimal reproduction or crafted artifact, and
which guarantee you believe is violated (integrity, pin, provenance,
confidentiality).

## Scope notes

- Runtime data (SQLite stores, media, private keys, tokens) is never
  committed — see `AGENTS.md` for the deliberate-artifact exceptions.
- The embedded browser verifier is dependency-free by design; dependency
  CVEs cannot reach it.
- `docs/` artifacts are simulated data with signed digests — real secrets
  are never present, but if you find one, that's a reportable bug.
