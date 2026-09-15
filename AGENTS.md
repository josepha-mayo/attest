# Project working rules

- This is an unfinished Ring hackathon prototype, not an attendance-verification or EVV-compliant product.
- Keep Attest private until the owner authorizes publication after another data/security review. Runtime SQLite files were removed from published main history; never reintroduce them or push the old history.
- Never commit runtime data, media, private keys, access tokens, authorization codes, or personal account data. Use explicit staging paths and inspect the staged file list. Runtime folders must be ignored even when their names differ from `data/`.
- Preserve the user's local runtime data. Do not reset demo databases or keys without specific approval.
- Keep observations, scheduled expectations, worker self-reports, model output, and human conclusions separate. Observed intervals are not time worked; missing events are not proof of absence. A signature authenticates record integrity under a trusted key, not physical truth.
- Worker-wide check-in tokens are legacy data only. Authentication uses visit-scoped, hashed, expiring, single-use grants. Private routes require ATTEST_ADMIN_TOKEN; CLI access logging is disabled to avoid leaking URL tokens.
- One ingestion source is bound per site. Cross-source deduplication is not implemented; switching requires explicit reconciliation. Late events must not silently mutate signed records.
- Successful local emulator tests are not successful official Playground integration tests. No successful live AWS inference or complete Ring event/media/receipt flow has yet been verified.
- Use PowerShell syntax on this Windows workspace. Do not use bash heredocs.

## Verification

Run from this repository:

- `.\.venv\Scripts\python -m pytest -q`
- `.\.venv\Scripts\ruff check src tests`
- `.\.venv\Scripts\ruff format --check src tests`
- `git diff --check`

The sibling ring-sandbox project has the same commands in its own environment. Its pytest fixtures auto-load through a pytest11 entry point; do not also register that plugin in conftest.py.

Install both editable projects together: `.\.venv\Scripts\python -m pip install -e "../ring-sandbox[server]" -e ".[dev]"`.

Windows requires tzdata for zoneinfo. aws-login credentials require botocore[crt]. Availability of an inference profile does not imply model access or quota.

## Known follow-up work

Coordinated replay clock, review/correction workflow, deployment authentication and OAuth lifecycle, media redirect validation, retention, dependency locking/CI, official integrations, product feedback, and the submission video remain unfinished. Webhook intake now acknowledges a durable separate inbox before background processing. Tests verify restart recovery, leasing, retry limits, and separation from the visit transaction; official deadline/load validation and failed-delivery replay tooling remain pending.
