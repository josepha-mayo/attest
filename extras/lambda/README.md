# attest-verify-pack — AWS Lambda verifier

An independent check on Attest packs that runs **inside AWS**, on hardware and
credentials that have no access to the Attest service, database, or signing
key. A coordinator, auditor, or judge can POST a `.zip` case pack (or dispute
pack) to a function URL and get back the same verdict the local verifiers
produce — the signature chain, receipt anchors, manifest hash map, site
attestations, and media digests — without trusting us or installing anything.

## Why it matters

The pack's own embedded `verify_case.py` proves self-consistency. This Lambda
runs the project's **pinned** verifier copies against the pack's data — the
pack's embedded script is never executed. Data and code come from different
parties; a tampered pack cannot also tamper with the check.

Pure standard library — the same verifier source that ships inside every pack.
No dependency layer, no boto3, no network calls, ~1s cold start.

## Build

```powershell
# emit verifier_case.py + verifier_bundle.py next to the handler
python -c "import attest.disputepack as d; d.write_verifiers('.')"
Compress-Archive verify_lambda.py, verifier_case.py, verifier_bundle.py verify-lambda.zip
```

## Deploy

```powershell
aws lambda create-function --function-name attest-verify-pack `
  --runtime python3.13 --handler verify_lambda.handler `
  --zip-file fileb://verify-lambda.zip --role <lambda-exec-role-arn> `
  --timeout 30 --memory-size 256

aws lambda create-function-url-config --function-name attest-verify-pack --auth-type NONE
aws lambda add-permission --function-name attest-verify-pack --action lambda:InvokeFunctionUrl `
  --principal "*" --function-url-auth-type NONE --statement-id public-url
```

## Use

```powershell
curl.exe -X POST <function-url> --data-binary @case.zip -H "Content-Type: application/zip"
# {"ok": true, "output": "OK: 6 record(s) verified; ...", "verifier": "attest pinned stdlib verifier ..."}
```

`ok` is `false` on any verification failure — an altered receipt, a dropped or
extra attestation file, a manifest hash mismatch, or a media digest that does
not appear in the signed evidence. The `output` field carries the verifier's
own wording, including the boundary statement that a signature proves record
integrity under the issuer key — not identity, attendance, or absence.

## Limits (honest ones)

- Synchronous Lambda invokes cap at ~6 MiB request payloads; larger packs need
  a pre-signed-URL fetch path (not built).
- The verifier attests integrity under the issuer key. Whether you trust the
  issuer key is a separate question — the function URL response is itself
  only as trustworthy as the AWS account hosting it. For adjudication, prefer
  the fully-offline path: extract the pack and run `verify_case.py` locally.
