"""AWS Lambda entry point: verify an Attest pack with the project's own
stdlib-only verifier — independent of any Attest deployment.

The handler extracts the uploaded pack and runs the PINNED verifier copies
shipped beside this file (``verifier_case.py`` / ``verifier_bundle.py``,
emitted by ``attest.disputepack.write_verifiers``). The pack's own embedded
verify script is never executed — the pack supplies data, the deployment
supplies the code, and neither side has to trust the other.

Pure standard library: no layer, no boto3, no outbound calls. Deploy:

    python -c "import attest.disputepack as d; d.write_verifiers('.')"
    zip verify-lambda.zip verify_lambda.py verifier_case.py verifier_bundle.py
    aws lambda create-function --function-name attest-verify-pack \
        --runtime python3.13 --handler verify_lambda.handler \
        --zip-file fileb://verify-lambda.zip --role <exec-role-arn>

Default posture is authenticated invoke only (as deployed). For a public
endpoint — e.g. letting judges POST packs without AWS credentials — add a
function URL deliberately:

    aws lambda create-function-url-config --function-name attest-verify-pack \
        --auth-type NONE
    aws lambda add-permission --function-name attest-verify-pack \
        --action lambda:InvokeFunctionUrl --principal "*" \
        --function-url-auth-type NONE --statement-id public-url
"""

import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile

# Lambda's synchronous invoke payload is 6 MiB; a generated pack with media
# can exceed that, so larger packs should be fetched from a pre-signed URL in
# a real deployment. The bound here keeps a single request honest.
MAX_PACK_BYTES = 24 * 1024 * 1024
HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT_SECONDS = 25  # verifier is pure CPU — hashing + Ed25519


def _respond(status: int, payload: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload),
    }


def _pack_bytes(event) -> bytes:
    body = event.get("body") or b""
    if event.get("isBase64Encoded"):
        return base64.b64decode(body)
    if isinstance(body, str):
        try:
            return base64.b64decode(json.loads(body)["pack_b64"])
        except (ValueError, KeyError, TypeError):
            return body.encode()
    return body


def _safe_names(zf: zipfile.ZipFile) -> bool:
    """Reject zip-slip and absolute paths — the pack is untrusted input."""
    return all(not n.startswith(("/", "\\")) and ".." not in n.split("/") for n in zf.namelist())


def handler(event, context):
    data = _pack_bytes(event)
    if not data or len(data) > MAX_PACK_BYTES:
        return _respond(400, {"ok": False, "error": "missing or oversized pack body"})
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return _respond(400, {"ok": False, "error": "body is not a zip pack"})
    if not _safe_names(zf):
        return _respond(400, {"ok": False, "error": "unsafe paths in pack"})
    # Bound decompressed size — a small zip can expand past /tmp's 512 MiB.
    if sum(i.file_size for i in zf.infolist()) > 256 * 1024 * 1024:
        return _respond(400, {"ok": False, "error": "pack expands beyond the 256 MB bound"})
    names = set(zf.namelist())
    if "manifest.json" in names:
        script, argv = "verifier_case.py", []
    elif "bundle.json" in names:
        script, argv = "verifier_bundle.py", ["bundle.json"]
    else:
        return _respond(400, {"ok": False, "error": "zip has neither manifest.json nor bundle.json"})
    script_path = os.path.join(HERE, script)
    if not os.path.exists(script_path):
        return _respond(500, {"ok": False, "error": f"verifier {script} not deployed"})
    with tempfile.TemporaryDirectory() as d:
        zf.extractall(d)
        try:
            proc = subprocess.run(
                [sys.executable, script_path, *argv],
                cwd=d,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return _respond(200, {"ok": False, "output": "verifier timed out"})
    return _respond(
        200,
        {
            "ok": proc.returncode == 0,
            "output": (proc.stdout + proc.stderr).strip(),
            "verifier": "attest pinned stdlib verifier (the pack's own script was not run)",
        },
    )
