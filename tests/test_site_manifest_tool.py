"""Guard regressions use only the existing conformance corpus's fixed seeds."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attest.ledger import Signer, verify_receipt

SPEC = importlib.util.spec_from_file_location(
    "make_site_manifest", Path(__file__).resolve().parents[1] / "tools/make_site_manifest.py"
)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    docs = tmp_path / "docs"
    (docs / ".well-known").mkdir(parents=True)
    signer = Signer(Ed25519PrivateKey.from_private_bytes(b"\x11" * 32))
    (docs / "story.html").write_bytes(b"story\n")
    (docs / ".well-known/attest-issuer.json").write_text(json.dumps({"issuer_key": signer.public_key_b64}))
    artifacts = tool._iter_artifacts()
    artifacts["story.html"] = "0" * 64  # Authored fixture's deliberately stale digest.
    receipt = signer.issue(
        visit_id="site:test",
        sequence=1,
        prev_hash=None,
        facts={
            "record_type": "site_manifest",
            "origin": "https://example.invalid/",
            "artifacts": artifacts,
        },
    )
    tool.OUT.write_text(receipt.model_dump_json())
    for command in (
        ["init", "-q"],
        ["add", "docs"],
        ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
    ):
        subprocess.run(["git", *command], check=True, capture_output=True)
    return signer


def run(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["make_site_manifest.py", *args])
    tool.main()


def test_dry_run_never_loads_key(site, monkeypatch, capsys):
    monkeypatch.setattr(Signer, "load", lambda path: pytest.fail("dry run opened a key"))
    run(monkeypatch, "--dry-run")
    assert json.loads(capsys.readouterr().out)["drift"] == ["story.html"]


def test_missing_key_never_creates_identity(site, monkeypatch):
    before = tool.OUT.read_bytes()
    with pytest.raises(FileNotFoundError):
        run(monkeypatch, "--write", "--key", "missing/issuer.key")
    assert not Path("missing").exists()
    assert tool.OUT.read_bytes() == before


def test_wrong_issuer_refused(site, monkeypatch):
    other = Signer(Ed25519PrivateKey.from_private_bytes(b"\x22" * 32))
    monkeypatch.setattr(Signer, "load", lambda path: other)
    before = tool.OUT.read_bytes()
    with pytest.raises(ValueError, match="identity change"):
        run(monkeypatch, "--write", "--key", "fixture-only")
    assert tool.OUT.read_bytes() == before


@pytest.mark.parametrize("change", ["crlf", "extra", "missing"])
def test_non_deployment_bytes_refused(site, monkeypatch, change):
    if change == "crlf":
        Path("docs/story.html").write_bytes(b"story\r\n")
    elif change == "extra":
        Path("docs/extra.txt").write_text("extra")
    else:
        Path("docs/story.html").unlink()
    with pytest.raises(ValueError, match="deployment bytes"):
        run(monkeypatch, "--dry-run")


def test_existing_output_not_overwritten(site, monkeypatch):
    tool.OUT.write_bytes(tool.OUT.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        run(monkeypatch, "--write", "--key", "fixture-only")


def test_fixture_signing_and_postcheck(site, monkeypatch):
    monkeypatch.setattr(Signer, "load", lambda path: site)
    run(monkeypatch, "--write", "--key", "fixture-only")
    result = json.loads(tool.OUT.read_bytes())
    assert verify_receipt(result, public_key=site.public_key_b64)[0]
    assert result["payload"]["artifacts"] == tool._iter_artifacts()
    run(monkeypatch, "--check")


def test_stale_check_fails(site, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run(monkeypatch, "--check")
    assert exc.value.code == 1


def test_bytes_changed_during_signing_refused(site, monkeypatch):
    monkeypatch.setattr(Signer, "load", lambda path: site)
    original_issue = site.issue
    before = tool.OUT.read_bytes()

    def changed(**kwargs):
        result = original_issue(**kwargs)
        Path("docs/story.html").write_bytes(b"changed\n")
        return result

    monkeypatch.setattr(site, "issue", changed)
    with pytest.raises(ValueError, match="deployment bytes"):
        run(monkeypatch, "--write", "--key", "fixture-only")
    assert tool.OUT.read_bytes() == before


def test_invalid_generated_signature_is_not_written(site, monkeypatch):
    monkeypatch.setattr(Signer, "load", lambda path: site)
    original_issue = site.issue
    before = tool.OUT.read_bytes()

    def invalid(**kwargs):
        result = original_issue(**kwargs)
        result.signature = "AA=="
        return result

    monkeypatch.setattr(site, "issue", invalid)
    with pytest.raises(ValueError, match="regenerated manifest failed"):
        run(monkeypatch, "--write", "--key", "fixture-only")
    assert tool.OUT.read_bytes() == before


def test_tampered_manifest_check_fails(site, monkeypatch):
    result = json.loads(tool.OUT.read_bytes())
    result["payload"]["artifacts"]["story.html"] = "f" * 64
    tool.OUT.write_text(json.dumps(result))
    with pytest.raises(ValueError, match="current manifest is invalid"):
        run(monkeypatch, "--check")
