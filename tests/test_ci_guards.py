"""Exercise the actual CI guard, including the workflow that it scans."""

import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = Path(".github/workflows/ci.yml")


@pytest.fixture
def guarded_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for path in (WORKFLOW, Path("tests/test_ci_guards.py")):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / path).read_bytes())
        subprocess.run(["git", "add", str(path)], cwd=tmp_path, check=True)
    return tmp_path


def run_private_key_guard(repo: Path) -> subprocess.CompletedProcess[str]:
    workflow = yaml.safe_load((repo / WORKFLOW).read_text(encoding="utf-8"))
    step = next(
        step
        for step in workflow["jobs"]["verify"]["steps"]
        if step.get("name") == "Reject tracked private-key material"
    )
    command = shlex.split(step["run"])
    assert command[:2] == ["python", "-c"]
    assert len(command) == 3
    return subprocess.run(
        [sys.executable, "-c", command[2]], cwd=repo, capture_output=True, text=True, check=False
    )


def test_private_key_guard_does_not_match_itself(guarded_repo: Path):
    result = run_private_key_guard(guarded_repo)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("key_type", ["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "])
def test_private_key_guard_rejects_tracked_key_headers(guarded_repo: Path, key_type: str):
    # Synthetic marker only, never a real private key or a contiguous marker in source.
    (guarded_repo / "accidental-secret.txt").write_text(
        "-----BEGIN " + key_type + "PRIVATE " + "KEY-----\nsynthetic test fixture\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "accidental-secret.txt"], cwd=guarded_repo, check=True)
    result = run_private_key_guard(guarded_repo)
    assert result.returncode != 0
    assert "private key material tracked:" in result.stderr
    assert "accidental-secret.txt" in result.stderr


def test_private_key_guard_ignores_untracked_runtime(guarded_repo: Path):
    (guarded_repo / "local-only.txt").write_text(
        "-----BEGIN PRIVATE " + "KEY-----\nsynthetic test fixture\n",
        encoding="utf-8",
    )
    result = run_private_key_guard(guarded_repo)
    assert result.returncode == 0, result.stderr
