"""Deployment preflight: `doctor` grades configuration posture, never the
store — fail exits 1 for CI gates, warn deploys with caveats, info is context."""

import json
import os

import pytest
from pydantic import SecretStr

from attest import cli, instance


@pytest.fixture()
def doctor_env(tmp_path, monkeypatch):
    """A plausible deployment posture: token + webhook key + writable dir."""
    monkeypatch.setattr(cli.settings, "admin_token", SecretStr("t" * 32))
    monkeypatch.setattr(cli.settings, "ring_webhook_key", "k" * 32)
    monkeypatch.setattr(cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(cli.settings, "signing_key_path", tmp_path / "attest-ed25519.key")
    monkeypatch.setattr(cli.settings, "replay_mode", False)
    monkeypatch.setattr(cli.settings, "kms_key_id", None)
    monkeypatch.setattr(cli.settings, "key_custody", None)
    return tmp_path


def _run(args_json=False):
    try:
        cli._doctor(__import__("argparse").Namespace(json=args_json))
    except SystemExit as exc:
        return exc.code or 0
    return 0


def test_doctor_passes_a_deployment_posture(doctor_env, capsys):
    cli.settings.key_path.touch()  # an existing plaintext PEM — warn, not fail
    assert _run() == 0
    out = capsys.readouterr().out
    assert "FAIL" not in out
    # plaintext key on disk is a warn — deployable, improvable
    assert "plaintext PEM" in out


def test_doctor_fails_without_admin_token(doctor_env, monkeypatch, capsys):
    monkeypatch.setattr(cli.settings, "admin_token", None)
    assert _run() == 1
    assert "admin token" in capsys.readouterr().out


def test_doctor_fails_on_replay_mode(doctor_env, monkeypatch, capsys):
    monkeypatch.setattr(cli.settings, "replay_mode", True)
    assert _run() == 1
    assert "replay" in capsys.readouterr().out


def test_doctor_fails_on_stray_custody_artifact(doctor_env, capsys):
    # A wrapped-key artifact with no matching config strands the issuer —
    # doctor surfaces the same loud refusal the loader enforces.
    key_path = cli.settings.key_path
    (key_path.parent / (key_path.name + ".kms.json")).write_text("{}")
    assert _run() == 1
    assert "custody" in capsys.readouterr().out


def test_doctor_reports_a_held_writer_lock(doctor_env, capsys):
    instance.acquire_instance_lock(doctor_env)
    # Doctor is read-only: it reports the lock's holder without needing it.
    # The holder pid sits at byte 1+ — deliberately outside the locked byte —
    # so a contender can always read who owns the runtime, even on Windows.
    assert _run() == 0
    out = capsys.readouterr().out
    assert "writer lock" in out and str(os.getpid()) in out
    # Held fds are process-lifetime by design — release this test's so the
    # tmp dir can be deleted (Windows won't unlink under an open handle).
    fd = instance._HELD.popitem()[1]
    os.close(fd)


def test_doctor_json_is_machine_readable(doctor_env, capsys):
    assert _run(args_json=True) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is True
    assert {c["level"] for c in payload["checks"]} >= {"ok", "warn"}
