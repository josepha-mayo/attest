"""Single-instance writer lock: one writer per runtime dir, everyone else
fails fast — two live writers split-brain the signer and the journal."""

import os

import pytest

from attest import instance


@pytest.fixture(autouse=True)
def _release_held_locks():
    """_HELD is process-lifetime by design — tests must hand back what they
    took so tmp dirs can be deleted (Windows won't unlink an open handle)."""
    yield
    for fd in instance._HELD.values():
        os.close(fd)
    instance._HELD.clear()


def test_instance_lock_is_reentrant_in_process(tmp_path):
    path = instance.acquire_instance_lock(tmp_path)
    assert path.name == "attest.lock"
    # multi-step commands (rotate-key calls _cli_engine twice) re-enter cleanly
    assert instance.acquire_instance_lock(tmp_path) == path
    # the holder's pid is recorded for the loser to report — read through the
    # held fd, since Windows byte-range locks are mandatory for other handles
    key = str(path.resolve())
    if os.name == "nt":
        key = os.path.normcase(key)
    fd = instance._HELD[key]
    os.lseek(fd, 0, os.SEEK_SET)
    assert str(os.getpid()).encode() in os.read(fd, 64)


def test_instance_lock_contention_fails_loudly(tmp_path, monkeypatch):
    path = instance.acquire_instance_lock(tmp_path)
    # A second fd on the same byte is a second process in miniature — the OS
    # must refuse it. (flock is per-open-description; LockFile per-handle.)
    fd = os.open(path, os.O_RDWR, 0o600)
    try:
        with pytest.raises(OSError):
            instance._lock_byte(fd)
    finally:
        os.close(fd)
    # and a fresh acquirer — a different process — is told who holds it
    monkeypatch.setattr(instance, "_HELD", {})
    with pytest.raises(RuntimeError, match="writer lock"):
        instance.acquire_instance_lock(tmp_path)


def test_instance_lock_released_after_holder_exits(tmp_path):
    # Simulate holder death: take the byte on a raw fd, then drop it — the
    # next acquirer wins, exactly like a crashed process releasing on exit.
    path = tmp_path / "attest.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    instance._lock_byte(fd)
    with pytest.raises(RuntimeError, match="writer lock"):
        instance.acquire_instance_lock(tmp_path)
    os.close(fd)
    assert instance.acquire_instance_lock(tmp_path) == path
