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
    # and a fresh acquirer — a different process — is told who holds it;
    # the pid sits at byte 1+ so even a Windows contender (mandatory byte
    # locks) can read it without touching the locked byte.
    monkeypatch.setattr(instance, "_HELD", {})
    with pytest.raises(RuntimeError, match=f"pid {os.getpid()}"):
        instance.acquire_instance_lock(tmp_path)


def test_writer_held_reports_the_holder_pid(tmp_path):
    assert instance.writer_held(tmp_path) == (False, None)
    instance.acquire_instance_lock(tmp_path)
    held, pid = instance.writer_held(tmp_path)
    assert held and pid == os.getpid()


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


def test_every_documented_writer_locks_and_readers_never_do():
    """AGENTS.md's single-writer contract is only as good as the wiring: a
    mutating handler that loses its acquire (a merge race, a refactor)
    silently reopens the split-brain hole. Assert the call sites by source —
    handlers that lock conditionally (--apply/--baseline/--requeue/--sign)
    still contain the call."""
    import inspect

    from attest import cli

    writers = [
        cli._serve,
        cli._demo,
        cli._anchor,
        cli._coverage_cert,
        cli._digest,
        cli._rotate_key,
        cli._revoke_key,
        cli._export,
        cli._verify_live,
        cli._attack_demo,
        cli._tamper_demo,
        cli._journal,  # --baseline re-pins journal coverage
        cli._retention,  # --apply purges
        cli._deliveries,  # --requeue rewrites delivery state
    ]
    readers = [
        cli._status,
        cli._journal,  # default path is verification-only
        cli._explain,
        cli._verify,
        cli._diff,
        cli._triage,
        cli._doctor,
        cli._cli_engine,  # shared loader — must stay lock-free (explain uses it)
    ]
    for fn in writers:
        assert "acquire_instance_lock" in inspect.getsource(fn), (
            f"{fn.__name__} mutates but never acquires the writer lock"
        )
    for fn in readers:
        src = inspect.getsource(fn)
        # _journal/--retention/--deliveries/_verify_live lock only inside the
        # mutating flag branch — that's intentional; unconditional readers
        # must never take it at all.
        if fn in (cli._journal, cli._retention, cli._deliveries, cli._verify_live):
            continue
        assert "acquire_instance_lock" not in src, (
            f"{fn.__name__} is read-only but takes the writer lock — "
            "read-only commands must run alongside a held lock"
        )
