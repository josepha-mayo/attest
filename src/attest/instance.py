"""Single-instance coordination for a runtime directory.

Two attest processes writing the same data dir split-brain the deployment:
each holds its own in-memory signer (a rotate-key on one leaves the other
signing post-pivot receipts under the retired key), and long write
transactions can starve a live server's intake. The fix is a tiny advisory
lock file the writer holds for its lifetime — acquired non-blocking so a
second writer fails fast with the pid to investigate rather than silently
corrupting the chain. Read-only commands (status, journal, explain, verify,
diff) never take it, and the OS releases it on process exit or crash.
"""

from __future__ import annotations

import os
from pathlib import Path

_HELD: dict[str, int] = {}  # resolved path -> fd kept open for process life


def acquire_instance_lock(data_dir: Path) -> Path:
    """Hold the exclusive writer lock for ``data_dir`` until process exit.

    Reentrant within a process (the same lock is handed back). A second
    process — or a deliberately simulated contender holding the byte — gets a
    loud RuntimeError naming the lock file and the recorded pid.
    """
    path = data_dir / "attest.lock"
    # normcase: Windows spellings of the same dir (case, 8.3 short names) must
    # share one reentrancy key or the process "contends" with its own lock.
    key = str(path.resolve())
    if os.name == "nt":
        key = os.path.normcase(key)
    if key in _HELD:
        return path
    data_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _lock_byte(fd)
        try:
            # POSIX: the lock guards the inode, not the name — if a cleanup
            # unlinked or replaced the path between open and lock, this fd is
            # a dead file and re-opening would hand a second process a fresh
            # lock. Refuse rather than split-brain on a detached inode.
            try:
                named_ino = os.stat(path).st_ino
            except OSError:
                named_ino = None  # unlinked under us — same refusal
            if named_ino != os.fstat(fd).st_ino:
                raise RuntimeError(
                    f"lock file {path} was replaced while acquiring — "
                    "never delete attest.lock from a live data dir"
                )
            # The holder pid sits at byte 1+: byte 0 is the locked byte, and
            # a Windows byte-range lock is mandatory — a contender reading
            # offset 0 would hit ERROR_LOCK_VIOLATION and never see the pid.
            payload = b" " + f"{os.getpid()}\n".encode()
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, payload)
            os.ftruncate(fd, len(payload))
        except BaseException:
            os.close(fd)
            raise
    except OSError as exc:
        holder = ""
        try:
            os.lseek(fd, 1, os.SEEK_SET)
            holder = os.read(fd, 64).decode(errors="replace").strip()
        except OSError:
            pass
        os.close(fd)
        raise RuntimeError(
            f"another attest process holds the writer lock for {data_dir}"
            + (f" (pid {holder})" if holder else "")
            + " — stop it first, or point this process at a different data dir"
        ) from exc
    _HELD[key] = fd
    return path


def writer_held(data_dir: Path) -> tuple[bool, int | None]:
    """Probe without taking: ``(held, holder_pid_or_None)``.

    Closes its probe fd immediately — never registers in ``_HELD`` — so it is
    safe in read-only commands. The holder records its pid at byte 1+ — the
    locked byte 0 is unreadable to contenders on Windows, where byte-range
    locks are mandatory — so the pid survives on both platforms.
    """
    path = data_dir / "attest.lock"
    if not path.exists():
        return False, None
    fd = os.open(path, os.O_RDWR, 0o600)
    try:
        _lock_byte(fd)
    except OSError:
        holder = None
        try:
            os.lseek(fd, 1, os.SEEK_SET)  # byte 0 is the locked byte — skip it
            holder = int(os.read(fd, 64).decode(errors="replace").strip())
        except (OSError, ValueError):
            pass
        return True, holder
    finally:
        os.close(fd)
    return False, None


def _lock_byte(fd: int) -> None:
    """Exclusive non-blocking lock on byte 0 of ``fd``. Empty-file safe."""
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        # LK_NBLCK raises OSError immediately when the byte is held.
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
