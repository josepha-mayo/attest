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
    key = str(path.resolve())
    if key in _HELD:
        return path
    data_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _lock_byte(fd)
    except OSError as exc:
        holder = ""
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            holder = os.read(fd, 64).decode(errors="replace").strip()
        except OSError:
            pass
        os.close(fd)
        raise RuntimeError(
            f"another attest process holds the writer lock for {data_dir}"
            + (f" (pid {holder})" if holder else "")
            + " — stop it first, or point this process at a different data dir"
        ) from exc
    payload = f"{os.getpid()}\n".encode()
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, payload)
    os.ftruncate(fd, len(payload))
    _HELD[key] = fd
    return path


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
