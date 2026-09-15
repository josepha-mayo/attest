"""Content-addressed storage for snapshots pulled from Ring."""

from __future__ import annotations

import hashlib
from pathlib import Path

_EXT = {"image/jpeg": "jpg", "image/png": "png", "video/mp4": "mp4"}


class MediaStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, visit_id: str, label: str, content: bytes, content_type: str) -> tuple[str, Path]:
        if any(
            not value
            or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in value)
            for value in (visit_id, label)
        ):
            raise ValueError("invalid media identifier")
        if len(content) > 20 * 1024 * 1024:
            raise ValueError("media exceeds size limit")
        sha = hashlib.sha256(content).hexdigest()
        ext = _EXT.get(content_type.split(";")[0].strip(), "bin")
        d = self.root / visit_id
        if not d.resolve().is_relative_to(self.root):
            raise ValueError("media path escapes storage root")
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{label}.{sha[:12]}.{ext}"
        if not path.exists():
            path.write_bytes(content)
        return sha, path

    def read(self, path: str | Path) -> bytes | None:
        p = Path(path)
        if not p.is_absolute():
            p = self.root / p
        p = p.resolve()
        if not p.is_relative_to(self.root) or not p.is_file() or p.stat().st_size > 20 * 1024 * 1024:
            return None
        return p.read_bytes()

    def verify(self, path: str | Path, sha256: str) -> bool:
        data = self.read(path)
        return data is not None and hashlib.sha256(data).hexdigest() == sha256
