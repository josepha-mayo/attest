"""Content-addressed storage for snapshots pulled from Ring."""

from __future__ import annotations

import hashlib
from pathlib import Path

_EXT = {"image/jpeg": "jpg", "image/png": "png", "video/mp4": "mp4"}


class MediaStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, visit_id: str, label: str, content: bytes, content_type: str) -> tuple[str, Path]:
        sha = hashlib.sha256(content).hexdigest()
        ext = _EXT.get(content_type.split(";")[0].strip(), "bin")
        d = self.root / visit_id
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{label}.{sha[:12]}.{ext}"
        if not path.exists():
            path.write_bytes(content)
        return sha, path

    def read(self, path: str | Path) -> bytes | None:
        p = Path(path)
        if not p.is_absolute():
            p = self.root / p
        return p.read_bytes() if p.exists() else None

    def verify(self, path: str | Path, sha256: str) -> bool:
        data = self.read(path)
        return data is not None and hashlib.sha256(data).hexdigest() == sha256
