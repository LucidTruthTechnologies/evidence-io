"""Open an E01 set read-only and expose it to The Sleuth Kit.

No OS-level mount: libewf reads the segment files in-process, so the
source is never opened for writing and no driver or administrator right is
involved.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List

import pyewf
import pytsk3


@dataclass
class SourceInfo:
    path: str
    segments: List[str]
    media_size: int
    bytes_per_sector: int
    stored_hashes: Dict[str, str] = field(default_factory=dict)
    header_values: Dict[str, str] = field(default_factory=dict)


class EwfImgInfo(pytsk3.Img_Info):
    """pytsk3 image backed by a pyewf handle."""

    def __init__(self, handle: "pyewf.handle") -> None:
        self._handle = handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self) -> None:  # type: ignore[override]
        self._handle.close()

    def read(self, offset: int, size: int) -> bytes:  # type: ignore[override]
        self._handle.seek(offset)
        return self._handle.read(size)

    def get_size(self) -> int:  # type: ignore[override]
        return self._handle.get_media_size()


def open_e01(path: str) -> tuple[EwfImgInfo, SourceInfo]:
    """Open the set that `path` belongs to. Raises FileNotFoundError or OSError."""
    # libewf on Windows splits only on backslash; the Tk file chooser returns
    # forward slashes, which libewf resolves as drive-relative and mangles.
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    segments = pyewf.glob(path)
    if not segments:
        raise OSError(f"no EWF segment files found for {path}")
    handle = pyewf.handle()
    handle.open(segments)  # default mode is read
    info = SourceInfo(
        path=os.path.abspath(path),
        segments=[os.path.abspath(s) for s in segments],
        media_size=handle.get_media_size(),
        bytes_per_sector=handle.get_bytes_per_sector(),
        stored_hashes=dict(handle.get_hash_values() or {}),
        header_values={k: str(v) for k, v in (handle.get_header_values() or {}).items()},
    )
    return EwfImgInfo(handle), info
