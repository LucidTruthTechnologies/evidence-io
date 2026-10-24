"""Pick FAT32 or exFAT for a set of files and build the volume.

FAT32 is the default because every reader handles it; exFAT is used when
FAT32 cannot hold the set: a file of 4 GiB or more, or a directory over
FAT32's 65,536-entry limit. The decision and its reason are returned so the
caller can record them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional, Sequence, Tuple

from .exfat import ExfatBuilder
from .fat32 import MAX_FILE_BYTES, Fat32Builder

FILESYSTEMS = ("auto", "fat32", "exfat")
# (path in the volume, forward slashes; host source file; modified time or None)
VolumeFile = Tuple[str, str, Optional[float]]


@dataclass
class VolumeResult:
    filesystem: str   # "fat32" or "exfat"
    reason: str       # why that filesystem was used
    image_bytes: int


def choose_filesystem(files: Sequence[VolumeFile], requested: str = "auto") -> Tuple[str, str]:
    """Return (filesystem, reason). Raises ValueError when FAT32 is requested
    explicitly for a set it cannot hold."""
    if requested not in FILESYSTEMS:
        raise ValueError(f"filesystem must be one of {', '.join(FILESYSTEMS)}")
    if requested == "exfat":
        return "exfat", "requested"
    big = [rel for rel, src, _ in files if os.path.getsize(src) > MAX_FILE_BYTES]
    over = []
    if not big:
        probe = Fat32Builder()
        for rel, src, mtime in files:
            probe.add_file(rel, src, mtime=mtime)
        over = probe.overfull_dirs()
    if requested == "fat32":
        if big:
            raise ValueError(f"FAT32 cannot hold files of 4 GiB or more: {', '.join(big[:5])}")
        if over:
            raise ValueError(f"FAT32 directory over 65,536 entries: {', '.join(over[:5])}")
        return "fat32", "requested"
    if big:
        return "exfat", f"{len(big)} file(s) of 4 GiB or more"
    if over:
        return "exfat", f"{len(over)} folder(s) over FAT32's 65,536-entry limit"
    return "fat32", "everything fits FAT32"


def build_volume(files: Sequence[VolumeFile], out_path: str, filesystem: str = "auto", label: str = "EVIDENCE",
                 progress: Optional[Callable[[int, int], None]] = None) -> VolumeResult:
    """Write a partitioned raw image holding `files`. Wrap it with
    ewf_writer.write_file_as_e01 for an E01."""
    fs, reason = choose_filesystem(files, filesystem)
    builder = Fat32Builder(label=label) if fs == "fat32" else ExfatBuilder(label=label)
    for rel, src, mtime in files:
        builder.add_file(rel, src, mtime=mtime)
    size = builder.build(out_path, progress)
    return VolumeResult(fs, reason, size)
