"""Write-once FAT32 image builder with an MBR, in pure Python.

Why this exists: pyfatfs depends on PyFilesystem2, which imports
pkg_resources, removed from setuptools 84. A forensic tool should not pin a
dead shim. This builder lays out a fresh volume from a list of files: no
deletes, no rewrites, contiguous clusters, VFAT long names.

Layout: MBR at sector 0, partition 1 (type 0x0C, FAT32 LBA) at 1 MiB,
volume to the end of the image. Validated by The Sleuth Kit in tests.

shortcut: whole directory tables are built in memory; fine below ~1 million
entries, switch to streamed directory clusters above that.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .exfat import _copy_exact, upcase_key

SECTOR = 512
PART_START_LBA = 2048  # 1 MiB alignment
RESERVED_SECTORS = 32
NUM_FATS = 2
ATTR_READ_ONLY = 0x01
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F
EOC = 0x0FFFFFFF
MAX_NAME_UNITS = 195  # measured 2026-10-23: TSK 4.14 resolves 195, truncates from 196
MAX_FILE_BYTES = 4 * 1024 ** 3 - 1  # a FAT32 size field is 32 bits
# The FAT specification caps a directory at 65,536 32-byte entries (2 MiB);
# long names take several entries each. Measured 2026-10-24: without this
# check a 70,000-file folder was written as 140,003 entries, out of spec.
MAX_DIR_ENTRIES = 65536


@dataclass
class _Entry:
    long_name: str
    is_dir: bool
    size: int = 0
    source: Optional[str] = None  # host path for files
    mtime: Optional[float] = None  # stamped on the entry; None means build time
    children: List["_Entry"] = field(default_factory=list)
    first_cluster: int = 0
    short: bytes = b""
    parent: Optional["_Entry"] = None


def _dos_datetime(ts: float) -> Tuple[int, int, int]:
    try:
        t = time.localtime(ts)
    except (OSError, OverflowError, ValueError):  # Windows rejects negative times
        return (0 << 9) | (1 << 5) | 1, 0, 0
    # FAT dates span 1980 to 2107; clamp so an out-of-range source time never
    # wraps into a different, plausible-looking date.
    if t.tm_year < 1980:
        return (0 << 9) | (1 << 5) | 1, 0, 0
    if t.tm_year > 2107:
        return (127 << 9) | (12 << 5) | 31, (23 << 11) | (59 << 5) | 29, 100
    date = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    tm = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    tenth = (t.tm_sec % 2) * 100
    return date, tm, tenth


def _short_checksum(short: bytes) -> int:
    s = 0
    for c in short:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def _utf16_units(name: str) -> int:
    """Length in UTF-16 code units: what FAT long-name entries store.
    len() counts code points and undercounts emoji (found by review)."""
    return len(name.encode("utf-16-le")) // 2


def _make_short(ordinal: int, long_name: str, is_dir: bool) -> bytes:
    """Deterministic unique 8.3 name. Long names carry the real name, so the
    short form only has to be unique and valid: F0000001.JPG style."""
    ext = ""
    if not is_dir and "." in long_name:
        ext = long_name.rsplit(".", 1)[1].upper()
        ext = "".join(ch for ch in ext if ch.isascii() and ch.isalnum())[:3]
    prefix = "D" if is_dir else "F"
    base = f"{prefix}{ordinal:07d}"
    return base.encode("ascii").ljust(8, b" ") + ext.encode("ascii").ljust(3, b" ")


def _lfn_entries(long_name: str, checksum: int) -> bytes:
    """One entry per 13 UTF-16 units; a NUL terminator only when the name does
    not fill the last entry, then 0xFFFF fill (Microsoft FAT spec)."""
    name = long_name.encode("utf-16-le")
    units = _utf16_units(long_name)
    count = max(1, (units + 12) // 13)
    if units % 13:
        name += b"\x00\x00"
    name += b"\xff\xff" * (count * 13 - len(name) // 2)
    out = []
    for i in range(count - 1, -1, -1):
        seq = i + 1
        if i == count - 1:
            seq |= 0x40
        chunk = name[i * 26:(i + 1) * 26]
        out.append(bytes([seq]) + chunk[0:10] + bytes([ATTR_LFN, 0, checksum]) + chunk[10:22] + b"\x00\x00" + chunk[22:26])
    return b"".join(out)


def _dir_entry(short: bytes, attr: int, first_cluster: int, size: int, ts: float) -> bytes:
    date, tm, tenth = _dos_datetime(ts)
    return struct.pack(
        "<11sBBBHHHHHHHI",
        short, attr, 0, tenth, tm, date, date,
        (first_cluster >> 16) & 0xFFFF, tm, date, first_cluster & 0xFFFF, size,
    )


class Fat32Builder:
    """Collect files, then `build(path)` writes the complete image."""

    def __init__(self, label: str = "FRAMES", cluster_sectors: Optional[int] = None, timestamp: Optional[float] = None) -> None:
        """cluster_sectors None picks the largest cluster size that still
        yields a FAT32 cluster count from the staged bytes, so small outputs
        stay small (33 MiB floor) and large ones keep the FAT short."""
        if cluster_sectors is not None and cluster_sectors not in (1, 2, 4, 8, 16, 32, 64, 128):
            raise ValueError("cluster_sectors must be a power of two up to 128")
        self.label = label.upper()[:11]
        self._auto_cluster = cluster_sectors is None
        self.cluster_sectors = cluster_sectors or 1
        self.ts = time.time() if timestamp is None else timestamp
        self.root = _Entry("", True)
        self._dirs: Dict[str, _Entry] = {"": self.root}  # keyed by up-cased path
        self._files: Set[str] = set()                     # up-cased paths
        self._ordinal = 0
        self.total_file_bytes = 0

    # -- population ------------------------------------------------------------

    def _dir(self, rel: str) -> _Entry:
        """Directories are keyed case-insensitively, as FAT compares names:
        "A/x" and "a/y" share one folder rather than making two that a
        reader cannot tell apart (found by review of the exFAT twin)."""
        rel = rel.strip("/")
        key = upcase_key(rel)
        if key in self._dirs:
            return self._dirs[key]
        parent_rel, _, name = rel.rpartition("/")
        parent = self._dir(parent_rel)
        if upcase_key(rel) in self._files:
            raise ValueError(f"FAT32: {rel!r} is already a file")
        self._ordinal += 1
        e = _Entry(name, True, parent=parent)
        e.short = _make_short(self._ordinal, name, True)
        parent.children.append(e)
        self._dirs[key] = e
        return e

    def add_file(self, rel_path: str, source: str, mtime: Optional[float] = None) -> None:
        """rel_path uses forward slashes, relative to the volume root."""
        if not rel_path or rel_path.endswith("/"):
            raise ValueError(f"bad path {rel_path!r}")
        rel_path = rel_path.lstrip("/")
        for part in rel_path.split("/"):
            # shortcut: FAT32 allows 255 units, but The Sleuth Kit (the reader
            # that verifies this volume) truncates very long names; the
            # pipeline never writes more than about 80 units.
            # A trailing dot or space is stored but Windows tools cannot open it.
            if (part in (".", "..", "") or any(ch in part for ch in '\\:*?"<>|')
                    or any(ord(ch) < 32 for ch in part) or part[-1] in ". "
                    or _utf16_units(part) > MAX_NAME_UNITS):
                raise ValueError(f"name not allowed in FAT32: {part!r}")
        parent_rel, _, name = rel_path.rpartition("/")
        parent = self._dir(parent_rel)
        key = upcase_key(rel_path)
        if key in self._files or key in self._dirs:
            raise ValueError(f"duplicate name in FAT32 directory: {rel_path}")
        self._files.add(key)
        size = os.path.getsize(source)
        if size > MAX_FILE_BYTES:
            raise ValueError(f"{rel_path}: FAT32 files must be under 4 GiB")
        self._ordinal += 1
        e = _Entry(name, False, size=size, source=source, mtime=mtime, parent=parent)
        e.short = _make_short(self._ordinal, name, False)
        parent.children.append(e)
        self.total_file_bytes += size

    # -- geometry ----------------------------------------------------------------

    @property
    def cluster_bytes(self) -> int:
        return self.cluster_sectors * SECTOR

    def _clusters_for(self, nbytes: int) -> int:
        return max(1, (nbytes + self.cluster_bytes - 1) // self.cluster_bytes)

    def _dir_bytes(self, d: _Entry) -> int:
        """Planned table size. It is the encoder's own output length, so the
        plan cannot drift from what is written (a hand count did, by one
        entry per 13-unit name, and files vanished). Cluster numbers are not
        assigned yet at plan time, but they do not change the length."""
        return len(self._dir_table(d))

    def overfull_dirs(self) -> List[str]:
        """Paths of directories whose table would exceed MAX_DIR_ENTRIES."""
        out = []
        for d in self._walk_dirs():
            if self._dir_bytes(d) // 32 > MAX_DIR_ENTRIES:
                parts = []
                e: Optional[_Entry] = d
                while e is not None and e is not self.root:
                    parts.append(e.long_name)
                    e = e.parent
                out.append("/" + "/".join(reversed(parts)))
        return out

    def _walk_dirs(self) -> Iterator[_Entry]:
        stack = [self.root]
        while stack:
            d = stack.pop()
            yield d
            stack.extend(c for c in d.children if c.is_dir)

    def _choose_cluster(self) -> None:
        if not self._auto_cluster:
            return
        sizes = [c.size for d in self._walk_dirs() for c in d.children if not c.is_dir]
        for cs in (128, 64, 32, 16, 8, 4, 2, 1):
            self.cluster_sectors = cs
            if sum(self._clusters_for(s) for s in sizes) >= 66560:
                return
        # falls through with cluster_sectors == 1

    def plan_size(self, slack: float = 0.05) -> int:
        """Total image bytes with headroom. Deterministic for the same input."""
        self._choose_cluster()
        data_clusters = 0
        for d in self._walk_dirs():
            data_clusters += self._clusters_for(self._dir_bytes(d))
            for c in d.children:
                if not c.is_dir:
                    data_clusters += self._clusters_for(c.size)
        data_clusters = int(data_clusters * (1 + slack)) + 64
        if data_clusters < 66560:
            # Readers treat fewer than 65525 clusters as FAT16; build() solves
            # the FAT size afterwards, which costs a few clusters, so keep headroom.
            data_clusters = 66560
        fat_sectors = (data_clusters + 2) * 4
        fat_sectors = (fat_sectors + SECTOR - 1) // SECTOR
        vol_sectors = RESERVED_SECTORS + NUM_FATS * fat_sectors + data_clusters * self.cluster_sectors
        return (PART_START_LBA + vol_sectors) * SECTOR

    # -- build -------------------------------------------------------------------

    def build(self, out_path: str, progress=None) -> int:
        """Write the image. Returns image size in bytes. Refuses (ValueError)
        a directory FAT32 cannot hold rather than writing it out of spec."""
        over = self.overfull_dirs()
        if over:
            raise ValueError(f"FAT32 directory over {MAX_DIR_ENTRIES} entries: {', '.join(over)}; use exFAT")
        total = self.plan_size()
        vol_sectors = total // SECTOR - PART_START_LBA
        # Solve fat size for the chosen volume size.
        fat_sectors = 1
        while True:
            clusters = (vol_sectors - RESERVED_SECTORS - NUM_FATS * fat_sectors) // self.cluster_sectors
            need = ((clusters + 2) * 4 + SECTOR - 1) // SECTOR
            if need <= fat_sectors:
                break
            fat_sectors = need
        data_clusters = (vol_sectors - RESERVED_SECTORS - NUM_FATS * fat_sectors) // self.cluster_sectors
        if data_clusters < 65525:
            raise ValueError("volume too small for FAT32")

        # Assign clusters: root first (cluster 2), then every directory, then files.
        next_cluster = 2
        fat: List[int] = [0] * (data_clusters + 2)
        fat[0] = 0x0FFFFFF8
        fat[1] = 0x0FFFFFFF

        def alloc(n: int) -> int:
            nonlocal next_cluster
            first = next_cluster
            for i in range(n):
                c = first + i
                fat[c] = c + 1 if i < n - 1 else EOC
            next_cluster += n
            return first

        dirs = list(self._walk_dirs())
        for d in dirs:
            d.first_cluster = alloc(self._clusters_for(self._dir_bytes(d)))
        files: List[_Entry] = []
        for d in dirs:
            for c in d.children:
                if not c.is_dir:
                    # An empty file owns no cluster: first cluster 0. chkdsk
                    # rejects a zero-size entry that points at one (Windows CI,
                    # 2026-10-24: "The size of the ... entry is not valid").
                    c.first_cluster = alloc(self._clusters_for(c.size)) if c.size else 0
                    files.append(c)
        if next_cluster > data_clusters + 2:
            raise ValueError("cluster plan overflowed; plan_size slack too small")
        used = next_cluster - 2

        data_start = PART_START_LBA + RESERVED_SECTORS + NUM_FATS * fat_sectors

        with open(out_path, "wb") as fh:
            fh.truncate(total)
            fh.seek(0)
            fh.write(self._mbr(vol_sectors))
            boot = self._boot_sector(vol_sectors, fat_sectors)
            fsinfo = self._fsinfo(data_clusters - used, next_cluster)
            fh.seek(PART_START_LBA * SECTOR)
            fh.write(boot)
            fh.write(fsinfo)
            fh.seek((PART_START_LBA + 6) * SECTOR)
            fh.write(boot)
            fh.write(fsinfo)
            fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
            for i in range(NUM_FATS):
                fh.seek((PART_START_LBA + RESERVED_SECTORS + i * fat_sectors) * SECTOR)
                fh.write(fat_bytes)
            for d in dirs:
                fh.seek((data_start + (d.first_cluster - 2) * self.cluster_sectors) * SECTOR)
                fh.write(self._dir_table(d))
            done = 0
            for f in files:
                if f.size:
                    fh.seek((data_start + (f.first_cluster - 2) * self.cluster_sectors) * SECTOR)
                    assert f.source is not None
                    _copy_exact(f.source, fh, f.size)
                done += 1
                if progress:
                    progress(done, len(files))
        return total

    def _mbr(self, vol_sectors: int) -> bytes:
        mbr = bytearray(SECTOR)
        struct.pack_into("<I", mbr, 440, int(self.ts) & 0xFFFFFFFF)  # disk signature
        entry = bytes([0x00, 0xFE, 0xFF, 0xFF, 0x0C, 0xFE, 0xFF, 0xFF]) + struct.pack("<II", PART_START_LBA, vol_sectors)
        mbr[446:462] = entry
        mbr[510:512] = b"\x55\xaa"
        return bytes(mbr)

    def _boot_sector(self, vol_sectors: int, fat_sectors: int) -> bytes:
        b = bytearray(SECTOR)
        b[0:3] = b"\xeb\x58\x90"
        b[3:11] = b"MSWIN4.1"
        struct.pack_into("<HBHBHHBHHHII", b, 11,
                         SECTOR, self.cluster_sectors, RESERVED_SECTORS, NUM_FATS,
                         0, 0, 0xF8, 0, 63, 255, PART_START_LBA, vol_sectors)
        struct.pack_into("<IHHIHH", b, 36, fat_sectors, 0, 0, 2, 1, 6)
        b[64] = 0x80
        b[66] = 0x29
        struct.pack_into("<I", b, 67, (int(self.ts * 1000) & 0xFFFFFFFF) or 1)
        b[71:82] = self.label.encode("ascii", "replace").ljust(11, b" ")
        b[82:90] = b"FAT32   "
        b[510:512] = b"\x55\xaa"
        return bytes(b)

    @staticmethod
    def _fsinfo(free: int, next_free: int) -> bytes:
        s = bytearray(SECTOR)
        struct.pack_into("<I", s, 0, 0x41615252)
        struct.pack_into("<III", s, 484, 0x61417272, free, next_free)
        s[508:512] = b"\x00\x00\x55\xaa"
        return bytes(s)

    def _dir_table(self, d: _Entry) -> bytes:
        out = []
        if d is self.root:
            out.append(_dir_entry(self.label.encode("ascii", "replace").ljust(11, b" "), 0x08, 0, 0, self.ts))
        else:
            assert d.parent is not None
            out.append(_dir_entry(b".          ", ATTR_DIRECTORY, d.first_cluster, 0, self.ts))
            parent_cluster = 0 if d.parent is self.root else d.parent.first_cluster
            out.append(_dir_entry(b"..         ", ATTR_DIRECTORY, parent_cluster, 0, self.ts))
        for c in d.children:
            out.append(_lfn_entries(c.long_name, _short_checksum(c.short)))
            attr = ATTR_DIRECTORY if c.is_dir else (ATTR_ARCHIVE | ATTR_READ_ONLY)
            ts = self.ts if c.mtime is None else c.mtime
            out.append(_dir_entry(c.short, attr, c.first_cluster, 0 if c.is_dir else c.size, ts))
        out.append(b"\x00" * 32)
        return b"".join(out)
