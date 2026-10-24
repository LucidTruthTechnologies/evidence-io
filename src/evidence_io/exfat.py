"""Write-once exFAT image builder with an MBR, in pure Python.

Why this exists: FAT32 cannot hold a file of 4 GiB or more, nor a directory
of more than 65,536 entries. exFAT has neither limit in practice and every
current Windows reads it natively. Same interface as fat32.Fat32Builder:
collect files, then `build(path)` writes the complete image.

Layout follows the Microsoft exFAT specification (2019): MBR at sector 0,
partition 1 (type 0x07) at 1 MiB; inside the volume the main and backup boot
regions (12 sectors each, with the boot checksum sector), one FAT, then the
cluster heap holding the allocation bitmap, the specification's recommended
up-case table (Table 25, compressed), the root directory, every other
directory, and the files, all contiguous and all with FAT chains
(NoFatChain is never set, so every reader can follow them). Times are
stored in UTC with the UTC-offset field marked valid. The volume is never
smaller than the specification's 1 MiB minimum.

shortcut: whole directory tables and the FAT are built in memory; fine for
millions of files, stream them if a volume ever needs more.
"""

from __future__ import annotations

import datetime as dt
import math
import os
import struct
import sys
import time
from array import array
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from ._upcase_table import RECOMMENDED_UPCASE

SECTOR = 512
SECTOR_SHIFT = 9
PART_START_LBA = 2048  # 1 MiB alignment, as in fat32
FAT_OFFSET = 128       # sectors from volume start; the spec requires at least 24
MIN_VOLUME_SECTORS = 2048  # spec 3.1.5: VolumeLength at least 1 MiB
MAX_MBR_SECTORS = 0xFFFFFFFF  # an MBR partition cannot describe more (2 TiB)
ATTR_READ_ONLY = 0x01
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
EOC = 0xFFFFFFFF
MAX_NAME_UNITS = 255
MAX_LABEL_UNITS = 11
MAX_DIR_BYTES = 256 * 1024 ** 2  # the spec's directory size limit
COPY_BLOCK = 1024 * 1024
_BAD_NAME_CHARS = set('"*/:<>?\\|')
UPCASE_CHECKSUM = 0xE619D30D  # stated in the spec for Table 25


@dataclass
class _Entry:
    name: str
    is_dir: bool
    size: int = 0
    source: Optional[str] = None
    mtime: Optional[float] = None
    children: List["_Entry"] = field(default_factory=list)
    by_key: Dict[str, "_Entry"] = field(default_factory=dict)  # up-cased name -> child
    first_cluster: int = 0
    data_len: int = 0  # bytes allocated to a directory (whole clusters)
    parent: Optional["_Entry"] = None


def _rotate32(c: int, b: int) -> int:
    return ((((c & 1) << 31) | (c >> 1)) + b) & 0xFFFFFFFF


def _rotate16(c: int, b: int) -> int:
    return ((((c & 1) << 15) | (c >> 1)) + b) & 0xFFFF


def boot_checksum(region: bytes) -> int:
    """Checksum of boot sectors 0-10, skipping VolumeFlags and PercentInUse."""
    c = 0
    for i, b in enumerate(region):
        if i in (106, 107, 112):
            continue
        c = _rotate32(c, b)
    return c


def table_checksum(data: bytes) -> int:
    c = 0
    for b in data:
        c = _rotate32(c, b)
    return c


def entry_set_checksum(raw: bytes) -> int:
    c = 0
    for i, b in enumerate(raw):
        if i in (2, 3):
            continue
        c = _rotate16(c, b)
    return c


def upcase_bytes() -> bytes:
    """The compressed table exactly as stored on the volume."""
    a = array("H", RECOMMENDED_UPCASE)
    if sys.byteorder != "little":
        a.byteswap()
    return a.tobytes()


def _expand(compressed: Tuple[int, ...]) -> array:
    """Decompress per spec 7.2.5.1: FFFFh followed by N means the next N
    code units map to themselves; units past the table map to themselves."""
    table = array("H", range(65536))
    i = pos = 0
    while pos < len(compressed):
        v = compressed[pos]
        if v == 0xFFFF and pos + 1 < len(compressed):
            i += compressed[pos + 1]
            pos += 2
            continue
        table[i] = v
        i += 1
        pos += 1
    return table


_UPCASE: Optional[array] = None


def upcase_table() -> array:
    global _UPCASE
    if _UPCASE is None:
        _UPCASE = _expand(RECOMMENDED_UPCASE)
    return _UPCASE


def _units(name: str) -> array:
    units = array("H")
    units.frombytes(name.encode("utf-16-le", "surrogatepass"))
    if sys.byteorder != "little":
        units.byteswap()
    return units


def upcase_key(name: str) -> str:
    """The name as the volume compares it: every UTF-16 unit through the
    volume's up-case table (not Python's str.upper, which expands some
    characters, such as the sharp s, into two)."""
    table = upcase_table()
    up = array("H", (table[u] for u in _units(name)))
    if sys.byteorder != "little":
        up.byteswap()
    return up.tobytes().decode("utf-16-le", "surrogatepass")


def name_hash(name: str) -> int:
    table = upcase_table()
    c = 0
    for u in _units(name):
        up = table[u]
        c = _rotate16(c, up & 0xFF)
        c = _rotate16(c, up >> 8)
    return c


def _clamped_utc(ts: float) -> dt.datetime:
    lo = dt.datetime(1980, 1, 1, tzinfo=dt.timezone.utc)
    hi = dt.datetime(2107, 12, 31, 23, 59, 59, tzinfo=dt.timezone.utc)
    try:
        t = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return hi if ts > 0 else lo
    return lo if t < lo else hi if t > hi else t


def _timestamp(ts: float) -> Tuple[int, int, int]:
    """(packed timestamp, 10 ms increment, UTC offset byte) in UTC,
    clamped to the representable 1980..2107 range."""
    t = _clamped_utc(ts)
    stamp = ((t.year - 1980) << 25) | (t.month << 21) | (t.day << 16) | (t.hour << 11) | (t.minute << 5) | (t.second // 2)
    ten_ms = (t.second % 2) * 100 + t.microsecond // 10000
    return stamp, ten_ms, 0x80  # OffsetValid, offset 0: the stamp is UTC


def entry_set(name: str, attr: int, first_cluster: int, data_len: int, ts: float) -> bytes:
    """File directory entry, stream extension entry and file name entries."""
    units = name.encode("utf-16-le", "surrogatepass")
    n_units = len(units) // 2
    n_names = (n_units + 14) // 15
    file_e = bytearray(32)
    file_e[0] = 0x85
    file_e[1] = 1 + n_names
    struct.pack_into("<H", file_e, 4, attr)
    stamp, ten_ms, off = _timestamp(ts)
    struct.pack_into("<III", file_e, 8, stamp, stamp, stamp)
    file_e[20] = ten_ms
    file_e[21] = ten_ms
    file_e[22] = file_e[23] = file_e[24] = off
    stream = bytearray(32)
    stream[0] = 0xC0
    stream[1] = 0x01  # AllocationPossible; NoFatChain clear
    stream[3] = n_units
    struct.pack_into("<H", stream, 4, name_hash(name))
    struct.pack_into("<Q", stream, 8, data_len)  # ValidDataLength
    struct.pack_into("<IQ", stream, 20, first_cluster if data_len else 0, data_len)
    names = bytearray()
    for k in range(n_names):
        e = bytearray(32)
        e[0] = 0xC1
        chunk = units[k * 30:(k + 1) * 30]
        e[2:2 + len(chunk)] = chunk
        names += e
    raw = bytearray(file_e + stream + names)
    struct.pack_into("<H", raw, 2, entry_set_checksum(bytes(raw)))
    return bytes(raw)


def check_name(part: str, what: str = "name", limit: int = MAX_NAME_UNITS) -> None:
    """Spec 7.7.3 file name rules, plus Windows' refusal of a trailing dot or
    space (exFAT stores such a name, but Windows tools cannot open it)."""
    if (part in (".", "..", "") or any(ch in _BAD_NAME_CHARS or ord(ch) < 32 for ch in part)
            or part[-1] in ". " or len(part.encode("utf-16-le", "surrogatepass")) // 2 > limit):
        raise ValueError(f"{what} not allowed in exFAT: {part!r}")


class ExfatBuilder:
    """Collect files, then `build(path)` writes the complete image."""

    def __init__(self, label: str = "EVIDENCE", timestamp: Optional[float] = None) -> None:
        if label:
            check_name(label, "volume label", MAX_LABEL_UNITS)
        self.label = label
        self.ts = time.time() if timestamp is None else timestamp
        self.root = _Entry("", True)
        self.total_file_bytes = 0
        self.cluster_sectors = 8

    # -- population ------------------------------------------------------------

    def _child_dir(self, parent: _Entry, name: str) -> _Entry:
        key = upcase_key(name)
        existing = parent.by_key.get(key)
        if existing is not None:
            if not existing.is_dir:
                raise ValueError(f"exFAT: {name!r} is already a file in this directory")
            return existing  # same folder whatever the case of this mention
        e = _Entry(name, True, parent=parent)
        parent.children.append(e)
        parent.by_key[key] = e
        return e

    def add_file(self, rel_path: str, source: str, mtime: Optional[float] = None) -> None:
        """rel_path uses forward slashes, relative to the volume root."""
        if not rel_path or rel_path.endswith("/"):
            raise ValueError(f"bad path {rel_path!r}")
        parts = rel_path.lstrip("/").split("/")
        for part in parts:
            check_name(part)
        parent = self.root
        for part in parts[:-1]:
            parent = self._child_dir(parent, part)
        name = parts[-1]
        key = upcase_key(name)
        if key in parent.by_key:
            raise ValueError(f"duplicate name in exFAT directory: {rel_path}")
        size = os.path.getsize(source)
        e = _Entry(name, False, size=size, source=source, mtime=mtime, parent=parent)
        parent.children.append(e)
        parent.by_key[key] = e
        self.total_file_bytes += size

    # -- geometry ----------------------------------------------------------------

    @property
    def cluster_bytes(self) -> int:
        return self.cluster_sectors * SECTOR

    def _clusters_for(self, nbytes: int) -> int:
        return max(1, -(-nbytes // self.cluster_bytes)) if nbytes else 0

    def _walk_dirs(self) -> Iterator[_Entry]:
        stack = [self.root]
        while stack:
            d = stack.pop()
            yield d
            stack.extend(c for c in d.children if c.is_dir)

    def _choose_cluster(self) -> None:
        # Windows' own defaults: 4 KiB to 256 MiB, 32 KiB to 32 GiB, 128 KiB above.
        if self.total_file_bytes < 256 * 1024 ** 2:
            self.cluster_sectors = 8
        elif self.total_file_bytes < 32 * 1024 ** 3:
            self.cluster_sectors = 64
        else:
            self.cluster_sectors = 256

    def _dir_table(self, d: _Entry, extra: bytes = b"") -> bytes:
        out = [extra]
        for c in d.children:
            if c.is_dir:
                out.append(entry_set(c.name, ATTR_DIRECTORY, c.first_cluster, c.data_len, self.ts))
            else:
                ts = self.ts if c.mtime is None else c.mtime
                out.append(entry_set(c.name, ATTR_ARCHIVE | ATTR_READ_ONLY, c.first_cluster, c.size, ts))
        return b"".join(out)

    def _dir_need(self, d: _Entry) -> int:
        """Bytes a directory needs: its entry sets, the root's three system
        entries, and one spare entry so an end-of-directory marker always fits."""
        return len(self._dir_table(d)) + (96 if d is self.root else 0) + 32

    def _root_prefix(self, bitmap_cluster: int, bitmap_len: int, up_cluster: int, up_len: int,
                     up_checksum: int) -> bytes:
        label = bytearray(32)
        label[0] = 0x83
        units = self.label.encode("utf-16-le", "surrogatepass")
        label[1] = len(units) // 2
        label[2:2 + len(units)] = units
        bitmap = bytearray(32)
        bitmap[0] = 0x81
        struct.pack_into("<IQ", bitmap, 20, bitmap_cluster, bitmap_len)
        up = bytearray(32)
        up[0] = 0x82
        struct.pack_into("<I", up, 4, up_checksum)
        struct.pack_into("<IQ", up, 20, up_cluster, up_len)
        return bytes(label + bitmap + up)

    def oversize_dirs(self) -> List[str]:
        return [d.name or "/" for d in self._walk_dirs() if self._dir_need(d) > MAX_DIR_BYTES]

    # -- build -------------------------------------------------------------------

    def build(self, out_path: str, progress=None) -> int:
        """Write the image. Returns image size in bytes."""
        over = self.oversize_dirs()
        if over:
            raise ValueError(f"exFAT directory over {MAX_DIR_BYTES} bytes: {', '.join(over)}")
        self._choose_cluster()
        up_bytes = upcase_bytes()
        up_checksum = table_checksum(up_bytes)
        dirs = list(self._walk_dirs())
        files = [c for d in dirs for c in d.children if not c.is_dir]

        # Directory sizes do not depend on cluster numbers, so size them first.
        for d in dirs:
            d.data_len = self._clusters_for(self._dir_need(d)) * self.cluster_bytes
        data_clusters = (sum(self._clusters_for(d.data_len) for d in dirs)
                         + sum(self._clusters_for(f.size) for f in files)
                         + self._clusters_for(len(up_bytes)))
        cluster_count = data_clusters + 16
        while True:
            # The bitmap's own size depends on the cluster count, and the FAT
            # length and heap offset depend on it too; the volume must also
            # reach the 1 MiB minimum.
            bitmap_len = (cluster_count + 7) // 8
            fat_len = -(-((cluster_count + 2) * 4) // SECTOR)
            heap_offset = -(-(FAT_OFFSET + fat_len) // self.cluster_sectors) * self.cluster_sectors
            need = data_clusters + self._clusters_for(bitmap_len) + 16
            short = MIN_VOLUME_SECTORS - (heap_offset + cluster_count * self.cluster_sectors)
            if short > 0:
                need = max(need, cluster_count + -(-short // self.cluster_sectors))
            if need <= cluster_count:
                break
            cluster_count = need
        if cluster_count > 0xFFFFFFF5:
            raise ValueError("too many clusters for exFAT")
        vol_sectors = heap_offset + cluster_count * self.cluster_sectors
        if vol_sectors > MAX_MBR_SECTORS:
            raise ValueError("volume over 2 TiB: an MBR partition cannot describe it")
        total = (PART_START_LBA + vol_sectors) * SECTOR

        fat = array("I", [0]) * (cluster_count + 2)
        fat[0] = 0xFFFFFFF8
        fat[1] = 0xFFFFFFFF
        next_cluster = 2

        def alloc(nbytes: int) -> int:
            nonlocal next_cluster
            n = self._clusters_for(nbytes)
            if n == 0:
                return 0
            first = next_cluster
            for i in range(n):
                c = first + i
                fat[c] = c + 1 if i < n - 1 else EOC
            next_cluster += n
            return first

        bitmap_cluster = alloc(bitmap_len)
        up_cluster = alloc(len(up_bytes))
        for d in dirs:  # root first: _walk_dirs yields it first
            d.first_cluster = alloc(d.data_len)
        for f in files:
            f.first_cluster = alloc(f.size)
        used = next_cluster - 2
        if used > cluster_count:
            raise ValueError("cluster plan overflowed")

        bitmap = bytearray(bitmap_len)
        for i in range(used):
            bitmap[i >> 3] |= 1 << (i & 7)

        vol_start = PART_START_LBA * SECTOR
        heap_start = vol_start + heap_offset * SECTOR

        def at(cluster: int) -> int:
            return heap_start + (cluster - 2) * self.cluster_bytes

        boot = self._boot_region(vol_sectors, fat_len, heap_offset, cluster_count, self.root.first_cluster,
                                 used * 100 // cluster_count)
        fat_bytes = fat.tobytes() if sys.byteorder == "little" else _swapped32(fat)
        with open(out_path, "wb") as fh:
            fh.truncate(total)
            fh.seek(0)
            fh.write(self._mbr(vol_sectors))
            fh.seek(vol_start)
            fh.write(boot)
            fh.write(boot)  # backup boot region
            fh.seek(vol_start + FAT_OFFSET * SECTOR)
            fh.write(fat_bytes)
            fh.seek(at(bitmap_cluster))
            fh.write(bitmap)
            fh.seek(at(up_cluster))
            fh.write(up_bytes)
            for d in dirs:
                prefix = self._root_prefix(bitmap_cluster, bitmap_len, up_cluster, len(up_bytes),
                                           up_checksum) if d is self.root else b""
                fh.seek(at(d.first_cluster))
                fh.write(self._dir_table(d, prefix))
            for done, f in enumerate(files, start=1):
                if f.size:
                    fh.seek(at(f.first_cluster))
                    assert f.source is not None
                    _copy_exact(f.source, fh, f.size)
                if progress:
                    progress(done, len(files))
        return total

    def _boot_region(self, vol_sectors: int, fat_len: int, heap_offset: int, cluster_count: int,
                     root_cluster: int, percent: int) -> bytes:
        b = bytearray(SECTOR)
        b[0:3] = b"\xeb\x76\x90"
        b[3:11] = b"EXFAT   "
        struct.pack_into("<QQIIIIIIHHBBBBB", b, 64,
                         PART_START_LBA, vol_sectors, FAT_OFFSET, fat_len, heap_offset, cluster_count,
                         root_cluster, (int(self.ts * 1000) & 0xFFFFFFFF) or 1,
                         0x0100, 0, SECTOR_SHIFT, int(math.log2(self.cluster_sectors)), 1, 0x80, percent)
        b[120:510] = b"\xf4" * 390
        b[510:512] = b"\x55\xaa"
        ext = (b"\x00" * (SECTOR - 4) + b"\x00\x00\x55\xaa") * 8
        region = bytes(b) + ext + b"\x00" * SECTOR * 2  # OEM parameters and reserved sectors
        checksum = struct.pack("<I", boot_checksum(region)) * (SECTOR // 4)
        return region + checksum

    def _mbr(self, vol_sectors: int) -> bytes:
        mbr = bytearray(SECTOR)
        struct.pack_into("<I", mbr, 440, int(self.ts) & 0xFFFFFFFF)  # disk signature
        entry = bytes([0x00, 0xFE, 0xFF, 0xFF, 0x07, 0xFE, 0xFF, 0xFF]) + struct.pack("<II", PART_START_LBA, vol_sectors)
        mbr[446:462] = entry
        mbr[510:512] = b"\x55\xaa"
        return bytes(mbr)


def _copy_exact(source: str, fh, size: int) -> None:
    """Copy exactly `size` bytes, the size the layout was planned with. A
    source that shrank or grew since add_file would otherwise overrun the
    next file's clusters or leave a zero-filled tail (found by review)."""
    left = size
    with open(source, "rb") as src:
        while left:
            block = src.read(min(COPY_BLOCK, left))
            if not block:
                raise ValueError(f"{source} shrank after it was added ({size - left} of {size} bytes)")
            fh.write(block)
            left -= len(block)
        if src.read(1):
            raise ValueError(f"{source} grew after it was added (planned {size} bytes)")


def _swapped32(a: array) -> bytes:
    b = array("I", a)
    b.byteswap()
    return b.tobytes()
