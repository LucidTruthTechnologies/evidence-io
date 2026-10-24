"""Walk every filesystem inside an opened image with The Sleuth Kit.

One walker for every tool: it yields every regular file (deleted ones on
request) with its original times and the flags an examiner needs, and the
caller decides what to keep. Nothing here writes to the image.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Set

import pytsk3

from .hashing import Hashes, hash_stream

COPY_BLOCK = 4 * 1024 * 1024
_TSK_EXFAT_SYSTEM = {"$ALLOC_BITMAP", "$UPCASE_TABLE"}
Log = Callable[[str], None]
Cancel = Callable[[], bool]


@dataclass
class PartitionInfo:
    index: int
    description: str
    start_sector: int
    length_sectors: int
    fs_type: str         # filesystem name, or "unreadable: <reason>"


@dataclass
class ImageFile:
    path: str            # inside the filesystem, forward slashes, no leading slash
    name: str
    size: int
    inode: int
    allocated: bool
    realloc: bool        # deleted name whose metadata now belongs to another file: never read it
    mtime: Optional[float]
    atime: Optional[float]
    ctime: Optional[float]   # metadata change time where the filesystem keeps one
    crtime: Optional[float]  # creation time where the filesystem keeps one
    fs_type: str             # e.g. "fat32" (local-time stamps) or "ntfs" (UTC)
    fs: pytsk3.FS_Info = field(repr=False)

    def open(self) -> "InodeReader":
        """Read the file in memory; nothing is written to disk."""
        return open_inode(self.fs, self.inode, self.size)

    def read(self, offset: int, n: int) -> bytes:
        return self.open().read(offset, n)

    def copy_to(self, dest: str, exclusive: bool = True) -> Hashes:
        return copy_inode(self.fs, self.inode, self.size, dest, exclusive)


class InodeReader:
    """Random and sequential reads of one file inside the image, in memory."""

    def __init__(self, fs: pytsk3.FS_Info, inode: int, size: int) -> None:
        self._f = fs.open_meta(inode=inode)
        self.size = size

    def read(self, offset: int, n: int) -> bytes:
        n = min(n, self.size - offset)
        return self._f.read_random(offset, n) if n > 0 else b""

    def iter_chunks(self, block: int = COPY_BLOCK) -> Iterator[bytes]:
        """Successive blocks from offset 0. Stops early, without padding, at
        an unreadable run; compare the bytes hashed with `size`."""
        pos = 0
        while pos < self.size:
            try:
                chunk = self._f.read_random(pos, min(block, self.size - pos))
            except OSError:
                return
            if not chunk:
                return
            yield chunk
            pos += len(chunk)


def open_inode(fs: pytsk3.FS_Info, inode: int, size: int) -> InodeReader:
    return InodeReader(fs, inode, size)


def _fs_type_names() -> dict:
    enum = pytsk3.TSK_FS_TYPE_ENUM
    names = {}
    for n in dir(enum):
        if n.startswith("TSK_FS_TYPE_") and "DETECT" not in n:
            try:
                names.setdefault(int(getattr(enum, n)), n[len("TSK_FS_TYPE_"):].lower())
            except (TypeError, ValueError):
                continue
    return names


_FS_TYPE_NAMES = _fs_type_names()


def fs_type_name(fs: pytsk3.FS_Info) -> str:
    """"fat32", "exfat", "ntfs" and so on. str() of the enum yields a bare
    number in pytsk3 20260715, so the name is looked up (found 2026-10-24)."""
    code = int(fs.info.ftype)
    return _FS_TYPE_NAMES.get(code, f"type-{code}")


def iter_filesystems(img: pytsk3.Img_Info, log: Log,
                     inventory: Optional[List[PartitionInfo]] = None) -> Iterator[tuple[int, int, pytsk3.FS_Info]]:
    """Yield (partition index, byte offset, FS_Info) for every readable
    filesystem. When `inventory` is given, every allocated partition is
    recorded there, readable or not.
    shortcut: no pool layer (pytsk3 exposes no Pool_Info), so APFS containers,
    BitLocker, LVM and VMFS volumes are recorded as unreadable, not walked."""
    if inventory is None:
        inventory = []
    found = False
    try:
        vol = pytsk3.Volume_Info(img)
    except OSError:
        vol = None
    if vol is not None:
        bps = vol.info.block_size or 512
        for part in vol:
            if not (part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC):
                continue
            offset = part.start * bps
            desc = part.desc.decode("utf-8", "replace") if isinstance(part.desc, bytes) else str(part.desc)
            try:
                fs = pytsk3.FS_Info(img, offset=offset)
            except OSError as exc:
                log(f"partition {part.addr} at offset {offset}: no readable filesystem ({exc})")
                inventory.append(PartitionInfo(part.addr, desc, part.start, part.len, f"unreadable: {exc}"))
                continue
            found = True
            inventory.append(PartitionInfo(part.addr, desc, part.start, part.len, fs_type_name(fs)))
            yield part.addr, offset, fs
    if not found:
        try:
            fs = pytsk3.FS_Info(img, offset=0)
        except OSError as exc:
            log(f"no partition table and no filesystem at offset 0 ({exc})")
            inventory.append(PartitionInfo(0, "whole image", 0, 0, f"unreadable: {exc}"))
            return
        inventory.append(PartitionInfo(0, "whole image (no partition table)", 0, 0, fs_type_name(fs)))
        yield 0, 0, fs


def _time(meta: object, attr: str) -> Optional[float]:
    v = getattr(meta, attr, 0)
    return float(v) if v else None


def walk_files(fs: pytsk3.FS_Info, include_deleted: bool, log: Log,
               cancel: Cancel = lambda: False) -> Iterator[ImageFile]:
    """Every regular file in `fs`, depth first. A deleted directory is
    descended only when its own metadata was not reallocated."""
    fs_type = fs_type_name(fs)
    seen_dirs: Set[int] = set()
    stack: List[tuple[str, int]] = [("", fs.info.root_inum)]
    while stack and not cancel():
        path, inum = stack.pop()
        if inum in seen_dirs:
            continue
        seen_dirs.add(inum)
        try:
            directory = fs.open_dir(inode=inum)
        except OSError as exc:
            log(f"cannot read directory {path or '/'} (inode {inum}): {exc}")
            continue
        for entry in directory:
            try:
                name = entry.info.name.name.decode("utf-8", "replace")
            except AttributeError:
                continue
            if name in (".", ".."):
                continue
            meta = entry.info.meta
            allocated = not (entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
            if (not allocated and not include_deleted) or meta is None:
                continue
            child = f"{path}/{name}" if path else name
            # A deleted name whose metadata entry has since been reused points
            # at another file's bytes (fls shows "(realloc)").
            realloc = False
            if not allocated:
                meta_alloc = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                name_seq = getattr(entry.info.name, "meta_seq", None)
                meta_seq = getattr(meta, "seq", None)
                realloc = meta_alloc or (name_seq is not None and meta_seq is not None and name_seq != meta_seq)
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                if allocated or not realloc:
                    stack.append((child, meta.addr))
                continue
            if meta.type != pytsk3.TSK_FS_META_TYPE_REG:
                continue
            # TSK presents a FAT/exFAT volume label, and exFAT's bitmap and
            # up-case table, as regular files; none of them is a user file.
            if name.endswith(" (Volume Label Entry)") or (not path and name in _TSK_EXFAT_SYSTEM):
                continue
            yield ImageFile(
                path=child, name=name, size=max(meta.size, 0), inode=meta.addr,
                allocated=allocated, realloc=realloc,
                mtime=_time(meta, "mtime"), atime=_time(meta, "atime"),
                ctime=_time(meta, "ctime"), crtime=_time(meta, "crtime"), fs_type=fs_type, fs=fs,
            )


def copy_inode(fs: pytsk3.FS_Info, inode: int, size: int, dest: str, exclusive: bool = True) -> Hashes:
    """Copy a file out of the image by inode, hashing as it goes. The caller
    compares Hashes.bytes with the declared size: a short read (a broken run
    on a deleted file) is reported, never padded. With `exclusive`, an
    existing `dest` raises FileExistsError."""
    reader = open_inode(fs, inode, size)
    with open(dest, "xb" if exclusive else "wb") as out:
        return hash_stream(reader.iter_chunks(), sink=out)
