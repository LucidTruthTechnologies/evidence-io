"""walk_files reports every entry it does not examine (on_skip)."""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytsk3

from evidence_io.fat32 import PART_START_LBA, SECTOR, Fat32Builder
from evidence_io.image_walk import walk_files


def _deleted_dir_volume(tmp_path) -> str:
    """FAT32 volume with keep.txt and a directory gone/ holding inner.txt;
    gone/ is then deleted the way FAT does it: first byte of its short entry
    and long-name entries set to 0xE5, its FAT chain freed in both FATs."""
    src = tmp_path / "payload"
    src.write_bytes(b"benign test bytes " * 50)
    fb = Fat32Builder()
    fb.add_file("gone/inner.txt", str(src))
    fb.add_file("keep.txt", str(src))
    img = tmp_path / "vol.img"
    fb.build(str(img))
    raw = bytearray(img.read_bytes())
    base = PART_START_LBA * SECTOR
    bps, spc, rsv, nfats = struct.unpack_from("<HBHB", raw, base + 11)
    fat_sz = struct.unpack_from("<I", raw, base + 36)[0]
    root = struct.unpack_from("<I", raw, base + 44)[0]
    data = base + (rsv + nfats * fat_sz) * bps
    start = data + (root - 2) * spc * bps
    deleted = 0
    for e in range(start, start + spc * bps, 32):
        if raw[e] == 0:
            break
        if raw[e + 11] == 0x10 and raw[e] not in (0x2E, 0xE5):
            first = struct.unpack_from("<H", raw, e + 20)[0] << 16 | struct.unpack_from("<H", raw, e + 26)[0]
            raw[e] = 0xE5
            j = e - 32
            while j >= start and raw[j + 11] == 0x0F:
                raw[j] = 0xE5
                j -= 32
            for k in range(nfats):
                struct.pack_into("<I", raw, base + (rsv + k * fat_sz) * bps + 4 * first, 0)
            deleted += 1
    assert deleted == 1
    img.write_bytes(raw)
    return str(img)


def _open(img: str) -> pytsk3.FS_Info:
    return pytsk3.FS_Info(pytsk3.Img_Info(img), offset=PART_START_LBA * SECTOR)


def _ns_entry(entry, realloc_dir: bool):
    """A plain copy of a TSK directory entry; with `realloc_dir`, a deleted
    directory's metadata is marked allocated, as NTFS shows a reused MFT
    record (FAT cannot: its metadata address is the name's own slot)."""
    name, meta = entry.info.name, entry.info.meta
    m = None
    if meta is not None:
        flags = int(meta.flags)
        if realloc_dir and meta.type == pytsk3.TSK_FS_META_TYPE_DIR and name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC:
            flags |= int(pytsk3.TSK_FS_META_FLAG_ALLOC)
        m = SimpleNamespace(flags=flags, type=meta.type, addr=meta.addr, size=meta.size, seq=meta.seq,
                            mtime=meta.mtime, atime=meta.atime, ctime=meta.ctime, crtime=meta.crtime)
    n = SimpleNamespace(name=name.name, flags=name.flags, meta_seq=name.meta_seq)
    return SimpleNamespace(info=SimpleNamespace(name=n, meta=m))


class _FsView:
    """The real FS_Info, with the root listing rewritten: the deleted
    directory shown as reallocated, plus one name that has no metadata."""

    def __init__(self, fs: pytsk3.FS_Info) -> None:
        self._fs = fs
        self.info = fs.info

    def open_dir(self, inode: int):
        entries = list(self._fs.open_dir(inode=inode))
        if inode != self.info.root_inum:
            return entries
        out = [_ns_entry(e, realloc_dir=True) for e in entries]
        orphan = SimpleNamespace(name=b"nometa.jpg", flags=pytsk3.TSK_FS_NAME_FLAG_UNALLOC, meta_seq=0)
        out.append(SimpleNamespace(info=SimpleNamespace(name=orphan, meta=None)))
        return out

    def open_meta(self, inode: int):
        return self._fs.open_meta(inode=inode)


def test_deleted_directory_is_descended_and_nothing_skipped(tmp_path):
    fs = _open(_deleted_dir_volume(tmp_path))
    skips = []
    files = {f.path: f for f in walk_files(fs, True, lambda _m: None, on_skip=lambda p, r: skips.append((p, r)))}
    assert files["keep.txt"].allocated
    assert not files["gone/inner.txt"].allocated and not files["gone/inner.txt"].realloc
    assert skips == []


def test_every_unexamined_entry_is_reported(tmp_path):
    fs = _FsView(_open(_deleted_dir_volume(tmp_path)))
    skips = []
    paths = [f.path for f in walk_files(fs, True, lambda _m: None, on_skip=lambda p, r: skips.append((p, r)))]
    assert paths == ["keep.txt"]
    reasons = dict(skips)
    assert set(reasons) == {"gone", "nometa.jpg"}
    assert "reallocated" in reasons["gone"]
    assert "no metadata" in reasons["nometa.jpg"]


def test_default_walk_unchanged_without_on_skip(tmp_path):
    fs = _FsView(_open(_deleted_dir_volume(tmp_path)))
    assert [f.path for f in walk_files(fs, True, lambda _m: None)] == ["keep.txt"]
    # Deleted names are not reported when the caller asked for none.
    skips = []
    list(walk_files(fs, False, lambda _m: None, on_skip=lambda p, r: skips.append(p)))
    assert skips == []
