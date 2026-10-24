"""EnCase 6 (EWF-E01) writer in pure Python.

Why this exists: the libewf-python wheels are built without zlib, so pyewf
refuses write mode. The layout below mirrors what libewf's ewfacquire
produces for `-f encase6` byte for byte in structure (dumped 2026-10-23):

    file header (13 bytes)
    header2, header2   UTF-16LE text, zlib
    header             CRLF text, zlib
    volume             1052 bytes
    sectors            chunk data
    table, table2      chunk offset tables
    data               copy of volume
    hash               MD5 of media
    done

Spec: libewf "Expert Witness Compression Format (EWF)" documentation.
"""

from __future__ import annotations

import hashlib
import itertools
import os
import struct
import time
import uuid
import zlib
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator, Optional

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
SECTOR = 512
SECTORS_PER_CHUNK = 64
CHUNK = SECTOR * SECTORS_PER_CHUNK  # 32768
DESCRIPTOR = 76
MAX_TABLE_ENTRIES = 65534  # EnCase 6 table limit (spec: "seems to be 65534")
COMPRESSED_FLAG = 0x80000000
MAX_SECTORS_SPAN = COMPRESSED_FLAG - 64 * 1024  # table offsets are 31-bit; keep a margin
DEFAULT_SEGMENT_SIZE = 2 * 1024 ** 3
MIN_SEGMENT_SIZE = 64 * 1024 ** 2


@dataclass
class EwfMetadata:
    case_number: str = ""
    evidence_number: str = ""
    description: str = ""
    examiner_name: str = ""
    notes: str = ""
    version: str = ""
    platform: str = ""
    acquired: float = field(default_factory=time.time)

    def _clean(self, value: str) -> str:
        # Header lines are tab separated, so tabs and newlines inside a
        # value would corrupt the record (spec header notes).
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ")

    def header_text(self) -> bytes:
        t = time.localtime(self.acquired)
        stamp = f"{t.tm_year} {t.tm_mon} {t.tm_mday} {t.tm_hour} {t.tm_min} {t.tm_sec}"
        values = [
            self._clean(self.case_number),
            self._clean(self.evidence_number),
            self._clean(self.description),
            self._clean(self.examiner_name),
            self._clean(self.notes),
            self._clean(self.version)[:11],
            self._clean(self.platform)[:23],
            stamp,
            stamp,
            "0",
        ]
        lines = ["1", "main", "c\tn\ta\te\tt\tav\tov\tm\tu\tp", "\t".join(values), ""]
        return ("\r\n".join(lines) + "\r\n").encode("ascii", "replace")

    def header2_text(self) -> bytes:
        epoch = str(int(self.acquired))
        values = [
            self._clean(self.description),
            self._clean(self.case_number),
            self._clean(self.evidence_number),
            self._clean(self.examiner_name),
            self._clean(self.notes),
            "",  # md model
            "",  # sn serial
            self._clean(self.version)[:11],
            self._clean(self.platform)[:23],
            epoch,
            epoch,
            "0",
            "",  # dc
        ]
        lines = [
            "3",
            "main",
            "a\tc\tn\te\tt\tmd\tsn\tav\tov\tm\tu\tp\tdc",
            "\t".join(values),
            "",
            "srce",
            "0\t1",
            "p\tn\tid\tev\ttb\tlo\tpo\tah\tgu\taq",
            "0\t0",
            "\t\t\t\t\t-1\t-1\t\t\t",
            "",
            "sub",
            "0\t1",
            "p\tn\tid\tnu\tco\tgu",
            "0\t0",
            "\t\t\t\t\t",
            "",
        ]
        return b"\xff\xfe" + ("\n".join(lines)).encode("utf-16-le")


def _adler(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def _descriptor(kind: bytes, offset: int, size: int) -> bytes:
    """76-byte section descriptor. `size` includes the descriptor itself.
    With size 0 the next-offset points at the section itself, which is the
    spec's form for the terminal `done` and `next` sections."""
    body = kind.ljust(16, b"\x00") + struct.pack("<QQ", offset + size, size) + b"\x00" * 40
    return body + struct.pack("<I", _adler(body))


def _volume_payload(chunk_count: int, sector_count: int, set_id: bytes, media_type: int, media_flags: int) -> bytes:
    body = bytearray(1048)
    body[0] = media_type
    struct.pack_into("<III", body, 4, chunk_count, SECTORS_PER_CHUNK, SECTOR)
    struct.pack_into("<Q", body, 16, sector_count)
    body[36] = media_flags
    body[52] = 1  # good (fast) compression, mirrors ewfacquire -c fast
    struct.pack_into("<I", body, 56, SECTORS_PER_CHUNK)  # error granularity
    body[64:80] = set_id
    return bytes(body) + struct.pack("<I", _adler(bytes(body)))


def _compress_chunk(raw: bytes) -> tuple[bytes, bool]:
    """Return (stored bytes, compressed?). A chunk is stored raw with an
    Adler-32 trailer when deflate does not win (spec, data chunk)."""
    packed = zlib.compress(raw, 1)
    if len(packed) < len(raw):
        return packed, True
    return raw + struct.pack("<I", _adler(raw)), False


def segment_stem(path: str) -> str:
    """The set is always named <stem>.E01, .E02 ... whatever extension was given."""
    stem, _ = os.path.splitext(path)
    return stem


def existing_segments(path: str, limit: int = 200) -> list[str]:
    """Segment files already on disk for this stem (stale E02+ included)."""
    return [n for n in itertools.islice(_segment_names(path), limit) if os.path.exists(n)]


def _segment_names(base: str) -> Iterator[str]:
    """E01, E02 ... E99, EAA ... (spec, segment file extensions)."""
    stem = segment_stem(base)
    for n in range(1, 100):
        yield f"{stem}.E{n:02d}"
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for a in letters[4:]:  # E, F, ...
        for b in letters:
            for c in letters:
                yield f"{stem}.{a}{b}{c}"


class EwfWriter:
    """Write a raw media stream as an EnCase 6 E01 set.

    Usage:
        w = EwfWriter("out.E01", media_size, metadata)
        for block in blocks: w.write(block)
        w.close()

    `media_size` must be known up front: the volume section precedes the
    data. Writes are buffered into 32 KiB chunks.
    """

    def __init__(self, path: str, media_size: int, metadata: EwfMetadata,
                 segment_size: int = DEFAULT_SEGMENT_SIZE, media_type: int = 1,
                 physical: bool = False) -> None:
        if media_size <= 0:
            raise ValueError("media_size must be positive")
        if media_size % SECTOR:
            raise ValueError("media_size must be a multiple of 512")
        if segment_size < MIN_SEGMENT_SIZE:
            raise ValueError(f"segment_size below {MIN_SEGMENT_SIZE // 1024 ** 2} MiB")
        self.path = path
        self.media_size = media_size
        self.meta = metadata
        self.segment_size = segment_size
        self.media_type = media_type
        self.media_flags = 0x01 | (0x02 if physical else 0)
        self.set_id = uuid.uuid4().bytes
        self.sector_count = media_size // SECTOR
        self.chunk_count = (media_size + CHUNK - 1) // CHUNK
        self.md5 = hashlib.md5()
        self.sha256 = hashlib.sha256()
        self._pending = bytearray()
        self._written = 0
        self._names = _segment_names(path)
        self.segments: list[str] = []
        self._fh: Optional[BinaryIO] = None
        self._segment_no = 0
        self._open_segment()

    # -- segment lifecycle -------------------------------------------------

    def _open_segment(self) -> None:
        name = next(self._names)
        self._segment_no += 1
        self.segments.append(name)
        self._fh = open(name, "wb")
        self._fh.write(SIGNATURE + b"\x01" + struct.pack("<HH", self._segment_no, 0))
        self._pos = 13
        if self._segment_no == 1:
            h2 = zlib.compress(self.meta.header2_text(), 9)
            self._section(b"header2", h2)
            self._section(b"header2", h2)
            self._section(b"header", zlib.compress(self.meta.header_text(), 9))
            self._section(b"volume", self._volume())
        else:
            self._section(b"data", self._volume())
        self._begin_sectors()

    def _volume(self) -> bytes:
        return _volume_payload(self.chunk_count, self.sector_count, self.set_id,
                               self.media_type, self.media_flags)

    def _section(self, kind: bytes, payload: bytes) -> None:
        assert self._fh is not None
        self._fh.write(_descriptor(kind, self._pos, DESCRIPTOR + len(payload)))
        self._fh.write(payload)
        self._pos += DESCRIPTOR + len(payload)

    def _begin_sectors(self) -> None:
        assert self._fh is not None
        self._sectors_start = self._pos
        self._fh.write(b"\x00" * DESCRIPTOR)  # patched in _end_sectors
        self._pos += DESCRIPTOR
        self._entries: list[int] = []

    def _end_sectors(self) -> None:
        assert self._fh is not None
        size = self._pos - self._sectors_start
        self._fh.seek(self._sectors_start)
        self._fh.write(_descriptor(b"sectors", self._sectors_start, size))
        self._fh.seek(self._pos)
        table = self._table_payload()
        self._section(b"table", table)
        self._section(b"table2", table)

    def _table_payload(self) -> bytes:
        head = struct.pack("<IIQI", len(self._entries), 0, self._sectors_start, 0)
        head += struct.pack("<I", _adler(head))
        body = struct.pack(f"<{len(self._entries)}I", *self._entries)
        return head + body + struct.pack("<I", _adler(body))

    def _close_segment(self, last: bool) -> None:
        assert self._fh is not None
        self._end_sectors()
        if last:
            if self._segment_no == 1:
                # Single-segment sets carry a trailing data section; in a
                # multi-segment set every later segment already opened with
                # one (matches ewfacquire, found by review).
                self._section(b"data", self._volume())
            hash_body = self.md5.digest() + b"\x00" * 16
            self._section(b"hash", hash_body + struct.pack("<I", _adler(hash_body)))
            self._fh.write(_descriptor(b"done", self._pos, 0))
        else:
            self._fh.write(_descriptor(b"next", self._pos, 0))
        self._fh.close()
        self._fh = None

    # -- data ------------------------------------------------------------------

    def write(self, data: bytes) -> None:
        if self._fh is None:
            raise ValueError("writer is closed")
        if self._written + len(data) > self.media_size:
            raise ValueError("write exceeds declared media_size")
        self._written += len(data)
        self.md5.update(data)
        self.sha256.update(data)
        self._pending += data
        while len(self._pending) >= CHUNK:
            self._emit(bytes(self._pending[:CHUNK]))
            del self._pending[:CHUNK]

    def _emit(self, raw: bytes) -> None:
        assert self._fh is not None
        stored, compressed = _compress_chunk(raw)
        # A segment rolls over when the next chunk plus the tables and
        # trailer would pass the segment size, or the table is full.
        trailer = 2 * (DESCRIPTOR + 28 + 4 * (len(self._entries) + 1)) + 2 * DESCRIPTOR + 1128 + 112
        if self._entries and (
            self._pos + len(stored) + trailer > self.segment_size
            or len(self._entries) >= MAX_TABLE_ENTRIES
            or self._pos - self._sectors_start + len(stored) >= MAX_SECTORS_SPAN
        ):
            self._close_segment(last=False)
            self._open_segment()
        rel = self._pos - self._sectors_start
        self._entries.append(rel | (COMPRESSED_FLAG if compressed else 0))
        self._fh.write(stored)
        self._pos += len(stored)

    def close(self) -> None:
        if self._fh is None:
            return
        if self._written != self.media_size:
            raise ValueError(f"wrote {self._written} of {self.media_size} declared bytes")
        if self._pending:
            # Final partial chunk is stored at its true size; readers bound
            # the last chunk by the declared media size.
            self._emit(bytes(self._pending))
            self._pending.clear()
        self._close_segment(last=True)

    def __enter__(self) -> "EwfWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        if exc[0] is None:
            self.close()
        elif self._fh is not None:
            self._fh.close()
            self._fh = None


def write_file_as_e01(src_path: str, dst_path: str, metadata: EwfMetadata,
                      segment_size: int = DEFAULT_SEGMENT_SIZE, progress=None) -> EwfWriter:
    """Encode a raw image file as E01. Returns the closed writer (hashes, segments)."""
    size = os.path.getsize(src_path)
    with open(src_path, "rb") as fh, EwfWriter(dst_path, size, metadata, segment_size) as w:
        done = 0
        while True:
            block = fh.read(CHUNK * 64)
            if not block:
                break
            w.write(block)
            done += len(block)
            if progress:
                progress(done, size)
    return w
