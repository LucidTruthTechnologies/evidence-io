"""make_vhd - build FAT32 and exFAT test volumes as fixed VHDs for Windows.

USAGE:
    python tests/make_vhd.py <out-dir>

Writes fat32.vhd, exfat.vhd and expected.json ({volume: {path: [sha256,
mtime epoch]}}). CI mounts each VHD read-only with Windows' own filesystem
drivers, compares every file's hash and modified time, and runs chkdsk: a
check of the builders by a reader that shares no code with them. Every file
is synthetic bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from evidence_io.volume import build_volume  # noqa: E402

MTIME = 1_600_000_000
FILES = {
    "Extension-.jpg/beach.jpg": b"\xff\xd8\xff\xe0" + b"A" * 3000,
    "Extension-.jpg/beach (2).jpg": b"\xff\xd8\xff\xe0" + b"B" * 5000,
    "Extension-.jpg/" + "Ünïcödé long name " * 6 + ".jpg": b"\xff\xd8" + b"U" * 70000,
    "Extension-.txt/empty.txt": b"",
    "deep/a/b/c/clip.mp4": bytes(range(256)) * 1200,
    "manifest.csv": b"output_path,sha256\r\n",
}


def vhd_footer(size: int) -> bytes:
    """Fixed-disk VHD footer (Virtual Hard Disk Image Format Specification)."""
    total = size // 512
    if total > 65535 * 16 * 255:
        total = 65535 * 16 * 255
    if total >= 65535 * 16 * 63:
        spt, heads = 255, 16
        cth = total // spt
    else:
        spt = 17
        cth = total // spt
        heads = max(4, (cth + 1023) // 1024)
        if cth >= heads * 1024 or heads > 16:
            spt, heads = 31, 16
            cth = total // spt
        if cth >= heads * 1024:
            spt, heads = 63, 16
            cth = total // spt
    cylinders = cth // heads
    f = bytearray(512)
    f[0:8] = b"conectix"
    struct.pack_into(">IIQI", f, 8, 2, 0x00010000, 0xFFFFFFFFFFFFFFFF, int(time.time()) - 946684800)
    f[28:32] = b"evio"
    struct.pack_into(">I", f, 32, 0x00010000)
    f[36:40] = b"Wi2k"
    struct.pack_into(">QQHBBI", f, 40, size, size, cylinders, heads, spt, 2)
    f[68:84] = uuid.uuid4().bytes
    struct.pack_into(">I", f, 64, (~sum(f)) & 0xFFFFFFFF)
    return bytes(f)


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    out = argv[0]
    src_dir = os.path.join(out, "src")
    os.makedirs(src_dir, exist_ok=True)
    files = []
    expected = {}
    for i, (rel, data) in enumerate(FILES.items()):
        p = os.path.join(src_dir, f"f{i}")
        with open(p, "wb") as fh:
            fh.write(data)
        files.append((rel, p, float(MTIME)))
        expected[rel] = [hashlib.sha256(data).hexdigest(), MTIME]
    result = {}
    for fs in ("fat32", "exfat"):
        raw = os.path.join(out, f"{fs}.vhd")
        build_volume(files, raw, filesystem=fs, label=fs.upper())
        size = os.path.getsize(raw)
        with open(raw, "ab") as fh:
            fh.write(vhd_footer(size))
        result[fs] = expected
    with open(os.path.join(out, "expected.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=1)
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
