"""Round trips of the two format writers through independent readers."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess

import pytest
import pytsk3

from evidence_io.ewf_reader import open_e01
from evidence_io.ewf_writer import CHUNK, EwfMetadata, EwfWriter, write_file_as_e01
from evidence_io.fat32 import PART_START_LBA, SECTOR, Fat32Builder
from evidence_io.filetypes import VIDEO_EXTENSIONS, magic_label


def test_fat32_round_trip_through_sleuthkit(tmp_path):
    stage = tmp_path / "stage"
    (stage / "frames" / "video_0001__a").mkdir(parents=True)
    payloads = {}
    for i in range(1, 30):
        rel = f"frames/video_0001__a/video_0001_f{i:06d}_t{i * 2:09.3f}s.jpg"
        data = b"\xff\xd8" + os.urandom((i * 7919) % 50000 + 1)
        (stage / rel).write_bytes(data)
        payloads[rel] = data
    long_rel = "frames/a folder with a long name/and a file name longer than thirteen characters.jpg"
    (stage / long_rel).parent.mkdir(parents=True)
    (stage / long_rel).write_bytes(b"long")
    payloads[long_rel] = b"long"
    fb = Fat32Builder(label="VFT TEST")
    for rel in payloads:
        fb.add_file(rel, str(stage / rel))
    img_path = tmp_path / "vol.img"
    size = fb.build(str(img_path))
    assert size == img_path.stat().st_size

    img = pytsk3.Img_Info(str(img_path))
    parts = [(p.desc, p.start) for p in pytsk3.Volume_Info(img)]
    assert any(b"FAT32" in d and s == PART_START_LBA for d, s in parts)
    fs = pytsk3.FS_Info(img, offset=PART_START_LBA * SECTOR)
    assert fs.info.ftype == pytsk3.TSK_FS_TYPE_FAT32
    for rel, data in payloads.items():
        f = fs.open(rel)
        assert f.read_random(0, f.info.meta.size) == data, rel
    names = {e.info.name.name for e in fs.open_dir("frames/video_0001__a")}
    assert b"video_0001_f000001_t00002.000s.jpg" in names


def test_fat32_rejects_bad_names(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"x")
    fb = Fat32Builder()
    for bad in ("a/../b", "con:x", "dir/", "", "x" * 196):
        with pytest.raises(ValueError):
            fb.add_file(bad, str(f))


def _read_all(e01: str) -> tuple[bytes, dict, dict]:
    """Media bytes, stored hashes and header values through the package's own reader."""
    img, info = open_e01(e01)
    try:
        data = img.read(0, info.media_size)
    finally:
        img.close()
    assert len(data) == info.media_size
    return data, info.stored_hashes, info.header_values


def _verify_with_libewf(e01: str) -> bytes:
    tool = shutil.which("ewfverify")
    if tool:
        proc = subprocess.run([tool, "-q", e01], capture_output=True, text=True)
        assert "SUCCESS" in proc.stdout + proc.stderr, proc.stdout + proc.stderr
    data, hashes, _ = _read_all(e01)
    assert hashes["MD5"] == hashlib.md5(data).hexdigest()
    return data


def test_ewf_single_segment_round_trip(tmp_path):
    raw = tmp_path / "raw.img"
    content = os.urandom(3 * CHUNK) + b"\x00" * CHUNK + b"q" * (SECTOR * 5)  # partial last chunk
    raw.write_bytes(content)
    meta = EwfMetadata(case_number="C-1", evidence_number="E-1", examiner_name="LTT examiner",
                       notes="unit", description="d", version="evidence-io test", platform="pytest")
    out = tmp_path / "one.E01"
    w = write_file_as_e01(str(raw), str(out), meta)
    assert w.segments == [str(out)]
    data = _verify_with_libewf(str(out))
    assert data == content
    _, _, hv = _read_all(str(out))
    assert hv["case_number"] == "C-1"
    assert hv["examiner_name"] == "LTT examiner"
    assert hv["evidence_number"] == "E-1"
    assert hv["notes"] == "unit"


def test_ewf_multi_segment_round_trip(tmp_path):
    raw = tmp_path / "raw.img"
    with open(raw, "wb") as fh:
        for _ in range(70):
            fh.write(os.urandom(1024 * 1024))
    out = tmp_path / "multi.E01"
    w = write_file_as_e01(str(raw), str(out), EwfMetadata(version="t", platform="t"), segment_size=64 * 1024 ** 2)
    assert len(w.segments) == 2
    assert w.segments[1].endswith(".E02")
    assert _verify_with_libewf(str(out)) == raw.read_bytes()


def test_ewf_writer_rejects_short_write(tmp_path):
    w = EwfWriter(str(tmp_path / "short.E01"), 2 * SECTOR, EwfMetadata())
    w.write(b"\x00" * SECTOR)
    with pytest.raises(ValueError):
        w.close()


def _read(fs, rel: str) -> bytes:
    f = fs.open(rel)
    return f.read_random(0, f.info.meta.size)

def test_fat32_names_at_lfn_boundaries(tmp_path):
    """Directory tables must hold exactly the planned entries for names of
    13, 26 and 39 UTF-16 units and for non-BMP characters (review finding)."""
    payload = tmp_path / "p"
    payload.write_bytes(b"\xff\xd8payload")
    names = ["a" * 13, "b" * 26, "c" * 39, "d" * 12, "e" * 14, "\U0001F600" * 6 + ".jpg", "f" * 195]
    fb = Fat32Builder(label="LFN")
    for i, n in enumerate(names):
        fb.add_file(f"d{i % 2}/{n}", str(payload))  # two dirs, five+ names each
        for k in range(6):
            fb.add_file(f"d{i % 2}/{n[:-1]}{k}", str(payload))
    img_path = tmp_path / "lfn.img"
    fb.build(str(img_path))
    fs = pytsk3.FS_Info(pytsk3.Img_Info(str(img_path)), offset=PART_START_LBA * SECTOR)
    for i, n in enumerate(names):
        assert _read(fs, f"d{i % 2}/{n}") == b"\xff\xd8payload", n
        for k in range(6):
            assert _read(fs, f"d{i % 2}/{n[:-1]}{k}") == b"\xff\xd8payload"

def test_magic_and_extension_tables():
    assert magic_label(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 500) == "iso-bmff"
    assert magic_label(b"RIFF\x00\x00\x00\x00AVI LIST" + b"\x00" * 500) == "avi"
    assert magic_label(b"RIFF\x00\x00\x00\x00WAVEfmt " + b"\x00" * 500) is None
    assert magic_label(b"\x1a\x45\xdf\xa3\xa3\x42\x86\x81\x01\x42\x82\x88matroska" + b"\x00" * 500) == "ebml"
    assert magic_label(b"\x1a\x45\xdf\xa3" + b"\x00" * 500) is None  # EBML without a video doctype
    assert magic_label(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 500) is None  # HEIC photo
    assert magic_label(b"\x00\x00\x00\x18ftypM4A " + b"\x00" * 500) is None  # audio
    assert magic_label(b"OggS" + b"\x00" * 24 + b"\x80theora" + b"\x00" * 500) == "ogg"
    assert magic_label(b"OggS" + b"\x00" * 24 + b"\x01vorbis" + b"\x00" * 500) is None
    ts = bytearray(512)
    ts[0] = 0x47
    ts[188] = 0x47
    assert magic_label(bytes(ts)) == "mpeg-ts"
    assert magic_label(b"\x00" * 512) is None
    for ext in ("mp4", "mov", "avi", "mkv", "wmv", "flv", "webm", "3gp", "mts", "m2ts", "mpg", "vob"):
        assert ext in VIDEO_EXTENSIONS
