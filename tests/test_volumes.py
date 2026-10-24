from __future__ import annotations

import hashlib
import os

import pytest
import pytsk3

from evidence_io import fat32, volume
from evidence_io.ewf_reader import open_e01
from evidence_io.ewf_writer import EwfMetadata, write_file_as_e01
from evidence_io.exfat import ExfatBuilder, entry_set, entry_set_checksum, name_hash
from evidence_io.fat32 import Fat32Builder
from evidence_io.hashing import hash_file, hash_stream
from evidence_io.image_walk import iter_filesystems, walk_files

MTIME = 1_600_000_000  # 2020-09-13T12:26:40Z

# path in the volume -> bytes
FILES = {
    "Extension-.jpg/beach.jpg": b"\xff\xd8\xff\xe0" + b"A" * 3000,
    "Extension-.jpg/" + "Ünïcödé long name " * 6 + ".jpg": b"\xff\xd8" + b"U" * 70000,
    "Extension-.txt/empty.txt": b"",
    "deep/a/b/c/clip.mp4": os.urandom(300_000),
    "top.bin": os.urandom(8192),
}


def _sources(tmp_path) -> list[tuple[str, str, float]]:
    out = []
    for i, (rel, data) in enumerate(FILES.items()):
        p = tmp_path / f"src{i}"
        p.write_bytes(data)
        out.append((rel, str(p), float(MTIME)))
    return out


def _read_back(raw: str) -> dict[str, tuple[str, float | None, str]]:
    img = pytsk3.Img_Info(raw)
    got = {}
    for _part, _off, fs in iter_filesystems(img, print):
        for f in walk_files(fs, include_deleted=False, log=print):
            if f.name.startswith("$"):
                continue
            h = hash_stream(f.open().iter_chunks())
            got[f.path] = (h.sha256, f.mtime, f.fs_type)
    return got


@pytest.mark.parametrize("fs_name", ["fat32", "exfat"])
def test_volume_reads_back_through_the_sleuth_kit(tmp_path, fs_name):
    raw = str(tmp_path / "v.img")
    res = volume.build_volume(_sources(tmp_path), raw, filesystem=fs_name, label="TESTVOL")
    assert res.filesystem == fs_name
    got = _read_back(raw)
    assert set(got) == set(FILES)
    for rel, data in FILES.items():
        assert got[rel][0] == hashlib.sha256(data).hexdigest(), rel
        assert got[rel][2] == fs_name
    if fs_name == "exfat":
        # stored as UTC; TSK 4.15 ignores the offset field, so compare clock fields
        assert got["top.bin"][1] is not None


def test_auto_prefers_fat32_when_it_fits(tmp_path):
    assert volume.choose_filesystem(_sources(tmp_path)) == ("fat32", "everything fits FAT32")


def test_auto_switches_to_exfat_for_a_4gib_file(tmp_path, monkeypatch):
    monkeypatch.setattr(volume, "MAX_FILE_BYTES", 10_000)  # stands in for 4 GiB
    fs, reason = volume.choose_filesystem(_sources(tmp_path))
    assert fs == "exfat" and "4 GiB" in reason


def test_auto_switches_to_exfat_for_an_overfull_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(fat32, "MAX_DIR_ENTRIES", 4)
    fs, reason = volume.choose_filesystem(_sources(tmp_path))
    assert fs == "exfat" and "65,536" in reason


def test_explicit_fat32_refuses_what_it_cannot_hold(tmp_path, monkeypatch):
    monkeypatch.setattr(volume, "MAX_FILE_BYTES", 10_000)
    with pytest.raises(ValueError):
        volume.choose_filesystem(_sources(tmp_path), "fat32")


def test_fat32_builder_refuses_an_overfull_directory(tmp_path):
    src = tmp_path / "one"
    src.write_bytes(b"x")
    b = Fat32Builder()
    for i in range(33_000):  # two entries each (long name plus short): over 65,536
        b.add_file(f"many/IMG_{i:05d}.jpg", str(src))
    assert b.overfull_dirs() == ["/many"]
    with pytest.raises(ValueError):
        b.build(str(tmp_path / "v.img"))


def test_exfat_rejects_case_insensitive_duplicates(tmp_path):
    src = tmp_path / "one"
    src.write_bytes(b"x")
    b = ExfatBuilder()
    b.add_file("a/Photo.JPG", str(src))
    with pytest.raises(ValueError):
        b.add_file("a/photo.jpg", str(src))


def test_exfat_entry_set_checksum_and_hash_are_self_consistent():
    raw = entry_set("Photo.jpg", 0x20, 5, 123, MTIME)
    assert raw[0] == 0x85 and raw[32] == 0xC0 and raw[64] == 0xC1
    assert int.from_bytes(raw[2:4], "little") == entry_set_checksum(raw)
    assert name_hash("Photo.jpg") == name_hash("PHOTO.JPG")  # hash is over the up-cased name


def test_e01_round_trip_with_in_memory_reads(tmp_path):
    raw = str(tmp_path / "v.img")
    volume.build_volume(_sources(tmp_path), raw, filesystem="exfat")
    e01 = str(tmp_path / "v.E01")
    w = write_file_as_e01(raw, e01, EwfMetadata(case_number="T1", examiner_name="pytest"))
    assert w.md5.hexdigest() == hash_file(raw).md5
    img, info = open_e01(e01.replace("\\", "/"))
    try:
        assert info.media_size == os.path.getsize(raw)
        for _p, _o, fs in iter_filesystems(img, print):
            for f in walk_files(fs, False, print):
                if f.path == "deep/a/b/c/clip.mp4":
                    h = hash_stream(f.open().iter_chunks(block=65536))
                    data = FILES[f.path]
                    assert (h.md5, h.sha1, h.sha256, h.bytes) == (
                        hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(),
                        hashlib.sha256(data).hexdigest(), len(data))
                    assert f.read(10, 5) == data[10:15]
                    assert f.allocated and not f.realloc
    finally:
        img.close()


def test_video_match_by_extension_and_signature():
    from evidence_io.filetypes import is_image, video_match

    mp4_head = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 500
    heic_head = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 500
    big = 64 * 1024
    assert video_match("clip.mp4", big, lambda n: mp4_head[:n]) == "extension+magic"
    assert video_match("renamed.dat", big, lambda n: mp4_head[:n]) == "magic"
    assert video_match("photo.heic", big, lambda n: heic_head[:n]) is None  # still image brand
    assert video_match("photo.jpg", big, lambda n: mp4_head[:n]) is None    # photos are never sniffed
    assert video_match("clip.mov", 10, lambda n: b"junk") == "extension"
    assert is_image("A.JPG") and not is_image("a.mp4")


def test_upcase_table_is_the_specifications(tmp_path):
    from evidence_io.exfat import UPCASE_CHECKSUM, table_checksum, upcase_bytes, upcase_key

    data = upcase_bytes()
    assert len(data) == 5836 and table_checksum(data) == UPCASE_CHECKSUM == 0xE619D30D
    assert upcase_key("straße") == "STRAßE"  # the volume does not expand the sharp s


def test_exfat_volume_meets_the_1_mib_minimum(tmp_path):
    import struct

    src = tmp_path / "tiny"
    src.write_bytes(b"0123456789")
    b = ExfatBuilder()
    b.add_file("tiny.txt", str(src))
    raw = tmp_path / "v.img"
    b.build(str(raw))
    with open(raw, "rb") as fh:
        fh.seek(2048 * 512 + 72)
        vol_len = struct.unpack("<Q", fh.read(8))[0]
    assert vol_len >= 2048


@pytest.mark.parametrize("builder", [ExfatBuilder, Fat32Builder])
def test_case_variant_folders_are_one_folder(tmp_path, builder):
    src = tmp_path / "one"
    src.write_bytes(b"x")
    b = builder()
    b.add_file("Photos/a.jpg", str(src))
    b.add_file("photos/b.jpg", str(src))
    raw = str(tmp_path / "v.img")
    b.build(raw)
    got = _read_back(raw)
    assert sorted(got) == ["Photos/a.jpg", "Photos/b.jpg"]


@pytest.mark.parametrize("builder", [ExfatBuilder, Fat32Builder])
def test_builders_refuse_ambiguous_names(tmp_path, builder):
    src = tmp_path / "one"
    src.write_bytes(b"x")
    b = builder()
    b.add_file("n", str(src))
    with pytest.raises(ValueError):
        b.add_file("n/y", str(src))  # a folder named like an existing file
    with pytest.raises(ValueError):
        b.add_file("N", str(src))  # differs only in case
    for bad in ("trailing.", "trailing ", "dir./x"):
        with pytest.raises(ValueError):
            b.add_file(bad, str(src))


@pytest.mark.parametrize("builder", [ExfatBuilder, Fat32Builder])
@pytest.mark.parametrize("change", [b"", b"grown" * 1000])
def test_builders_refuse_a_source_that_changed_size(tmp_path, builder, change):
    src = tmp_path / "f"
    src.write_bytes(b"x" * 2000)
    b = builder()
    b.add_file("f.bin", str(src))
    src.write_bytes(change)  # shrank to nothing, or grew
    with pytest.raises(ValueError):
        b.build(str(tmp_path / "v.img"))


def test_exfat_times_clamp_to_the_representable_range():
    from evidence_io.exfat import _clamped_utc

    assert _clamped_utc(-10 ** 12).year == 1980
    assert _clamped_utc(10 ** 15).year == 2107
    assert _clamped_utc(0).year == 1980


def test_copy_inode_is_exclusive_and_hashes(tmp_path):
    raw = str(tmp_path / "v.img")
    volume.build_volume(_sources(tmp_path), raw, filesystem="fat32")
    img = pytsk3.Img_Info(raw)
    for _p, _o, fs in iter_filesystems(img, print):
        f = next(x for x in walk_files(fs, False, print) if x.path == "top.bin")
        dest = str(tmp_path / "out.bin")
        h = f.copy_to(dest)
        assert h.sha256 == hashlib.sha256(FILES["top.bin"]).hexdigest() and h.bytes == 8192
        with pytest.raises(FileExistsError):
            f.copy_to(dest)
