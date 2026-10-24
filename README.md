# evidence-io

Shared evidence input and output for Lucid Truth Technologies' triage tools (`file_organizer`, `video-frame-triage`, `image-triage`). It reads E01 images in place, read-only, and writes new E01 images that hold a FAT32 or exFAT volume.

Requires Python 3.11 or later. CI runs on Windows and Linux with Python 3.12.

## What is in it

| Module | Purpose |
| --- | --- |
| `ewf_reader` | `open_e01(path)` opens any segment of an E01 set read-only through libewf and returns a The Sleuth Kit image plus `SourceInfo` (segments, media size, stored hashes, header values). No mount, no driver, no administrator rights. |
| `image_walk` | `iter_filesystems(img, log)` yields every readable filesystem in the image; `walk_files(fs, include_deleted, log)` yields every regular file as an `ImageFile` with its path, size, inode, `allocated`, `realloc`, the four times (`mtime`, `atime`, `ctime`, `crtime`, epoch seconds or `None`) and `fs_type`. `ImageFile.open()` reads a file in memory without writing anything to disk; `ImageFile.copy_to(dest)` copies it out exclusively and returns its hashes. |
| `hashing` | `hash_stream(chunks)` and `hash_file(path)` return MD5, SHA-1, SHA-256 and the byte count in one pass. |
| `filetypes` | `video_match(name, size, read_head)` finds videos by extension and by container signature, so renamed videos are found; `is_image(name)` matches images by extension. |
| `fat32`, `exfat` | Write-once volume builders: collect files, then `build(path)` writes a partitioned raw image. |
| `volume` | `build_volume(files, path, filesystem="auto")` picks FAT32 when everything fits and exFAT when a file is 4 GiB or larger or a folder holds more than FAT32's 65,536 directory entries, and reports which it chose and why. |
| `ewf_writer` | `write_file_as_e01(raw, e01, metadata)` encodes a raw image as an EnCase 6 E01 (deflate, MD5 stored), split into segments. |

## Rules the code keeps

- A deleted file whose metadata entry has been reused (`realloc`) points at another file's bytes. It is reported and must never be read as the deleted file.
- A short read from a damaged deleted file is reported as such (`Hashes.bytes` less than `size`), never padded.
- A file written into a new volume carries an extraction date in that container. The original times travel in the caller's manifest, and only those are evidence.
- FAT32 stores local time with no zone. exFAT entries are written in UTC with the offset field marked valid. The Sleuth Kit 4.15 ignores that field and shows the UTC clock time as if it were local.

## Why pure Python writers

The `libewf-python` wheel is built without zlib and refuses to write. `pyfatfs` depends on PyFilesystem2, which imports `pkg_resources`, removed in setuptools 84. So the E01 encoder follows the section layout of `ewfacquire -f encase6`, and both volume builders are written from their specifications: the FAT32 layout, and Microsoft's exFAT specification (2019).

## Verification

`pytest` builds FAT32 and exFAT volumes, reads them back through The Sleuth Kit, and compares every file's hash. It also round-trips an E01 and checks the automatic filesystem choice and the FAT32 directory limit. On Windows, CI also mounts both volumes read-only as VHDs with Windows' own filesystem drivers, compares every file's SHA-256 (and the exFAT modified times), and runs `chkdsk` on each (`tests/make_vhd.py`, `tests/windows_mount_check.ps1`).

## Using it

Pin the full commit hash of a release, never the tag. A tag can be moved to different code by anyone who gains control of this repository, and every consumer pinned to it would silently pull that code; a commit hash cannot change. Release tags mark which commits are releases. Resolve one with `git ls-remote https://github.com/LucidTruthTechnologies/evidence-io refs/tags/v1.0.1^{}`.

```text
# v1.0.1
evidence-io @ git+https://github.com/LucidTruthTechnologies/evidence-io@69d424615ab1fde6c000ce3081a4f2376762eadd
```

Dependencies: `libewf-python` (LGPL-3.0-or-later) and `pytsk3` (Apache-2.0).

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Lucid Truth Technologies®.
