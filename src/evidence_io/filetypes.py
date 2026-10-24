"""Which files are videos or images.

Videos match by extension first and by container signature second, so a
renamed or extension-less video is still found (moved unchanged from
video-frame-triage's discover.py). Images match by extension.
"""

from __future__ import annotations

import os
from typing import Callable, Optional, Set

# Common container extensions. Audio-only containers (mp3, wav) are not here;
# ogg and asf can hold video, so they stay.
VIDEO_EXTENSIONS: Set[str] = {
    "mp4", "m4v", "mov", "qt", "3gp", "3g2", "avi", "mkv", "webm", "wmv", "asf",
    "flv", "f4v", "mpg", "mpeg", "mpe", "m2v", "mpv", "vob", "ts", "mts", "m2ts",
    "mxf", "dv", "ogv", "ogg", "rm", "rmvb", "divx", "xvid", "h264", "264", "hevc",
    "265", "mjpeg", "mjpg", "swf", "amv", "dav", "mod", "tod", "evo", "trp", "tp",
}

# Still images: camera, phone, editor and vector formats; camera raw by vendor extension.
IMAGE_EXTENSIONS: Set[str] = {
    "jpg", "jpeg", "jpe", "jfif", "png", "gif", "bmp", "dib", "tif", "tiff",
    "webp", "ico", "heic", "heif", "avif", "jxl", "jp2", "j2k", "psd", "xcf",
    "pdn", "kra", "ora", "svg", "eps", "ai", "cdr", "wmf", "emf", "tga", "pcx",
    "raw", "dng", "cr2", "cr3", "crw", "nef", "nrw", "arw", "srf", "sr2",
    "orf", "rw2", "raf", "pef", "srw", "x3f", "3fr", "erf", "kdc", "mrw",
}

# (offset, bytes, label)
MAGIC = [
    (4, b"ftyp", "iso-bmff"),       # mp4, mov, 3gp, m4v, f4v, heif video
    (0, b"RIFF", "riff"),           # avi (checked for AVI at 8 below)
    (0, b"\x1a\x45\xdf\xa3", "ebml"),  # mkv, webm
    (0, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c", "asf"),
    (0, b"FLV\x01", "flv"),
    (0, b"\x00\x00\x01\xba", "mpeg-ps"),
    (0, b"\x00\x00\x01\xb3", "mpeg-video"),
    (0, b"OggS", "ogg"),
    (0, b".RMF", "realmedia"),
    (0, b"\x06\x0e\x2b\x34\x02\x05\x01\x01\x0d\x01\x02", "mxf"),
    (0, b"\x00\x00\x00\x0c\x6a\x50\x20\x20", "jp2"),  # motion jpeg 2000
]
SNIFF_BYTES = 512
SNIFF_MIN_SIZE = 16 * 1024  # shortcut: files under 16 KiB are not sniffed, raise if tiny clips matter

# Extensions never sniffed: a renamed video hides behind an unknown or absent
# extension, not behind a photo, executable, document or archive one.
NON_VIDEO_EXTENSIONS: Set[str] = {
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "heic", "heif", "webp", "ico", "psd", "raw", "cr2", "nef", "dng",
    "exe", "dll", "sys", "ocx", "msi", "cab", "lib", "obj", "pdb", "so", "dylib",
    "txt", "log", "ini", "cfg", "xml", "json", "html", "htm", "css", "js", "py", "c", "h", "cpp",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt",
    "zip", "7z", "rar", "gz", "bz2", "xz", "tar", "iso", "dmg",
    "mp3", "wav", "flac", "aac", "m4a", "wma", "opus", "oga", "aiff",
    "db", "sqlite", "sqlite3", "dat_", "evtx", "lnk", "pf", "etl", "edb",
}

# ISO base media major brands that are still images or audio, not video.
_NON_VIDEO_BRANDS = {b"heic", b"heix", b"hevx", b"heim", b"heis", b"mif1", b"msf1", b"avif",
                     b"M4A ", b"M4B ", b"M4P ", b"jp2 ", b"jpm ", b"jpx ", b"crx "}


def extension(name: str) -> str:
    """Lower-case extension without the dot."""
    return os.path.splitext(name)[1][1:].lower()


def magic_label(head: bytes) -> Optional[str]:
    """Container label when `head` (the first bytes of a file) is a video."""
    for off, sig, label in MAGIC:
        if head[off:off + len(sig)] == sig:
            if label == "riff":
                return "avi" if head[8:12] == b"AVI " else None
            if label == "iso-bmff":
                return None if head[8:12] in _NON_VIDEO_BRANDS else label
            if label == "ebml":
                return label if (b"matroska" in head[:64] or b"webm" in head[:64]) else None
            if label == "ogg":
                return label if any(m in head for m in (b"theora", b"OVP80", b"dirac", b"fishead")) else None
            return label
    if len(head) >= 377 and head[0] == 0x47 and head[188] == 0x47:  # MPEG-TS sync bytes
        return "mpeg-ts"
    return None


def video_match(name: str, size: int, read_head: Callable[[int], bytes], sniff: bool = True) -> Optional[str]:
    """"extension", "magic", "extension+magic", or None when not a video.
    `read_head(n)` returns the first n bytes; it is called only when the
    signature is worth checking. An unreadable head counts as no signature.
    For an ImageFile `f`: video_match(f.name, f.size, lambda n: f.read(0, n))."""
    ext = extension(name)
    by_ext = ext in VIDEO_EXTENSIONS
    by_magic = False
    if sniff and size > 0 and (by_ext or (size >= SNIFF_MIN_SIZE and ext not in NON_VIDEO_EXTENSIONS)):
        try:
            by_magic = magic_label(read_head(min(SNIFF_BYTES, size))) is not None
        except OSError:
            by_magic = False
    if by_ext and by_magic:
        return "extension+magic"
    if by_ext:
        return "extension"
    return "magic" if by_magic else None


def is_image(name: str) -> bool:
    return extension(name) in IMAGE_EXTENSIONS
