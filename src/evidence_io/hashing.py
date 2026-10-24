"""MD5, SHA-1 and SHA-256 of a byte stream in one pass."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Optional

BLOCK = 4 * 1024 * 1024


@dataclass
class Hashes:
    md5: str
    sha1: str
    sha256: str
    bytes: int


class MultiHasher:
    def __init__(self) -> None:
        self._md5 = hashlib.md5()
        self._sha1 = hashlib.sha1()
        self._sha256 = hashlib.sha256()
        self.count = 0

    def update(self, block: bytes) -> None:
        self._md5.update(block)
        self._sha1.update(block)
        self._sha256.update(block)
        self.count += len(block)

    def result(self) -> Hashes:
        return Hashes(self._md5.hexdigest(), self._sha1.hexdigest(), self._sha256.hexdigest(), self.count)


def hash_stream(chunks: Iterable[bytes], sink: Optional[BinaryIO] = None) -> Hashes:
    """Hash every chunk; when `sink` is given, also write each chunk to it."""
    h = MultiHasher()
    for block in chunks:
        h.update(block)
        if sink is not None:
            sink.write(block)
    return h.result()


def hash_file(path: str) -> Hashes:
    with open(path, "rb") as fh:
        return hash_stream(iter(lambda: fh.read(BLOCK), b""))
