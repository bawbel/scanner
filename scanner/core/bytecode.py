"""
Bawbel Scanner - precompiled bytecode (.pyc) header, pure functions.

A .pyc file starts with a header. Since Python 3.7 (PEP 552) it is 16 bytes:

    bytes 0-3    magic number: two bytes (little endian) then b"\\r\\n"
    bytes 4-7    flags, little endian: bit 0 = hash based, bit 1 = check source
    bytes 8-15   the source hash if hash based, else the source mtime and size

so the flags are 0b00 for a timestamp pyc, 0b11 for a checked hash and 0b01 for an unchecked
hash. Python loads an unchecked-hash pyc without comparing it to its source. This layout was
checked by compiling with each `py_compile` invalidation mode (issue 182), and Python versions
older than 3.7 have no flags field, so the flags are read only from magic number 3392 up.

These functions read no file and never raise. The file reads are in
scanner/engines/bytecode_engine.py. Nothing here looks at the code object itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scanner.config import PYC_PEP552_MIN_MAGIC

_PYC_CACHE_DIR = "__pycache__"
# bit 0 = hash based, bit 1 = check source. A valid header sets no other bit, and CPython rejects
# one that does, so only the exact value is read as "unchecked hash".
_FLAGS_UNCHECKED_HASH = 0b01


@dataclass(frozen=True)
class PycHeader:
    """What the first bytes of a .pyc file say."""

    magic_number: int
    flags: Optional[int]  # None for a pre-3.7 header, which has no flags field

    @property
    def unchecked_hash(self) -> bool:
        """Hash based with source checking off: the flags are exactly 0b01."""
        return self.flags == _FLAGS_UNCHECKED_HASH


def parse_pyc_header(head: bytes) -> Optional[PycHeader]:
    """The header in the first bytes of a file, or None if they are not a .pyc header."""
    if len(head) < 8 or head[2:4] != b"\r\n":
        return None
    magic = int.from_bytes(head[0:2], "little")
    if magic < PYC_PEP552_MIN_MAGIC:
        return PycHeader(magic_number=magic, flags=None)
    return PycHeader(magic_number=magic, flags=int.from_bytes(head[4:8], "little"))


def matching_source(pyc: Path) -> Path:
    """The source file a .pyc would have been compiled from, by name only.

    `pkg/__pycache__/mod.cpython-312.pyc` and `...opt-1.pyc` match `pkg/mod.py`. A legacy
    `pkg/mod.pyc` matches `pkg/mod.py`. Python only imports a __pycache__ file when the source
    is there, and imports a bare `mod.pyc` only when it is not.
    """
    if pyc.parent.name == _PYC_CACHE_DIR:
        module = pyc.name[: -len(pyc.suffix)].split(".", 1)[0]
        return pyc.parent.parent / f"{module}.py"
    return pyc.with_suffix(".py")
