"""
The precompiled-bytecode rules. Issue #182, AVE-2026-00075.

Two rules read only the 16 byte header of a .pyc file and look for its source file:

    bawbel-pyc-unchecked-hash   hash based with source checking off (PEP 552 flags 0b01)
    bawbel-pyc-no-source        no matching source file beside it

The bytecode is never read or analysed. These tests build real .pyc files with `py_compile`, in
each invalidation mode, from a source that holds only a docstring. Nothing is run or imported.

Run: pytest tests/unit/test_bytecode_rule.py -q
"""

import py_compile
import struct
import sys
from pathlib import Path

import pytest

from scanner.core.bytecode import PycHeader, matching_source, parse_pyc_header
from scanner.engines.bytecode_engine import (
    AVE_ID,
    RULE_NO_SOURCE,
    RULE_UNCHECKED_HASH,
    run_bytecode_scan,
)
from scanner.models import Severity

MODES = py_compile.PycInvalidationMode
TAG = sys.implementation.cache_tag
FORBIDDEN_WORDS = ("safe", "secure", "cleared", "certified", "audited")


def compiled(directory: Path, name: str, mode, keep_source: bool, legacy: bool = False) -> Path:
    """Compile `name`.py with `mode`. The .pyc goes in __pycache__, or beside it if `legacy`."""
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / f"{name}.py"
    source.write_text('"""A docstring and nothing else."""\n', encoding="utf-8")
    if legacy:
        target = directory / f"{name}.pyc"
    else:
        (directory / "__pycache__").mkdir(exist_ok=True)
        target = directory / "__pycache__" / f"{name}.{TAG}.pyc"
    py_compile.compile(str(source), cfile=str(target), doraise=True, invalidation_mode=mode)
    if not keep_source:
        source.unlink()
    return target


def rules(path: Path) -> set[str]:
    return {f.rule_id for f in run_bytecode_scan(str(path))}


# ── The header, from files py_compile wrote ───────────────────────────────────


@pytest.mark.parametrize(
    "mode,flags",
    [(MODES.TIMESTAMP, 0b00), (MODES.CHECKED_HASH, 0b11), (MODES.UNCHECKED_HASH, 0b01)],
)
def test_the_flags_py_compile_writes_for_each_mode(tmp_path, mode, flags):
    """The layout the rule relies on: 4 byte magic, then 4 byte little endian flags."""
    pyc = compiled(tmp_path, "m", mode, keep_source=True)
    head = pyc.read_bytes()[:16]
    assert head[2:4] == b"\r\n"
    assert struct.unpack("<I", head[4:8])[0] == flags
    header = parse_pyc_header(head)
    assert header is not None and header.flags == flags
    assert header.unchecked_hash == (mode is MODES.UNCHECKED_HASH)


@pytest.mark.parametrize(
    "head,expected",
    [
        (b"", None),
        (b"abcdefgh", None),  # no \r\n at bytes 2-3
        (b"\xcb\x0d\x0d\x0a", None),  # shorter than 8 bytes
        (b"\xcb\x0d\r\n" + struct.pack("<I", 0b01) + b"\x00" * 8, 0b01),
        (b"\xcb\x0d\r\n" + struct.pack("<I", 0b11) + b"\x00" * 8, 0b11),
        # bits other than the two defined ones: CPython rejects the file, so it is not "unchecked"
        (b"\xcb\x0d\r\n" + struct.pack("<I", 0b101) + b"\x00" * 8, 0b101),
    ],
)
def test_parse_pyc_header_table(head, expected):
    header = parse_pyc_header(head)
    if expected is None:
        assert header is None
    else:
        assert header is not None and header.flags == expected
        assert header.unchecked_hash == (expected == 0b01)


def test_a_header_older_than_pep_552_has_no_flags():
    """Before Python 3.7 bytes 4-7 are a timestamp, so a value of 1 there is not a flag."""
    old_magic = struct.pack("<H", 3379) + b"\r\n"  # Python 3.6
    header = parse_pyc_header(old_magic + struct.pack("<I", 1) + b"\x00" * 8)
    assert header == PycHeader(magic_number=3379, flags=None)
    assert not header.unchecked_hash


def test_the_first_magic_number_with_flags_is_3392():
    below = struct.pack("<H", 3391) + b"\r\n" + struct.pack("<I", 1) + b"\x00" * 8
    at = struct.pack("<H", 3392) + b"\r\n" + struct.pack("<I", 1) + b"\x00" * 8
    assert not parse_pyc_header(below).unchecked_hash
    assert parse_pyc_header(at).unchecked_hash


# ── The matching source, by name ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "pyc,source",
    [
        ("pkg/__pycache__/mod.cpython-312.pyc", "pkg/mod.py"),
        ("pkg/__pycache__/mod.cpython-312.opt-1.pyc", "pkg/mod.py"),
        ("pkg/__pycache__/mod.pyc", "pkg/mod.py"),
        ("pkg/mod.pyc", "pkg/mod.py"),
        ("mod.pyc", "mod.py"),
    ],
)
def test_matching_source(pyc, source):
    assert matching_source(Path(pyc)) == Path(source)


# ── The two rules, on real files ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "mode,keep_source,expected",
    [
        # what a normal import writes: a timestamp or a checked hash, beside its source
        (MODES.TIMESTAMP, True, set()),
        (MODES.CHECKED_HASH, True, set()),
        # hash based with checking off, source present: only the first rule
        (MODES.UNCHECKED_HASH, True, {RULE_UNCHECKED_HASH}),
        # the source is gone: the second rule, and the first as well if it is unchecked
        (MODES.TIMESTAMP, False, {RULE_NO_SOURCE}),
        (MODES.CHECKED_HASH, False, {RULE_NO_SOURCE}),
        (MODES.UNCHECKED_HASH, False, {RULE_UNCHECKED_HASH, RULE_NO_SOURCE}),
    ],
)
def test_rules_in_pycache(tmp_path, mode, keep_source, expected):
    assert rules(compiled(tmp_path, "m", mode, keep_source)) == expected


@pytest.mark.parametrize(
    "keep_source,expected",
    [(True, set()), (False, {RULE_NO_SOURCE})],
)
def test_rules_for_a_legacy_pyc_beside_its_source(tmp_path, keep_source, expected):
    """A bare mod.pyc is imported only when mod.py is absent, which is the second rule."""
    pyc = compiled(tmp_path, "m", MODES.TIMESTAMP, keep_source, legacy=True)
    assert rules(pyc) == expected


def test_a_source_in_the_wrong_directory_does_not_match(tmp_path):
    pyc = compiled(tmp_path / "a", "m", MODES.TIMESTAMP, keep_source=False)
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "m.py").write_text("x = 1\n", encoding="utf-8")
    assert rules(pyc) == {RULE_NO_SOURCE}


def test_a_file_that_is_not_bytecode_has_no_finding(tmp_path):
    fake = tmp_path / "fake.pyc"
    fake.write_text("this is not bytecode\n", encoding="utf-8")
    assert run_bytecode_scan(str(fake)) == []
    assert run_bytecode_scan(str(tmp_path / "missing.pyc")) == []  # unreadable: never raises
    assert run_bytecode_scan(str(tmp_path)) == []  # a directory


def test_the_bytecode_is_not_read_past_the_header(tmp_path):
    """Trailing bytes that are not a valid code object change nothing: only the header is read."""
    pyc = compiled(tmp_path, "m", MODES.UNCHECKED_HASH, keep_source=True)
    head = pyc.read_bytes()[:16]
    pyc.write_bytes(head + b"\xff" * 64)
    assert rules(pyc) == {RULE_UNCHECKED_HASH}


# ── What the findings say ─────────────────────────────────────────────────────


def test_finding_fields(tmp_path):
    pyc = compiled(tmp_path, "m", MODES.UNCHECKED_HASH, keep_source=False)
    findings = {f.rule_id: f for f in run_bytecode_scan(str(pyc))}
    assert set(findings) == {RULE_UNCHECKED_HASH, RULE_NO_SOURCE}
    for finding in findings.values():
        assert finding.ave_id == AVE_ID == "AVE-2026-00075"
        assert finding.engine == "bytecode"
        assert finding.severity is Severity.MEDIUM and finding.aivss_score == 4.4
        assert finding.owasp == ["ASI04"] and finding.owasp_mcp == ["MCP04"]
        assert finding.ave_url and finding.ave_url.endswith("AVE-2026-00075")
        assert len(finding.title) <= 80
        assert finding.line is None


def test_the_wording_says_the_contents_were_not_analysed(tmp_path):
    pyc = compiled(tmp_path, "m", MODES.UNCHECKED_HASH, keep_source=False)
    for finding in run_bytecode_scan(str(pyc)):
        assert "Contents not analysed" in finding.description
        text = f"{finding.title} {finding.description} {finding.match}".lower()
        for word in FORBIDDEN_WORDS:
            assert word not in text.split(), (finding.rule_id, word)
        assert str(tmp_path) not in text  # the file name only, never a directory path
    unchecked = next(f for f in run_bytecode_scan(str(pyc)) if f.rule_id == RULE_UNCHECKED_HASH)
    assert "without checking its source" in unchecked.title
