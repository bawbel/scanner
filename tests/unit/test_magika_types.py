"""
The Magika engine's dangerous-type list. Issue #186.

`_DANGEROUS_TYPES` is keyed by Magika's own labels. It held `python_pyc`, `pe32`, `pe64` and
`jsp`, which are not labels of any Magika version in the supported range (0.5.1, 0.6.1 and 1.0.3
were read), so those types could never match. Magika calls compiled Python `pythonbytecode` and a
Windows executable `pebin`, and has no JSP label.

Three layers, so a dead key cannot come back whether or not Magika is installed:

  - without Magika: no key is one of the names known to be dead
  - with Magika: every key is a label of the installed version (this fails, it does not skip, on
    a key that is not a label), and each type Magika can identify from a harmless sample gets the
    finding. The samples are tiny and are never run or imported.
  - with Magika: a real .pyc handed to scan() gets the finding and the text engines are skipped

No CI job installs Magika at the time of writing, so the second and third layers run where it is
installed (`pip install "bawbel-scanner[magika]"`).

Run: pytest tests/unit/test_magika_types.py -q
"""

import pickle
import py_compile
import struct
from pathlib import Path

import pytest

import scanner.engines.magika_engine as magika_engine
from scanner.engines.magika_engine import _DANGEROUS_TYPES, run_magika_scan

DEAD_KEYS = {"python_pyc", "pe32", "pe64", "jsp"}
EXPECTED_KEYS = {
    "elf",
    "pebin",
    "pythonbytecode",
    "php",
    "shell",
    "batch",
    "powershell",
    "pickle",
}


def test_no_key_is_a_name_known_to_be_dead():
    assert not DEAD_KEYS & set(_DANGEROUS_TYPES)


def test_the_keys_are_the_ones_the_engine_documents():
    assert set(_DANGEROUS_TYPES) == EXPECTED_KEYS


# ── With Magika installed ─────────────────────────────────────────────────────


@pytest.fixture()
def magika_enabled(monkeypatch):
    """Switch the engine on. tests/test_scanner.py reloads the module with the engine disabled and
    does not reload it again, so the module can be left disabled for the rest of the session."""
    monkeypatch.setattr(magika_engine, "MAGIKA_ENABLED", True)


@pytest.fixture(scope="module")
def magika_labels():
    magika = pytest.importorskip("magika")
    try:
        from magika.types import ContentTypeLabel

        return {label.value for label in ContentTypeLabel}
    except ImportError:  # an older Magika without the enum: read the label list it ships
        import json

        config = Path(magika.__file__).parent / "config"
        for name in ("content_types_kb.min.json", "content_types_config.json"):
            if (config / name).exists():
                return set(json.loads((config / name).read_text(encoding="utf-8")))
        raise


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_every_key_is_a_label_of_the_installed_magika(magika_labels, key):
    """Strict: a key that is not a Magika label fails here rather than silently never matching."""
    assert key in magika_labels, f"{key!r} is not a label of the installed Magika"


def _pe() -> bytes:
    """A PE header with no sections and no code: a DOS header, the PE signature, two headers."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    coff = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)
    return bytes(dos) + b"PE\0\0" + coff + struct.pack("<H", 0x20B) + bytes(238)


SAMPLES = {
    "pebin": _pe(),
    "php": b"<?php\n// greeting\n$name = 'world';\necho 'Hello ' . $name . \"\\n\";\n"
    b"function add($a, $b) { return $a + $b; }\n?>\n",
    "shell": b'#!/bin/sh\n# greeting\nname=world\necho "Hello $name"\nfor i in 1 2 3; do\n'
    b'  echo "$i"\ndone\n',
    "batch": b"@echo off\r\nREM greeting\r\nset NAME=world\r\necho Hello %NAME%\r\n"
    b"for %%i in (1 2 3) do echo %%i\r\npause\r\n",
    "powershell": b"# greeting script\r\nparam([string]$Name = 'world')\r\n"
    b"$ErrorActionPreference = 'Stop'\r\nfunction Get-Greeting {\r\n    param($Who)\r\n"
    b'    return "Hello $Who"\r\n}\r\nWrite-Host (Get-Greeting -Who $Name)\r\n'
    b"Get-ChildItem -Path . | Where-Object { $_.Length -gt 0 } | ForEach-Object { $_.Name }\r\n"
    b"$items = @(1, 2, 3)\r\nforeach ($i in $items) { Write-Output $i }\r\n",
    "pickle": pickle.dumps({"greeting": "hello", "numbers": [1, 2, 3]}),
}


def _pyc(directory: Path) -> bytes:
    source = directory / "m.py"
    source.write_text('"""A docstring."""\nVALUE = 1\n', encoding="utf-8")
    target = directory / "m.pyc"
    py_compile.compile(str(source), cfile=str(target), doraise=True)
    return target.read_bytes()


@pytest.mark.parametrize("label", sorted([*SAMPLES, "pythonbytecode"]))
def test_a_file_of_each_type_gets_the_dangerous_type_finding(
    magika_labels, magika_enabled, tmp_path, label
):
    """The file has a skill extension but the content of another type, as in a disguised file."""
    data = _pyc(tmp_path) if label == "pythonbytecode" else SAMPLES[label]
    sample = tmp_path / f"{label}-sample.md"
    sample.write_bytes(data)
    findings = run_magika_scan(str(sample))
    assert [f.rule_id for f in findings] == ["bawbel-content-type-dangerous"], findings
    assert findings[0].match == f"detected: {label}"
    assert findings[0].ave_id == "AVE-2026-00024"
    assert findings[0].engine == "magika"


def test_a_pyc_handed_to_scan_gets_the_finding_and_the_text_engines_are_skipped(
    magika_labels, magika_enabled, tmp_path
):
    from scanner.scanner import scan

    target = tmp_path / "m.pyc"
    target.write_bytes(_pyc(tmp_path))
    result = scan(str(target))
    assert [f.rule_id for f in result.findings if f.engine == "magika"] == [
        "bawbel-content-type-dangerous"
    ]
    skipped = {d.engine: d.reason for d in result.engines_degraded}
    assert skipped.get("pattern") == "skipped_content_type"
