#!/usr/bin/env python3
"""Write scanner/_ave_snapshot.py from the AVE corpus that README.md pins.

The scanner never reads AVE data at scan time over the network, and it never keeps a copy typed
by hand (docs/AVE-CONSUMPTION.md in bawbel/.github, R2, R3, R4, R5, R9). It reads this
vendored snapshot, and this script is the only thing that writes it:

    python scripts/sync_ave_snapshot.py                # rewrite the snapshot
    python scripts/sync_ave_snapshot.py --check        # exit 1 if it is stale or was edited
    python scripts/sync_ave_snapshot.py --corpus FILE  # a local corpus file, no network

The corpus is the one `scripts/sync_record_counts.py` already uses: the file
`dist/ave-records-latest.json` of aveproject/ave at the commit pinned by the README marker
`<!-- counts:corpus ref=<40 hex> -->`. There is one pin. Moving it (`sync_record_counts.py
--update-ref`) makes the snapshot stale until this script is run again.

The snapshot file records where its data came from: `CORPUS_SHA256` (of the exact bytes
consumed), `SCHEMA_VERSION`, `RECORD_COUNT`, `SOURCE_URL` and `GENERATED_AT`. Running the
script again on the same corpus writes the same bytes, including the timestamp.

`--check` does two things. Offline, it verifies the file is intact: its `CONTENT_SHA256` and
`RECORD_COUNT` match the data in it, which catches an edit by hand. Then it fetches the pinned
corpus and verifies the file is exactly what this script would write from it. If the network is
unreachable it prints a warning, skips that second comparison, and does not fail on it. A
corpus it can read but does not accept (an unknown schema major, a missing field) is an error.

Exit status: 0 current (or written), 1 stale or edited (--check only), 2 something could not be
read. Nothing is written when the exit status is 2. Standard library only, and no scanner code
is imported. Not packaged in the wheel.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The corpus source, the pin, the fetch and the schema-free parts of reading it are
# scripts/sync_record_counts.py. They are imported, not copied, so there is one of each.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sync_record_counts as counts  # noqa: E402

CountsError = counts.CountsError
FetchError = counts.FetchError

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SNAPSHOT = ROOT / "scanner" / "_ave_snapshot.py"
SNAPSHOT_RELATIVE = "scanner/_ave_snapshot.py"

# ── What the scanner uses, and which schema this reads ────────────────────────

# R4: accept the majors it knows, warn on a newer minor, refuse an unknown major.
KNOWN_SCHEMA_MAJOR = 1
KNOWN_SCHEMA_MINOR = 3  # the newest minor this script has been checked against
SCHEMA_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")

# Fields every record must carry. A record without one is refused: the scanner would
# otherwise have to invent the value, and R8 says missing is missing.
TEXT_FIELDS = (
    "title",
    "severity",
    "evidence_kind_default",
    "detection_stage",
    "detection_layer",
)
NUMBER_FIELDS = ("aivss_score", "confidence_baseline")
REQUIRED_LIST_FIELDS = ("owasp_mcp",)
# Fields AVE does not provide for every record. When a record has none, the snapshot says None
# ("not provided"); the scanner does not fill it in.
OPTIONAL_LIST_FIELDS = ("owasp_asi", "mitre_atlas", "nist_ai_rmf")
# The order the fields are written in. Every name above appears exactly once.
FIELD_ORDER = (
    "title",
    "severity",
    "aivss_score",
    "confidence_baseline",
    "evidence_kind_default",
    "detection_stage",
    "detection_layer",
    "owasp_mcp",
    "owasp_asi",
    "mitre_atlas",
    "nist_ai_rmf",
)

HEADER_CONSTANTS = (
    "CORPUS_SHA256",
    "SCHEMA_VERSION",
    "RECORD_COUNT",
    "SOURCE_URL",
    "GENERATED_AT",
    "CONTENT_SHA256",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# ── Reading and validating the corpus ─────────────────────────────────────────


def check_schema(records: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """R4. Returns the schema versions found, joined, and any warnings. Refuses an unknown major."""
    versions: set[str] = set()
    newer: set[str] = set()
    for rec in records:
        version = rec.get("schema_version")
        match = SCHEMA_RE.match(version) if isinstance(version, str) else None
        if not match:
            raise CountsError(f"{rec['ave_id']} has no readable schema_version: {version!r}")
        if int(match["major"]) != KNOWN_SCHEMA_MAJOR:
            raise CountsError(
                f"{rec['ave_id']} has schema_version {version}; "
                f"this script reads major {KNOWN_SCHEMA_MAJOR} only"
            )
        if int(match["minor"]) > KNOWN_SCHEMA_MINOR:
            newer.add(version)
        versions.add(version)
    warnings = []
    if newer:
        warnings.append(
            f"schema {', '.join(sorted(newer))} is newer than 1.{KNOWN_SCHEMA_MINOR}, "
            "which this script was checked against; fields it does not know are ignored"
        )
    return " and ".join(sorted(versions)), warnings


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) and v for v in value)


def build_snapshot(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The fields the scanner uses, for every record, in id order. Raises CountsError.

    Fields the scanner does not use are dropped. A required field that is missing or of the wrong
    type refuses the corpus, naming the record and the field.
    """
    snapshot: dict[str, dict[str, Any]] = {}
    for rec in sorted(records, key=lambda r: r["ave_id"]):
        ave_id = rec["ave_id"]
        entry: dict[str, Any] = {}
        for name in TEXT_FIELDS:
            if not isinstance(rec.get(name), str) or not rec[name]:
                raise CountsError(f"{ave_id}: {name} is missing or not text")
        for name in NUMBER_FIELDS:
            if not _is_number(rec.get(name)):
                raise CountsError(f"{ave_id}: {name} is missing or not a number")
        for name in REQUIRED_LIST_FIELDS:
            if not _string_list(rec.get(name)):
                raise CountsError(f"{ave_id}: {name} is missing or not a list of text")
        for name in OPTIONAL_LIST_FIELDS:
            if rec.get(name) is not None and not _string_list(rec[name]):
                raise CountsError(f"{ave_id}: {name} is present but not a list of text")
        for name in FIELD_ORDER:
            entry[name] = rec.get(name)
        snapshot[ave_id] = entry
    return snapshot


# ── Writing the snapshot file ─────────────────────────────────────────────────


def content_sha256(snapshot: dict[str, Any]) -> str:
    """SHA-256 of the snapshot data in a canonical form, so an edit to any value changes it."""
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _literal(value: Any) -> str:
    """A JSON-compatible value as Python source."""
    return "None" if value is None else json.dumps(value, ensure_ascii=True)


DOCSTRING = '''"""
Bawbel Scanner - snapshot of the published AVE records. GENERATED, do not edit.

Written by scripts/sync_ave_snapshot.py from the AVE corpus that README.md pins. The scanner
reads AVE data from here, offline, and keeps no copy of it anywhere else
(docs/AVE-CONSUMPTION.md in bawbel/.github, R5 and R9). `scripts/sync_ave_snapshot.py --check`
fails when this file is stale or has been edited by hand, and CI runs it.

Provenance (R3):
    CORPUS_SHA256   SHA-256 of the exact bytes of the corpus file that was read
    SCHEMA_VERSION  the schema_version values found in that corpus
    RECORD_COUNT    the number of records in AVE_SNAPSHOT
    SOURCE_URL      where the corpus came from
    GENERATED_AT    when this file was written (UTC); unchanged when the corpus is unchanged
    CONTENT_SHA256  SHA-256 of AVE_SNAPSHOT in canonical JSON, to detect an edit by hand

A field AVE does not provide for a record is None here. The scanner does not fill it in.
"""'''


def render(snapshot: dict[str, dict[str, Any]], meta: dict[str, Any], generated_at: str) -> str:
    """The exact text of scanner/_ave_snapshot.py."""
    lines = [
        "# GENERATED by scripts/sync_ave_snapshot.py. Do not edit by hand.",
        "# fmt: off",
        "# flake8: noqa",
        DOCSTRING,
        "",
        f"CORPUS_SHA256 = {_literal(meta['corpus_sha256'])}",
        f"SCHEMA_VERSION = {_literal(meta['schema_version'])}",
        f"RECORD_COUNT = {_literal(len(snapshot))}",
        f"SOURCE_URL = {_literal(meta['source_url'])}",
        f"GENERATED_AT = {_literal(generated_at)}",
        f"CONTENT_SHA256 = {_literal(content_sha256(snapshot))}",
        "",
        "AVE_SNAPSHOT: dict[str, dict] = {",
    ]
    for ave_id, entry in snapshot.items():
        lines.append(f"    {_literal(ave_id)}: {{")
        for name in FIELD_ORDER:
            lines.append(f"        {_literal(name)}: {_literal(entry[name])},")
        lines.append("    },")
    lines.append("}")
    return "\n".join(lines) + "\n"


def source_label(source: str) -> str:
    """What to stamp as SOURCE_URL: an https URL as given, a local file as `file:<name>`.

    A snapshot made from a local file can never equal the one made from the pinned URL, so it
    cannot pass `--check`. That is intended: the one source is the published artifact (R2).
    """
    return source if source.startswith("https://") else f"file:{Path(source).name}"


# ── Reading the snapshot file back, without running it ────────────────────────


def parse_snapshot(text: str) -> dict[str, Any]:
    """The header constants and AVE_SNAPSHOT of a snapshot file, read with ast, never executed."""
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise CountsError(f"{SNAPSHOT_RELATIVE} does not parse: {exc.msg}") from exc
    found: dict[str, Any] = {}
    wanted = set(HEADER_CONSTANTS) | {"AVE_SNAPSHOT"}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names, value = [node.target.id], node.value
        elif isinstance(node, ast.Assign):
            names, value = [getattr(t, "id", "") for t in node.targets], node.value
        else:
            continue
        for name in names:
            if name in wanted and value is not None:
                try:
                    found[name] = ast.literal_eval(value)
                except ValueError as exc:
                    raise CountsError(f"{name} in {SNAPSHOT_RELATIVE} is not a literal") from exc
    return found


def integrity_problems(found: dict[str, Any]) -> list[str]:
    """What is wrong with the file by itself, without the corpus. Empty when it is intact."""
    problems = []
    for name in HEADER_CONSTANTS + ("AVE_SNAPSHOT",):
        if name not in found:
            problems.append(f"{name} is missing")
    if problems:
        return problems
    data = found["AVE_SNAPSHOT"]
    if not isinstance(data, dict):
        return ["AVE_SNAPSHOT is not a dict"]
    for name in ("CORPUS_SHA256", "CONTENT_SHA256"):
        if not isinstance(found[name], str) or not SHA256_RE.match(found[name]):
            problems.append(f"{name} is not a sha256 hex digest")
    if found["RECORD_COUNT"] != len(data):
        problems.append("RECORD_COUNT does not match the records in AVE_SNAPSHOT")
    if found["CONTENT_SHA256"] != content_sha256(data):
        problems.append("CONTENT_SHA256 does not match AVE_SNAPSHOT: the data was edited by hand")
    return problems


# ── Command line ──────────────────────────────────────────────────────────────


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CountsError(f"cannot read {path}: {exc}") from exc


def build(args: Namespace, now: str) -> tuple[str, dict[str, Any], list[str]]:
    """Read the pinned corpus and return the text to write, its provenance, and warnings.

    The timestamp of the file already on disk is kept when the corpus and its source are the same,
    so running the script twice writes the same bytes.
    """
    readme_text = _read_text(Path(args.readme))
    if readme_text is None:
        raise CountsError(f"cannot read {args.readme}")
    source = counts.corpus_source(args, counts.pinned_ref(readme_text))
    records, digest = counts.load_corpus(source)
    versions, warnings = check_schema(records)
    snapshot = build_snapshot(records)
    meta = {
        "corpus_sha256": digest,
        "schema_version": versions,
        "source_url": source_label(source),
    }
    generated_at = now
    existing = _read_text(Path(args.snapshot))
    if existing is not None:
        try:
            found = parse_snapshot(existing)
        except CountsError:
            found = {}
        if (
            found.get("CORPUS_SHA256") == digest
            and found.get("SOURCE_URL") == meta["source_url"]
            and isinstance(found.get("GENERATED_AT"), str)
        ):
            generated_at = found["GENERATED_AT"]
    return render(snapshot, meta, generated_at), meta, warnings


def run(args: Namespace) -> int:
    snapshot_path = Path(args.snapshot)
    if not args.check:
        text, meta, warnings = build(args, _utc_now())
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        current = _read_text(snapshot_path)
        print(f"corpus: sha256 {meta['corpus_sha256']}, {meta['source_url']}")
        if current == text:
            print(f"{SNAPSHOT_RELATIVE}: already current")
            return 0
        snapshot_path.write_text(text, encoding="utf-8")
        print(f"{SNAPSHOT_RELATIVE}: written")
        return 0

    # --check, part one: the file by itself. Needs no network.
    current = _read_text(snapshot_path)
    if current is None:
        print(f"{SNAPSHOT_RELATIVE}: missing. Run scripts/sync_ave_snapshot.py", file=sys.stderr)
        return 1
    try:
        found = parse_snapshot(current)
    except CountsError as exc:
        print(f"{exc}: it was edited by hand", file=sys.stderr)
        return 1
    problems = integrity_problems(found)
    for problem in problems:
        print(f"{SNAPSHOT_RELATIVE}: {problem}", file=sys.stderr)

    # Part two: the file against the pinned corpus.
    try:
        expected, meta, warnings = build(args, found.get("GENERATED_AT") or _utc_now())
    except FetchError as exc:
        print(
            f"warning: the corpus could not be fetched, so freshness was not checked: {exc}",
            file=sys.stderr,
        )
        return 1 if problems else 0
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"corpus: sha256 {meta['corpus_sha256']}, {meta['source_url']}")
    if found.get("CORPUS_SHA256") != meta["corpus_sha256"]:
        print(
            f"{SNAPSHOT_RELATIVE}: stale. It was made from corpus sha256 "
            f"{found.get('CORPUS_SHA256')}, the pinned corpus is {meta['corpus_sha256']}. "
            "Run scripts/sync_ave_snapshot.py",
            file=sys.stderr,
        )
        return 1
    if expected != current:
        print(
            f"{SNAPSHOT_RELATIVE}: differs from what scripts/sync_ave_snapshot.py writes from "
            "the pinned corpus. It was edited by hand, or the script changed. "
            "Run scripts/sync_ave_snapshot.py",
            file=sys.stderr,
        )
        return 1
    if problems:
        return 1
    print(f"{SNAPSHOT_RELATIVE}: matches the pinned corpus")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="change nothing; exit 1 if stale")
    parser.add_argument("--corpus", help="a corpus file or https URL (default: the pinned commit)")
    parser.add_argument("--readme", default=str(README), help=argparse.SUPPRESS)
    parser.add_argument("--snapshot", default=str(SNAPSHOT), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        return run(args)
    except CountsError as exc:
        print(f"sync_ave_snapshot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
