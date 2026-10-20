#!/usr/bin/env python3
"""Derive the counts in README.md from the AVE corpus and the scanner's own rule files.

A count typed by hand drifts: the corpus grew from 80 to 87 records in a week. Every count
in the README sits in an inline marker, and this script writes the value:

    <!-- count:published -->87<!-- /count -->

HTML comments are invisible when the README is rendered and work inside table cells and
sentences, so the prose stays as written. The corpus is pinned by commit in one marker:

    <!-- counts:corpus ref=<40 hex> -->

so `--check` only fails when a rule file or the README changes, not whenever AVE publishes a
record. `--update-ref` moves the pin to the head of the AVE main branch.

    python scripts/sync_record_counts.py                  # rewrite the README
    python scripts/sync_record_counts.py --check          # exit 1 if a count is stale
    python scripts/sync_record_counts.py --update-ref     # move the pin, then rewrite
    python scripts/sync_record_counts.py --corpus FILE    # a local snapshot, no network

Exit status: 0 current (or rewritten), 1 stale (--check only), 2 something could not be read.
Nothing is written when the exit status is 2. Standard library only, and no scanner code is
imported: the rule files are parsed, not run. Not packaged in the wheel.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

# ── Where the data comes from: the one place ──────────────────────────────────

AVE_SITE_URL = "https://aveproject.org"
AVE_REPO = "aveproject/ave"
CORPUS_FILE = "dist/ave-records-latest.json"
CORPUS_URL_TEMPLATE = f"https://raw.githubusercontent.com/{AVE_REPO}/{{ref}}/{CORPUS_FILE}"
HEAD_SHA_URL = f"https://api.github.com/repos/{AVE_REPO}/commits/main"
CORPUS_URL_ENV = "BAWBEL_AVE_CORPUS_URL"  # same name bawbel-mcp uses for the same setting
FETCH_TIMEOUT_SEC = 15
MAX_BYTES = 8 * 1024 * 1024  # the corpus is about 0.7 MB (87 records, 2026-10)
USER_AGENT = "bawbel-scanner-sync-record-counts"

PATTERN_RULES_FILE = "scanner/engines/pattern_engine.py"
YARA_RULES_FILE = "scanner/rules/yara/ave_rules.yar"
SEMGREP_RULES_FILE = "scanner/rules/semgrep/ave_rules.yaml"
MAGIKA_ENGINE_FILE = "scanner/engines/magika_engine.py"
FLOWS_FILE = "scanner/core/toxic_flows/flows.py"
AVE_META_FILE = "scanner/ave_meta.py"

AVE_ID = r"AVE-\d{4}-\d{5}"
AVE_ID_RE = re.compile(rf"^{AVE_ID}$")
COUNT_RE = re.compile(r"<!-- count:(?P<name>[a-z][a-z0-9_]*) -->(?P<value>[^\n]*?)<!-- /count -->")
REF_RE = re.compile(r"<!-- counts:corpus ref=(?P<ref>[0-9a-f]{40}) -->")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

BADGE = (
    "[![AVE Records](https://img.shields.io/badge/AVE_Records-{published}-green.svg)]"
    f"({AVE_SITE_URL})"
)


class CountsError(Exception):
    """Something the script needs could not be read, or is not shaped as expected."""


# ── Reading the corpus ────────────────────────────────────────────────────────


def _https_get(url: str, accept: str) -> bytes:
    """GET an https URL with a timeout and a size cap. Raises CountsError."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.netloc:
        raise CountsError(f"not an https URL: {url}")
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN")
    if token and parts.netloc.endswith("github.com"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    timeout = FETCH_TIMEOUT_SEC
    try:
        # B310/S310: the scheme is checked above, so only https reaches urlopen.
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # nosec B310  # noqa: S310
            body = resp.read(MAX_BYTES + 1)
    except OSError as exc:  # URLError, HTTPError, and TimeoutError are all OSError
        raise CountsError(f"could not fetch {url}: {exc}") from exc
    if len(body) > MAX_BYTES:
        raise CountsError(f"{url} is larger than {MAX_BYTES} bytes")
    return body


def head_sha() -> str:
    """The commit at the head of the AVE main branch."""
    sha = _https_get(HEAD_SHA_URL, "application/vnd.github.sha").decode("utf-8").strip()
    if not SHA_RE.match(sha):
        raise CountsError(f"{HEAD_SHA_URL} did not return a commit sha")
    return sha


def parse_corpus(raw: bytes, source: str) -> list[dict[str, Any]]:
    """The records in a corpus file: a JSON list of records, or an object with `records`."""
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise CountsError(f"{source} is not valid JSON") from exc
    records = data.get("records") if isinstance(data, dict) else data
    if not isinstance(records, list) or not records:
        raise CountsError(f"{source} holds no list of records")
    seen: set[str] = set()
    for rec in records:
        ave_id = rec.get("ave_id") if isinstance(rec, dict) else None
        if not isinstance(ave_id, str) or not AVE_ID_RE.match(ave_id):
            raise CountsError(f"{source} has a record without a valid ave_id")
        if ave_id in seen:
            raise CountsError(f"{source} repeats {ave_id}")
        seen.add(ave_id)
    return records


def corpus_sha256(records: list[dict[str, Any]]) -> str:
    """Hash of the records in a canonical serialization, to name the corpus used."""
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_corpus(source: str) -> list[dict[str, Any]]:
    """Read the corpus from a file path or an https URL."""
    path = Path(source)
    if path.is_file():
        raw = path.read_bytes()
    else:
        raw = _https_get(source, "application/json")
    return parse_corpus(raw, source)


# ── Reading the scanner's rule files ──────────────────────────────────────────


def _read(relative: str, root: Path) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except OSError as exc:
        raise CountsError(f"cannot read {relative}: {exc}") from exc


def _parse(source: str, relative: str) -> ast.Module:
    try:
        return ast.parse(source)
    except SyntaxError as exc:
        raise CountsError(f"{relative} does not parse: {exc.msg}") from exc


def _assigned_value(source: str, name: str, relative: str) -> ast.expr:
    """The value of the last module-level assignment to `name`, found by parsing."""
    value = None
    for node in _parse(source, relative).body:
        if isinstance(node, ast.AnnAssign):
            names = [getattr(node.target, "id", None)]
        elif isinstance(node, ast.Assign):
            names = [getattr(t, "id", None) for t in node.targets]
        else:
            continue
        if name in names:
            value = node.value
    if value is None:
        raise CountsError(f"{name} not found in {relative}")
    return value


def _list_elements(source: str, name: str, relative: str) -> list[ast.expr]:
    """The elements of a module-level list, following how the module builds it.

    Handles a list literal, another list's name, and `a + b`, in source order, so a list
    assembled as `RULES = RULES + RULES_V2` is counted whole. Raises CountsError if the final
    binding is anything else: an unrecognized shape must not be counted wrongly.
    """
    env: dict[str, list[ast.expr]] = {}

    def resolve(expr: ast.expr | None) -> list[ast.expr] | None:
        if isinstance(expr, ast.List):
            return list(expr.elts)
        if isinstance(expr, ast.Name):
            return env.get(expr.id)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left, right = resolve(expr.left), resolve(expr.right)
            return None if left is None or right is None else left + right
        return None

    for node in _parse(source, relative).body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets, value = [node.target.id], node.value
        elif isinstance(node, ast.Assign):
            targets, value = [getattr(t, "id", "") for t in node.targets], node.value
        else:
            continue
        elements = resolve(value)
        for target in targets:
            if elements is not None:
                env[target] = elements
            elif target == name:
                raise CountsError(f"{name} in {relative} is built in a way this script cannot read")
    if name not in env:
        raise CountsError(f"{name} not found in {relative}")
    return env[name]


def _string_key(node: ast.expr, key: str) -> str | None:
    """The constant string value stored under `key` in a dict literal, if there is one."""
    if not isinstance(node, ast.Dict):
        return None
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else None
    return None


def pattern_rules(root: Path) -> tuple[int, set[str]]:
    """Number of PATTERN_RULES entries (V1 and V2 joined) and the AVE ids they cite."""
    elements = _list_elements(_read(PATTERN_RULES_FILE, root), "PATTERN_RULES", PATTERN_RULES_FILE)
    rules = [e for e in elements if _string_key(e, "rule_id")]
    if len(rules) != len(elements):
        raise CountsError(f"an entry in PATTERN_RULES ({PATTERN_RULES_FILE}) has no rule_id")
    ids = {i for i in (_string_key(e, "ave_id") for e in rules) if i}
    return len(rules), ids


def yara_rules(root: Path) -> tuple[int, set[str]]:
    """Number of YARA rules and the AVE ids they cite. Every rule must cite one."""
    text = _read(YARA_RULES_FILE, root)
    chunks = re.split(r"(?m)^\s*rule\s+\w+", text)[1:]
    if not chunks:
        raise CountsError(f"no rules found in {YARA_RULES_FILE}")
    ids: set[str] = set()
    for chunk in chunks:
        found = re.findall(rf'ave_id\s*=\s*"({AVE_ID})"', chunk)
        if not found:
            raise CountsError(f"a rule in {YARA_RULES_FILE} cites no ave_id")
        ids.update(found)
    return len(chunks), ids


def semgrep_rules(root: Path) -> tuple[int, set[str]]:
    """Number of Semgrep rules and the AVE ids they cite.

    The file is read line by line instead of with a YAML parser, which the core install does
    not have. It refuses to continue unless there is exactly one `ave_id` per rule.
    """
    text = _read(SEMGREP_RULES_FILE, root)
    rule_count = len(re.findall(r"(?m)^  - id:\s*\S", text))
    ids = re.findall(rf"(?m)^\s+ave_id:\s*[\"']?({AVE_ID})", text)
    if rule_count == 0 or rule_count != len(ids):
        raise CountsError(
            f"{SEMGREP_RULES_FILE}: {rule_count} rules but {len(ids)} ave_id lines; "
            "the layout is not the one this script reads"
        )
    return rule_count, set(ids)


def magika_ids(root: Path) -> set[str]:
    """AVE ids the Magika engine reports (keyword argument `ave_id="..."`)."""
    text = _read(MAGIKA_ENGINE_FILE, root)
    return set(re.findall(rf'ave_id\s*=\s*"({AVE_ID})"', text))


def chain_count(root: Path) -> int:
    """Number of FlowDef entries in FLOW_DEFINITIONS."""
    elements = _list_elements(_read(FLOWS_FILE, root), "FLOW_DEFINITIONS", FLOWS_FILE)
    flows = [
        e for e in elements if isinstance(e, ast.Call) and getattr(e.func, "id", "") == "FlowDef"
    ]
    if len(flows) != len(elements):
        raise CountsError(f"an entry in FLOW_DEFINITIONS ({FLOWS_FILE}) is not a FlowDef call")
    return len(flows)


def metadata_ids(root: Path) -> set[str]:
    """The AVE ids that have an entry in the scanner's AVE_META table."""
    value = _assigned_value(_read(AVE_META_FILE, root), "AVE_META", AVE_META_FILE)
    if not isinstance(value, ast.Dict):
        raise CountsError(f"AVE_META in {AVE_META_FILE} is not a dict literal")
    return {k.value for k in value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}


# ── Measuring ─────────────────────────────────────────────────────────────────


def format_id_ranges(ids: set[str] | list[str]) -> str:
    """Compact ids: 'AVE-2026-00041 to 00045, 00049 to 00051'. The year prefix is written once."""
    parsed = sorted((i[:-5], int(i[-5:])) for i in ids)
    if not parsed:
        return "none"
    runs: list[list[tuple[str, int]]] = []
    for item in parsed:
        if runs and runs[-1][-1][0] == item[0] and runs[-1][-1][1] + 1 == item[1]:
            runs[-1].append(item)
        else:
            runs.append([item])
    parts = []
    for n, run in enumerate(runs):
        first, last = run[0], run[-1]
        head = (
            f"{first[0]}{first[1]:05d}"
            if n == 0 or first[0] != runs[n - 1][0][0]
            else f"{first[1]:05d}"
        )
        parts.append(head if len(run) == 1 else f"{head} to {last[1]:05d}")
    return ", ".join(parts)


def measure(records: list[dict[str, Any]], root: Path = ROOT) -> tuple[dict[str, str], list[str]]:
    """Every count the README can carry, as strings, and any warnings.

    Warnings: rules or metadata that cite an ave_id the corpus does not publish.
    """
    published = {r["ave_id"] for r in records}
    pattern_n, pattern_ids = pattern_rules(root)
    yara_n, yara_ids = yara_rules(root)
    semgrep_n, semgrep_ids = semgrep_rules(root)
    static = pattern_ids | yara_ids | semgrep_ids
    cited = static | magika_ids(root)
    meta = metadata_ids(root)

    warnings = []
    for label, ids in (("rules", cited), ("AVE_META", meta)):
        unknown = sorted(ids - published)
        if unknown:
            warnings.append(f"{label} cite ids the corpus does not publish: {', '.join(unknown)}")

    detected = cited & published
    uncovered = published - detected
    stages = {r["ave_id"]: str(r.get("detection_stage")) for r in records}
    by_stage = [stages[i] for i in uncovered]
    schema_versions = sorted({str(r.get("schema_version")) for r in records})
    aivss_specs = sorted(
        {str((r.get("aivss") or {}).get("spec_version")) for r in records if r.get("aivss")}
    )
    metadata_only = (meta & published) - detected

    values = {
        "published": str(len(published)),
        "id_first": min(published),
        "id_last": max(published),
        "detected": str(len(detected)),
        "detected_static": str(len(static & published)),
        "magika_only_ids": format_id_ranges((cited - static) & published),
        "metadata_only": str(len(metadata_only)),
        "metadata_only_ids": format_id_ranges(metadata_only),
        "uncovered": str(len(uncovered)),
        "uncovered_static": str(by_stage.count("static_detection")),
        "uncovered_runtime": str(sum(1 for s in by_stage if s.startswith("runtime"))),
        "runtime_observed": str(by_stage.count("runtime_observed")),
        "runtime_drift_detected": str(by_stage.count("runtime_drift_detected")),
        "schema_version": " and ".join(schema_versions),
        "aivss_spec": " and ".join(aivss_specs),
        "pattern_rules": str(pattern_n),
        "yara_rules": str(yara_n),
        "semgrep_rules": str(semgrep_n),
        "chains": str(chain_count(root)),
    }
    values["badge"] = BADGE.format(published=values["published"])
    return values, warnings


# ── Editing the README ────────────────────────────────────────────────────────


def pinned_ref(text: str) -> str:
    """The commit the README pins the corpus to."""
    matches = REF_RE.findall(text)
    if len(matches) != 1:
        raise CountsError(
            f"README.md needs exactly one '<!-- counts:corpus ref=<40 hex> -->' marker, "
            f"found {len(matches)}"
        )
    return matches[0]


def set_ref(text: str, ref: str) -> str:
    pinned_ref(text)  # exactly one marker, or CountsError
    return REF_RE.sub(f"<!-- counts:corpus ref={ref} -->", text)


def apply_counts(text: str, values: dict[str, str]) -> tuple[str, list[tuple[int, str, str, str]]]:
    """Rewrite every marker. Returns the new text and (line, name, old, new) for each change."""
    changes: list[tuple[int, str, str, str]] = []
    unknown = sorted({m["name"] for m in COUNT_RE.finditer(text)} - set(values))
    if unknown:
        raise CountsError(f"README.md has markers with no measurement: {', '.join(unknown)}")

    def replace(match: re.Match) -> str:
        name, old, new = match["name"], match["value"], values[match["name"]]
        if old != new:
            line = text.count("\n", 0, match.start()) + 1
            changes.append((line, name, old, new))
        return f"<!-- count:{name} -->{new}<!-- /count -->"

    return COUNT_RE.sub(replace, text), changes


# ── Command line ──────────────────────────────────────────────────────────────


def corpus_source(args: argparse.Namespace, ref: str) -> str:
    """Where to read the corpus: --corpus, then the environment, then the pinned commit."""
    return args.corpus or os.environ.get(CORPUS_URL_ENV) or CORPUS_URL_TEMPLATE.format(ref=ref)


def run(args: argparse.Namespace) -> int:
    readme = Path(args.readme)
    try:
        text = readme.read_text(encoding="utf-8")
    except OSError as exc:
        raise CountsError(f"cannot read {readme}: {exc}") from exc

    ref = head_sha() if args.update_ref else pinned_ref(text)
    source = corpus_source(args, ref)
    records = load_corpus(source)
    values, warnings = measure(records)

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    new_text, changes = apply_counts(set_ref(text, ref) if args.update_ref else text, values)
    pin_changed = args.update_ref and ref != pinned_ref(text)
    print(f"corpus: {len(records)} records, sha256 {corpus_sha256(records)[:16]}, {source}")

    if args.check:
        for line, name, old, new in changes:
            print(
                f"{readme.name}:{line}: count:{name} is {old!r}, measured {new!r}", file=sys.stderr
            )
        if changes:
            return 1
        print("README counts match the corpus and the rule files")
        return 0

    if changes or pin_changed:
        readme.write_text(new_text, encoding="utf-8")
    for line, name, old, new in changes:
        print(f"{readme.name}:{line}: count:{name} {old!r} -> {new!r}")
    print(
        f"{readme.name}: {len(changes)} count(s) updated" + (", pin moved" if pin_changed else "")
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="change nothing; exit 1 if stale")
    parser.add_argument("--corpus", help="a corpus file or https URL (default: the pinned commit)")
    parser.add_argument("--update-ref", action="store_true", help="pin the head of AVE main")
    parser.add_argument("--readme", default=str(README), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.check and args.update_ref:
        parser.error("--check changes nothing, so it cannot be combined with --update-ref")
    try:
        return run(args)
    except CountsError as exc:
        print(f"sync_record_counts: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
