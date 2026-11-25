"""
Bawbel Scanner - precompiled bytecode (.pyc) check.

Two rules, both citing AVE-2026-00075 (bytecode poisoning). Neither reads the bytecode: the
header and the presence of a source file are all that is looked at, and every finding says the
contents were not analysed.

    bawbel-pyc-unchecked-hash   the header says hash based with source checking off (PEP 552), so
                                Python loads the file without checking its source
    bawbel-pyc-no-source        no matching source file is beside it (see core/bytecode.py)

Normal imports write neither. A .pyc is written next to the source it was compiled from, with a
timestamp or a checked hash.

This is a file-level check, not a stage of scan(): a directory scan does not hand .pyc files to
scan(), and the text engines are not run on them. It is not in ENGINES and reports nothing to the
engine ledger. Never raises; an unreadable file gives no finding.
"""

from __future__ import annotations

from pathlib import Path

from scanner.ave_meta import get_ave_meta
from scanner.config import PYC_HEADER_BYTES
from scanner.core.bytecode import matching_source, parse_pyc_header
from scanner.messages import Info, Logs
from scanner.models import Finding, Severity
from scanner.utils import ave_record_url, get_logger

log = get_logger(__name__)

AVE_ID = "AVE-2026-00075"
ENGINE_LABEL = "bytecode"
RULE_UNCHECKED_HASH = "bawbel-pyc-unchecked-hash"
RULE_NO_SOURCE = "bawbel-pyc-no-source"

# Severity, score and crosswalk are the values of the record in the corpus the README pins
# (MEDIUM, AIVSS 4.4, ASI04, MCP04). The rule shows less than the record's class (no comparison of
# the bytecode with its source), which is why the descriptions say what was not checked.
_SEVERITY = Severity.MEDIUM
_AIVSS_SCORE = 4.4
_OWASP = ["ASI04"]
_OWASP_MCP = ["MCP04"]


def _finding(rule_id: str, title: str, description: str, match: str) -> Finding:
    meta = get_ave_meta(AVE_ID, ENGINE_LABEL)
    return Finding(
        rule_id=rule_id,
        ave_id=AVE_ID,
        title=title,
        description=description,
        severity=_SEVERITY,
        aivss_score=_AIVSS_SCORE,
        line=None,
        match=match,
        engine=ENGINE_LABEL,
        owasp=list(_OWASP),
        owasp_mcp=list(_OWASP_MCP),
        piranha_url=ave_record_url(AVE_ID),
        ave_url=ave_record_url(AVE_ID),
        confidence=meta.confidence_baseline,
        evidence_kind=meta.evidence_kind,
        detection_stage=meta.detection_stage,
        detection_layer=meta.detection_layer,
    )


def run_bytecode_scan(file_path: str) -> list[Finding]:
    """
    Check one .pyc file's header and whether its source is beside it.

    Args:
        file_path: path to a regular file. The caller has already rejected symlinks.

    Returns:
        Zero, one or two Findings. Empty if the file cannot be read or does not start with a
        .pyc header (it is then not bytecode that Python would load).
    """
    path = Path(file_path)
    try:
        with path.open("rb") as handle:
            head = handle.read(PYC_HEADER_BYTES)
    except OSError as exc:
        log.warning(Logs.BYTECODE_HEADER_UNREADABLE, path.name, type(exc).__name__)
        return []

    header = parse_pyc_header(head)
    if header is None:
        return []

    findings: list[Finding] = []
    if header.unchecked_hash:
        findings.append(
            _finding(
                RULE_UNCHECKED_HASH,
                Info.PYC_UNCHECKED_TITLE,
                Info.PYC_UNCHECKED_DESCRIPTION.format(name=path.name),
                "flags=0b01 (unchecked hash)",
            )
        )

    source = matching_source(path)
    try:
        has_source = source.is_file()
    except OSError:
        has_source = True  # cannot tell, so do not claim it is missing
    if not has_source:
        findings.append(
            _finding(
                RULE_NO_SOURCE,
                Info.PYC_NO_SOURCE_TITLE,
                Info.PYC_NO_SOURCE_DESCRIPTION.format(name=path.name, source=source.name),
                f"no {source.name}",
            )
        )
    return findings
