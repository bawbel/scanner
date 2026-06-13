"""
Bawbel Scanner - Finding deduplication.

Two-pass deduplication:
  Pass 1: per rule_id — keeps highest-severity finding.
  Pass 2: per (ave_id) — keeps highest-priority engine finding,
          removing cross-engine duplicates for the same AVE on the same line.
"""

from scanner.models import Finding
from scanner.models.severity import SEVERITY_SCORES

_ENGINE_PRIORITY: dict[str, int] = {
    "pattern": 0,
    "yara": 1,
    "semgrep": 2,
    "llm": 3,
    "sandbox": 4,
}


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings across engines, keeping the most informative per AVE."""
    by_rule: dict[str, Finding] = {}
    for f in findings:
        existing = by_rule.get(f.rule_id)
        if existing is None or SEVERITY_SCORES.get(f.severity.value, 0) > SEVERITY_SCORES.get(
            existing.severity.value, 0
        ):
            by_rule[f.rule_id] = f

    by_ave: dict[str, Finding] = {}
    no_ave: list[Finding] = []

    for f in by_rule.values():
        if not f.ave_id:
            no_ave.append(f)
            continue
        existing = by_ave.get(f.ave_id)
        if existing is None:
            by_ave[f.ave_id] = f
            continue

        f_has_line = f.line is not None
        ex_has_line = existing.line is not None

        if f_has_line and not ex_has_line:
            by_ave[f.ave_id] = f
        elif not f_has_line and ex_has_line:
            pass
        else:
            if _ENGINE_PRIORITY.get(f.engine, 99) < _ENGINE_PRIORITY.get(existing.engine, 99):
                by_ave[f.ave_id] = f

    return list(by_ave.values()) + no_ave
