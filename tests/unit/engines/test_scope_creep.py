"""
Fixture tests for the pattern rule bawbel-scope-creep (AVE-2026-00022).

Positive fixture tests/fixtures/skills/malicious/scope-creep.md must fire the
rule in a normal scan. Negative fixture
tests/fixtures/skills/clean/scope-creep-clean.md must stay clean, scanned
with no_ignore=True (audit mode) so a suppression file cannot hide a match -
the fixture is clean because no pattern matches, not because something ignored it.
"""

from pathlib import Path

from scanner.scanner import scan

RULE_ID = "bawbel-scope-creep"
MALICIOUS = Path("tests/fixtures/skills/malicious/scope-creep.md")
CLEAN = Path("tests/fixtures/skills/clean/scope-creep-clean.md")


def test_detects_scope_creep():
    assert MALICIOUS.exists(), f"missing positive fixture: {MALICIOUS}"
    result = scan(str(MALICIOUS), no_ignore=True)
    assert len(result.findings) >= 1, "positive fixture produced no findings"
    assert any(
        f.rule_id == RULE_ID for f in result.findings
    ), f"expected {RULE_ID}, got {[f.rule_id for f in result.findings]}"


def test_no_fp_scope_creep_clean():
    assert CLEAN.exists(), f"missing negative fixture: {CLEAN}"
    result = scan(str(CLEAN), no_ignore=True)
    assert (
        result.is_clean
    ), f"negative fixture produced findings: {[f.rule_id for f in result.findings]}"
