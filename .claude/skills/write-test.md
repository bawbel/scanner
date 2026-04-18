---
name: write-test
description: >
  Run this when asked to write a test, add a test case, or verify behaviour.
  Triggers: "write a test", "add a test for", "test that X", "verify X works".
---

# Write Test

Human guide: `.claude/testing.md` — do not duplicate it here.
This file is AI execution instructions only.

---

## Always start with these imports

```python
from scanner.scanner import scan, _deduplicate as deduplicate
from scanner.models import Finding, ScanResult, Severity, SEVERITY_SCORES
from scanner.engines.pattern import run_pattern_scan
from config import MAX_MATCH_LENGTH
from scanner.cli import cli
from click.testing import CliRunner
from pathlib import Path

GOLDEN = Path("tests/fixtures/skills/malicious/malicious_skill.md")

def write_skill(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)
```

---

## Put the test in the right class

| Testing what | Class |
|---|---|
| Golden fixture behaviour | `TestGoldenFixture` — never modify this class |
| Rule fires on malicious content | `TestPatternRulesPositive` |
| Rule does NOT fire on clean content | `TestPatternRulesNegative` |
| ScanResult property | `TestScanResult` |
| Deduplication logic | `TestDeduplication` |
| CLI commands and output | `TestCLI` |
| Severity ordering | `TestSeverityOrdering` |
| Security invariant | `TestSecurity` |

---

## Templates — copy and fill in

### Rule fires (positive)
```python
def test_detects_<rule>(self, tmp_path):
    """<rule_id> must detect <attack>."""
    path = write_skill(tmp_path, "skill.md", "# Skill\n<triggering content>\n")
    result = scan(path)
    assert "<bawbel-rule-id>" in [f.rule_id for f in result.findings]
```

### Rule does not fire (negative / false positive guard)
```python
def test_<rule>_no_false_positive(self, tmp_path):
    """<rule_id> must not fire on legitimate content."""
    path = write_skill(tmp_path, "skill.md", "# Skill\n<innocent content>\n")
    result = scan(path)
    assert "<bawbel-rule-id>" not in [f.rule_id for f in result.findings], \
        f"False positive: {[(f.rule_id, f.match) for f in result.findings]}"
```

### Security invariant
```python
def test_<invariant>(self, tmp_path):
    """<property> must hold — <why it matters>."""
    <arrange>
    result = scan(<path>)
    assert isinstance(result, ScanResult)   # never raises
    assert result.error is not None         # or specific assertion
```

### CLI behaviour
```python
def test_cli_<behaviour>(self):
    """CLI must <expected behaviour>."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(GOLDEN)])
    assert result.exit_code == 0            # or 2 for --fail-on-severity
    assert "CRITICAL" in result.output
```

---

## Most-used assertions

```python
assert result.is_clean                     # no findings AND no error
assert not result.is_clean
assert result.error is not None            # scan failed
assert result.error is None                # no error
assert len(result.findings) == N
assert result.risk_score >= 9.0
assert result.max_severity == Severity.CRITICAL
assert result.scan_time_ms < 500           # Stage 1 speed
assert "<bawbel-rule-id>" in [f.rule_id for f in result.findings]
assert "AVE-2026-00001" in [f.ave_id for f in result.findings]
for f in result.findings:
    if f.match: assert len(f.match) <= 80  # security invariant
```

---

## After writing

```bash
# Run just the new test first
python -m pytest tests/test_scanner.py::<Class>::<test_name> -v

# Then run everything — must all pass
python -m pytest tests/ -q
```

---

## Hard rules

- Use `tmp_path` fixture — never write to real directories
- Every positive test needs a matching negative test
- Never touch `TestGoldenFixture` or `malicious_skill.md`
- Test name pattern: `test_detects_X`, `test_X_no_false_positive`, `test_X_never_raises`
