---
name: add-detection-rule
description: >
  Run this when asked to add a detection rule, write a YARA rule, write a
  Semgrep rule, or detect a new vulnerability pattern.
  Triggers: "add a rule", "detect X", "write a YARA rule", "add detection for".
---

# Add Detection Rule

Human guide: `docs/guides/writing-rules.md` — do not duplicate it here.
This file is AI execution instructions only.

---

## Decide rule type first

| If the pattern is... | Use |
|---|---|
| Simple text match | Pattern rule in `scanner/engines/pattern.py` |
| Multi-string, binary, complex logic | YARA rule in `scanner/rules/yara/ave_rules.yar` |
| Structural / AST match | Semgrep rule in `scanner/rules/semgrep/ave_rules.yaml` |

Default to pattern. Escalate only if regex is not sufficient.

---

## Pattern rule — execute these steps

**Step 1 — Add to `PATTERN_RULES` in `scanner/engines/pattern.py`**

Required fields — no omissions:
```python
{
    "rule_id":     "bawbel-<kebab-case>",   # unique, NEVER change after publish
    "ave_id":      "AVE-2026-NNNNN",        # or None
    "title":       "<max 80 chars>",
    "description": "<one sentence, why dangerous>",
    "severity":    Severity.<LEVEL>,        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    "cvss_ai":     <float>,                 # 0.0–10.0
    "owasp":       ["ASI0X", ...],
    "patterns":    [r"<regex>", ...],       # re.IGNORECASE applied automatically
},
```

Pattern rules:
- Use `\s+` not literal space — content has irregular whitespace
- One finding per rule per file — first matching pattern wins, then breaks
- Avoid overly broad patterns — false positives erode trust

**Step 2 — Create two fixtures**

```bash
# Positive — must trigger the rule
cat > tests/fixtures/skills/malicious/<rule_id>_trigger.md << 'EOF'
# Test Skill
<content that triggers the rule>
EOF

# Negative — must NOT trigger (false positive guard)
cat > tests/fixtures/skills/clean/<rule_id>_clean.md << 'EOF'
# Clean Skill
<similar but innocent content>
EOF
```

**Step 3 — Write two tests in `tests/test_scanner.py`**

```python
# In TestPatternRulesPositive
def test_detects_<rule_id>(self, tmp_path):
    """<rule_id> must detect <attack>."""
    path = write_skill(tmp_path, "skill.md", "<triggering content>\n")
    result = scan(path)
    assert "<bawbel-rule-id>" in [f.rule_id for f in result.findings]

# In TestPatternRulesNegative
def test_<rule_id>_no_false_positive(self, tmp_path):
    """<rule_id> must not fire on legitimate content."""
    path = write_skill(tmp_path, "skill.md", "<innocent content>\n")
    result = scan(path)
    assert "<bawbel-rule-id>" not in [f.rule_id for f in result.findings]
```

**Step 4 — Verify**

```bash
python -m pytest tests/ -q                 # all pass
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
# must still be: 2 findings, CRITICAL 9.4
```

**Step 5 — Commit**

```bash
git checkout -b rule/ave-<NNNNN>-<brief>
git commit -m "rule(pattern): add AVE-2026-<NNNNN> <description>"
```

---

## YARA rule — steps 1–5 above, plus

- Rule name format: `AVE_PascalCase_Description`
- All meta fields required: `ave_id`, `attack_class`, `severity`, `cvss_ai`, `description`, `owasp`
- `severity` and `cvss_ai` are strings in YARA meta, not typed values
- Use `nocase` modifier on all text strings

## Semgrep rule — steps 1–5 above, plus

- `languages: [generic]` for markdown/text files
- `severity: ERROR` = HIGH, `WARNING` = MEDIUM, `INFO` = LOW
- `metadata:` block must have `cvss_ai_score` and `owasp_mapping`
