# Writing Detection Rules

Three rule types, each with different strengths. Add to any of them independently — no Python changes needed.

---

## Choosing a rule type

| Rule type | Best for | File |
|---|---|---|
| Pattern | Simple phrase matching, single-line | `scanner/engines/pattern.py` |
| YARA | Multi-keyword combinations, binary content | `scanner/rules/yara/ave_rules.yar` |
| Semgrep | Multi-line, proximity-aware, structural | `scanner/rules/semgrep/ave_rules.yaml` |

Start with Pattern. If you need multi-condition logic use YARA. If you need multi-line context use Semgrep.

---

## Pattern rules

Edit `PATTERN_RULES` in `scanner/engines/pattern.py`.

```python
{
    "rule_id":     "bawbel-my-new-rule",   # kebab-case, must be unique
    "ave_id":      "AVE-2026-XXXXX",       # or None if no AVE record yet
    "title":       "Short title (max 80 chars)",
    "description": "Full description for reports and remediation guides.",
    "severity":    Severity.HIGH,          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    "aivss_score": 7.5,                    # 0.0-10.0
    "owasp":       ["ASI01"],              # OWASP Top 10 for LLM Apps
    "owasp_mcp":   ["MCP04"],              # OWASP MCP Top 10
    "patterns": [
        r"(?i)my attack pattern",          # case-insensitive regex
        r"alternative phrasing",
    ],
},
```

Rules are matched line by line. Any pattern matching any line triggers the rule.

### OWASP codes

Top 10 for LLM Apps: `ASI01`-`ASI10`
MCP Top 10: `MCP01`-`MCP10`

### Testing

```bash
python -m pytest tests/test_scanner.py::TestPatternRulesPositive -v
python -m pytest tests/unit/engines/test_pattern_engine.py -v
```

Add a positive test to `TestNewPatternRules` in `tests/test_scanner.py`:

```python
def test_detects_my_new_rule(self, tmp_path):
    path = write_skill(tmp_path, "skill.md",
        "# Skill\nmy attack pattern here\n")
    result = scan(path)
    assert "bawbel-my-new-rule" in [f.rule_id for f in result.findings]
```

---

## YARA rules

Edit `scanner/rules/yara/ave_rules.yar`.

```yara
// -- AVE-2026-XXXXX - My new attack class --------------------------------
rule AVE_MyNewRule
{
    meta:
        ave_id       = "AVE-2026-XXXXX"
        title        = "Short title"
        severity     = "HIGH"
        aivss        = "7.5"
        owasp        = "ASI01"
        owasp_mcp    = "MCP04"
        description  = "Full description."

    strings:
        $a = "suspicious phrase one"  nocase
        $b = "suspicious phrase two"  nocase
        $c = "related keyword"        nocase

    condition:
        // Trigger on any single phrase OR combination
        any of ($a, $b) or
        ($c and (any of ($a, $b)))
}
```

### Rules

- All strings declared in `strings:` must appear in the `condition:` — YARA raises a `SyntaxError` on unreferenced strings
- Use `nocase` for case-insensitive matching
- Use `ascii` (the default) for text files — do not use `wide`
- No non-ASCII characters in string literals or comments — YARA's lexer rejects them
- All `meta:` values are strings even for numbers: `aivss = "7.5"` not `aivss = 7.5`

### Test

```bash
python3 -c "
import yara
rules = yara.compile('scanner/rules/yara/ave_rules.yar')
print(f'Compiled OK')
"
```

---

## Semgrep rules

Edit `scanner/rules/semgrep/ave_rules.yaml`.

```yaml
- id: ave-my-new-rule
  patterns:
    - pattern-regex: '(?i)(suspicious phrase|alternative phrasing)'
  message: >
    AVE-2026-XXXXX [HIGH 7.5] Short title.
    Full description.
  languages: [generic]
  severity: ERROR
  metadata:
    ave_id: AVE-2026-XXXXX
    attack_class: My Attack Class
    aivss_score: "7.5"
    owasp_mapping:
      - ASI01
    owasp_mcp:
      - MCP04
```

### Rules

- Always use single-quoted pattern-regex values: `'...'` not `"..."` — double-quoted YAML strings treat `\s`, `\|`, `\{` as escape sequences and fail validation
- `aivss_score` must be a quoted string: `"7.5"` not `7.5`
- `languages: [generic]` — all component files are plain text
- `severity: ERROR` maps to HIGH; `WARNING` to MEDIUM; `INFO` to LOW

### Validate

```bash
semgrep --validate --config scanner/rules/semgrep/ave_rules.yaml
```

### Test

```bash
python -m pytest tests/test_scanner.py -k "test_detects" -v
```

---

## Checking coverage

After adding a rule, verify it fires on positive content and does not fire on clean content:

```bash
# Quick manual check
echo "my attack pattern here" > /tmp/test.md
bawbel scan /tmp/test.md

echo "# Clean skill\nDo helpful things." > /tmp/clean.md
bawbel scan /tmp/clean.md
```
