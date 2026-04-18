# Writing Detection Rules — Bawbel Scanner

---

## Rule Types

| Type | Use when | File |
|---|---|---|
| **Pattern** | Simple text matching, no dependencies | `scanner/engines/pattern.py` |
| **YARA** | Multi-string, binary patterns, complex logic | `scanner/rules/yara/ave_rules.yar` |
| **Semgrep** | Structural code/text patterns | `scanner/rules/semgrep/ave_rules.yaml` |

**Start with pattern rules.** Add YARA or Semgrep only when regex is genuinely insufficient.

---

## Built-in Pattern Rules (v0.1.0)

All 15 built-in rules and what they detect:

| Rule ID | Severity | AVE ID | Attack Class |
|---|---|---|---|
| `bawbel-goal-override` | HIGH 8.1 | — | Goal hijack / prompt injection |
| `bawbel-jailbreak-instruction` | HIGH 8.3 | — | Jailbreak, role-play bypass |
| `bawbel-hidden-instruction` | HIGH 7.9 | — | Covert operation |
| `bawbel-external-fetch` | CRITICAL 9.4 | AVE-2026-00001 | Metamorphic payload |
| `bawbel-dynamic-tool-call` | HIGH 8.2 | — | Tool call injection |
| `bawbel-permission-escalation` | HIGH 7.8 | — | Shadow permission escalation |
| `bawbel-env-exfiltration` | HIGH 8.5 | AVE-2026-00003 | Credential exfiltration |
| `bawbel-pii-exfiltration` | HIGH 8.0 | — | PII exfiltration |
| `bawbel-shell-pipe` | HIGH 8.8 | — | Shell injection |
| `bawbel-destructive-command` | CRITICAL 9.1 | — | File destruction |
| `bawbel-crypto-drain` | CRITICAL 9.6 | — | Cryptocurrency drain |
| `bawbel-trust-escalation` | MEDIUM 6.5 | — | Trust manipulation |
| `bawbel-persistence-attempt` | HIGH 8.4 | — | Self-replication |
| `bawbel-mcp-tool-poisoning` | HIGH 8.7 | AVE-2026-00002 | MCP tool poisoning |
| `bawbel-system-prompt-leak` | MEDIUM 6.2 | — | Prompt extraction |

---

## OWASP Agentic AI Top 10 Mapping

| Code | Name | Rules that map to it |
|---|---|---|
| ASI01 | Prompt Injection | goal-override, jailbreak, external-fetch, permission-escalation, env-exfiltration, shell-pipe, trust-escalation, mcp-tool-poisoning |
| ASI02 | Sensitive Data Exposure | — |
| ASI03 | Supply Chain Compromise | dynamic-tool-call, mcp-tool-poisoning |
| ASI04 | Insecure Tool Calls | — |
| ASI05 | Unsafe Resource Access | — |
| ASI06 | Data Exfiltration | env-exfiltration, pii-exfiltration |
| ASI07 | Tool Abuse | shell-pipe, destructive-command, crypto-drain, persistence-attempt |
| ASI08 | Goal Hijacking | goal-override, jailbreak, external-fetch, permission-escalation |
| ASI09 | Trust Manipulation | hidden-instruction, trust-escalation, system-prompt-leak |
| ASI10 | Sandbox Escape | — |

---

## Adding a Pattern Rule

Add a new entry to `PATTERN_RULES` in `scanner/engines/pattern.py`:

```python
{
    "rule_id":     "bawbel-your-rule-name",  # kebab-case, unique forever
    "ave_id":      "AVE-2026-NNNNN",         # or None if no record yet
    "title":       "Short title (max 80 chars)",
    "description": "Full description of what this detects and why it is dangerous.",
    "severity":    Severity.HIGH,             # CRITICAL/HIGH/MEDIUM/LOW/INFO
    "cvss_ai":     8.0,                       # 0.0–10.0, justify this score
    "owasp":       ["ASI01", "ASI08"],        # from OWASP Agentic AI Top 10
    "patterns": [
        r"your\s+regex\s+pattern",           # re.IGNORECASE applied automatically
        r"alternative\s+pattern",            # first match per file wins
    ],
},
```

**Pattern writing tips:**
- Use `\s+` not literal spaces — content may have irregular whitespace
- Test each pattern before committing:
  ```bash
  python3 -c "import re; print(re.search(r'your pattern', 'test string', re.I))"
  ```
- Prefer specific patterns over broad ones — false positives erode trust
- The rule also needs a **remediation entry** in `scanner/cli.py`:
  ```python
  REMEDIATION_GUIDE = {
      ...
      "bawbel-your-rule-name": "Specific instructions on how to fix this.",
  }
  ```

---

## Adding a YARA Rule

Add to `scanner/rules/yara/ave_rules.yar`:

```yara
rule AVE_YourRuleName_BriefDescription
{
    meta:
        ave_id       = "AVE-2026-NNNNN"
        attack_class = "Attack Class Name"
        severity     = "HIGH"
        cvss_ai      = "8.0"
        description  = "One sentence description."
        owasp        = "ASI01, ASI08"

    strings:
        $s1 = "exact phrase" nocase
        $s2 = /regex pattern/ nocase
        $s3 = { 48 65 6C 6C 6F }   // hex bytes for binary matching

    condition:
        any of ($s*)
}
```

**YARA tips:**
- Rule name format: `AVE_PascalCase_Description`
- All `meta:` fields are required — `run_yara_scan()` reads them to build `Finding` objects
- `nocase` modifier for text strings
- Test: `yara scanner/rules/yara/ave_rules.yar tests/fixtures/skills/malicious/malicious_skill.md`

---

## Adding a Semgrep Rule

Add to `scanner/rules/semgrep/ave_rules.yaml`:

```yaml
rules:
  - id: ave-your-rule-name              # kebab-case, unique
    patterns:
      - pattern-regex: '(?i)your pattern here'
    message: >
      [HIGH] Brief title. Full description of what was detected and why it is dangerous.
    languages: [generic]                # use generic for .md, .txt, .yaml
    severity: ERROR                     # ERROR=HIGH, WARNING=MEDIUM, INFO=LOW
    metadata:
      ave_id: AVE-2026-NNNNN
      attack_class: "Attack Class Name"
      cvss_ai_score: 8.0
      owasp_mapping:
        - ASI01
        - ASI08
```

**Semgrep tips:**
- Use `languages: [generic]` for markdown and text files
- `pattern-regex` supports full Python regex syntax
- Test: `semgrep --config scanner/rules/semgrep/ave_rules.yaml <file>`
- Validate syntax: `semgrep --validate --config scanner/rules/semgrep/ave_rules.yaml`

---

## Remediation Entries

Every new rule should have a remediation entry in `scanner/cli.py` so
`bawbel report` shows specific fix instructions:

```python
# In scanner/cli.py — REMEDIATION_GUIDE dict
REMEDIATION_GUIDE = {
    ...
    "bawbel-your-rule-name": (
        "Specific, actionable instructions on how to fix this vulnerability. "
        "Tell the developer exactly what to remove or change."
    ),
}
```

If no entry exists, report falls back to: `"Review and remove this pattern."`

---

## Required: Test Fixtures

Every rule needs both:

**Positive fixture** — must trigger the rule:
```bash
cat > tests/fixtures/skills/malicious/your_rule_trigger.md << 'EOF'
# Skill
[content that triggers your rule]
EOF
```

**Negative fixture** — must NOT trigger (false positive check):
```bash
cat > tests/fixtures/skills/clean/your_rule_clean.md << 'EOF'
# Legitimate Skill
[similar-looking but innocent content]
EOF
```

**Pytest tests** in `tests/test_scanner.py`:
```python
def test_detects_your_rule(self, tmp_path):
    """Rule must detect [attack class]."""
    path = write_skill(tmp_path, "s.md", "# Skill\n[triggering content]\n")
    result = scan(path)
    assert "bawbel-your-rule-name" in [f.rule_id for f in result.findings]

def test_your_rule_no_false_positive(self, tmp_path):
    """Rule must not fire on legitimate content."""
    path = write_skill(tmp_path, "s.md", "# Skill\n[innocent content]\n")
    result = scan(path)
    assert "bawbel-your-rule-name" not in [f.rule_id for f in result.findings], (
        f"False positive: {result.findings}"
    )
```

---

## Severity and CVSS-AI Scoring Guide

| Severity | CVSS-AI range | When to use |
|---|---|---|
| CRITICAL | 9.0–10.0 | Direct code execution, wallet drain, file destruction, external fetch |
| HIGH | 7.0–8.9 | Credential theft, goal override, permission escalation, MCP poisoning |
| MEDIUM | 4.0–6.9 | Trust manipulation, prompt leak, obfuscation |
| LOW | 0.1–3.9 | Minor information disclosure, suspicious but low-risk patterns |
| INFO | 0.0 | Informational only, not a vulnerability |

---

## Verification Checklist

After adding any rule:

```bash
# Rule fires on intended content
python -m pytest tests/test_scanner.py::TestNewPatternRules -v

# Rule does not false-positive on clean content
python -m pytest tests/test_scanner.py::TestNewPatternRulesNegative -v

# Golden fixture still passes (no regressions)
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
# Expected: 2 findings, CRITICAL 9.4

# Full test suite green
python -m pytest tests/ -v

# Bandit clean
bandit -r scanner/ -f screen
```

---

## Full Step-by-Step Guide

See `.claude/skills/add-detection-rule.md` for the complete process
including AVE record lookup, commit conventions, and PR checklist.
