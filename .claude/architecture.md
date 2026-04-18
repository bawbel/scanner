# Architecture — Bawbel Scanner

## Detection Pipeline

Every call to `scan(file_path)` runs through three stages in sequence.
Each stage is independent — a failure in Stage 2 or 3 never blocks Stage 1.

```
scan(file_path)          ← scanner/scanner.py — orchestrator only
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 1 — Static Analysis (always runs, zero deps required)     │
│                                                                 │
│  engines/pattern.py        run_pattern_scan()  ← stdlib only   │
│  engines/yara_engine.py    run_yara_scan()     ← yara-python   │
│  engines/semgrep_engine.py run_semgrep_scan()  ← semgrep CLI   │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ Stage 2 — LLM Semantic Analysis (optional)          │
│                                                     │
│  run_llm_scan()       ← requires ANTHROPIC_API_KEY  │
│                          or other LLM provider      │
│  Detects: nuanced prompt injection, goal hijack,    │
│  shadow permissions that regex cannot catch         │
└─────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ Stage 3 — Behavioral Sandbox (future, v1.0)         │
│                                                     │
│  Executes component in isolated sandbox             │
│  Monitors: network egress, file access, syscalls    │
│  Requires: Docker + eBPF (Linux only)               │
└─────────────────────────────────────────────────────┘
      │
      ▼
  deduplicate()          ← keeps highest severity per rule_id
      │
      ▼
  sort by severity
      │
      ▼
  ScanResult             ← returned to caller
```

---

## Core Data Models

### Finding
Single vulnerability detection. Immutable after creation.

```python
@dataclass
class Finding:
    rule_id:     str           # unique rule identifier, kebab-case
    ave_id:      Optional[str] # AVE-2026-NNNNN or None
    title:       str           # max 80 chars, human-readable
    description: str           # full description for reports
    severity:    Severity      # CRITICAL/HIGH/MEDIUM/LOW/INFO
    cvss_ai:     float         # 0.0–10.0
    line:        Optional[int] # source line number
    match:       Optional[str] # matched text snippet, max 80 chars
    engine:      str           # "pattern" | "yara" | "semgrep" | "llm"
    owasp:       list[str]     # ["ASI01", "ASI08"]
```

### ScanResult
Complete result for one file scan.

```python
@dataclass
class ScanResult:
    file_path:      str
    component_type: str            # skill/mcp/prompt/plugin/a2a/rag/model
    findings:       list[Finding]
    scan_time_ms:   int
    error:          Optional[str]  # set if scan failed, findings will be []

    # Computed properties
    max_severity    → Optional[Severity]   # highest severity in findings
    risk_score      → float                # max cvss_ai score
    is_clean        → bool                 # True if no findings
```

---

## Adding a New Detection Engine

Follow this pattern when adding Stage 1, 2, or 3 engines:

```python
def run_myengine_scan(file_path: str) -> list[Finding]:
    findings = []
    try:
        # 1. Check if engine/dependency is available
        import mylib  # or subprocess.run(["mytool", "--version"])

        # 2. Run the scan
        results = mylib.scan(file_path)

        # 3. Map results to Finding objects
        for r in results:
            findings.append(Finding(
                rule_id     = "myengine-rule-id",
                ave_id      = "AVE-2026-NNNNN",  # or None
                title       = "Short title",
                description = "Full description",
                severity    = Severity.HIGH,
                cvss_ai     = 8.0,
                line        = r.line,
                match       = r.match[:80],
                engine      = "myengine",
                owasp       = ["ASI01"],
            ))

    except ImportError:
        pass  # dependency not installed — skip silently
    except Exception:
        pass  # engine failed — skip silently, never raise

    return findings
```

Then:

1. Add to `scanner/engines/__init__.py`:
```python
from scanner.engines.my_engine import run_myengine_scan
__all__ = [..., "run_myengine_scan"]
```

2. Wire into `scanner/scanner.py`:
```python
findings.extend(run_pattern_scan(content))
findings.extend(run_yara_scan(str(path)))
findings.extend(run_semgrep_scan(str(path)))
findings.extend(run_myengine_scan(str(path)))  # ← add here
```

---

## Component Type Detection

Component type is inferred from file extension:

```python
COMPONENT_EXTENSIONS = {
    ".md":   "skill",
    ".json": "mcp",
    ".yaml": "prompt",
    ".yml":  "prompt",
    ".txt":  "prompt",
}
```

To add a new type: add the extension to this dict. The `component_type` field
flows through to `ScanResult` and is shown in CLI output and JSON reports.

---

## Deduplication Strategy

`deduplicate()` keeps the highest-severity finding per `rule_id`.

This means if YARA and pattern matching both fire on the same rule, only
the one with higher severity is kept. If they are equal severity, the first
one encountered wins.

**Do not change this behaviour** without bumping the minor version — downstream
CI/CD integrations may depend on finding counts.

---

## Rule Files

### YARA rules — `scanner/rules/yara/ave_rules.yar`

Each rule must have `meta:` block with:
- `ave_id` — AVE-2026-NNNNN or empty string
- `attack_class` — from the AVE taxonomy
- `severity` — CRITICAL/HIGH/MEDIUM/LOW/INFO
- `cvss_ai` — float as string e.g. "9.4"
- `description` — one sentence
- `owasp` — comma-separated ASI identifiers

### Semgrep rules — `scanner/rules/semgrep/ave_rules.yaml`

Each rule must have `metadata:` block with:
- `ave_id` — optional
- `attack_class` — from the AVE taxonomy
- `cvss_ai_score` — float
- `owasp_mapping` — list

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean scan, no findings |
| `1` | Findings below `--fail-on-severity` threshold |
| `2` | Findings at or above `--fail-on-severity` threshold |

These are stable — do not change without a major version bump.
