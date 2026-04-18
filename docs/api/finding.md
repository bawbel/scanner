# API Reference — Finding

A `Finding` represents a single detected vulnerability in an agentic component.

---

## Import

```python
from scanner import Finding, Severity
```

---

## Fields

| Field | Type | Stable | Description |
|---|---|---|---|
| `rule_id` | `str` | ✅ | Unique rule identifier — kebab-case, never changes |
| `ave_id` | `Optional[str]` | ✅ | `AVE-2026-NNNNN` or `None` if unpublished |
| `title` | `str` | ✅ | Human-readable title, max 80 chars |
| `description` | `str` | ✅ | Full description for reports |
| `severity` | `Severity` | ✅ | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `cvss_ai` | `float` | ✅ | CVSS-AI score, 0.0–10.0 |
| `line` | `Optional[int]` | ✅ | Source line number (1-indexed), or `None` |
| `match` | `Optional[str]` | ✅ | Matched text — always ≤ 80 chars |
| `engine` | `str` | ✅ | `"pattern"` / `"yara"` / `"semgrep"` / `"llm"` |
| `owasp` | `list[str]` | ✅ | OWASP ASI identifiers e.g. `["ASI01", "ASI08"]` |

Fields marked ✅ are stable public API. Never rename or remove without a major version bump.

---

## Severity Enum

```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # CVSS-AI 9.0–10.0
    HIGH     = "HIGH"       # CVSS-AI 7.0–8.9
    MEDIUM   = "MEDIUM"     # CVSS-AI 4.0–6.9
    LOW      = "LOW"        # CVSS-AI 0.1–3.9
    INFO     = "INFO"       # CVSS-AI 0.0
```

Because `Severity` extends `str`, comparisons and JSON serialisation work naturally:

```python
finding.severity == "CRITICAL"        # True
finding.severity.value                # "CRITICAL"
json.dumps({"severity": finding.severity})  # {"severity": "CRITICAL"}
```

---

## Example

```python
from scanner import scan

result = scan("./skill.md")

for f in result.findings:
    print(f"[{f.severity.value:8}] {f.rule_id}")
    if f.ave_id:
        print(f"           AVE: {f.ave_id}")
    if f.line:
        print(f"           Line {f.line}: {f.match}")
    print(f"           OWASP: {', '.join(f.owasp)}")
```

---

## Construction

**Never instantiate `Finding` directly.** Always use `_make_finding()` in `scanner.py`
which validates and sanitises all fields (truncates match, clamps cvss_ai, etc.).
