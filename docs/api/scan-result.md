# API Reference - ScanResult

```python
from scanner import ScanResult
```

`ScanResult` is the complete output of a single file scan. Returned by `scan()`, never
instantiated directly.

---

## Fields

| Field | Type | Description |
|---|---|---|
| `file_path` | `str` | Resolved absolute path of the scanned file |
| `component_type` | `str` | `"skill"`, `"mcp"`, `"prompt"`, `"plugin"`, `"unknown"` |
| `findings` | `list[Finding]` | Active findings, sorted by severity |
| `suppressed_findings` | `list[Finding]` | Suppressed findings (audit trail) |
| `toxic_flows` | `list[ToxicFlow]` | Detected attack chains |
| `scan_time_ms` | `int` | Total scan time in milliseconds |
| `error` | `str \| None` | Error code if scan failed, `None` on success |

---

## Properties

```python
result.is_clean         # bool - no active findings AND no error
result.has_error        # bool - error is not None
result.max_severity     # Severity | None - highest severity across findings
result.risk_score       # float - max aivss_score across findings, 0.0 if clean
result.findings_by_severity  # dict[str, list[Finding]]
```

### findings_by_severity

```python
{
    "CRITICAL": [...],
    "HIGH":     [...],
    "MEDIUM":   [...],
    "LOW":      [...],
    "INFO":     [...],
}
```

---

## Methods

### to_dict()

```python
result.to_dict() -> dict
```

JSON-serialisable representation. Includes `findings`, `suppressed_findings`, and `toxic_flows`.

```python
{
    "file_path":          "/path/to/skill.md",
    "component_type":     "skill",
    "scan_time_ms":       45,
    "error":              None,
    "risk_score":         9.4,
    "max_severity":       "CRITICAL",
    "findings":           [{...}, ...],
    "toxic_flows":        [{...}, ...],
}
```

---

## Example

```python
from scanner import scan

result = scan("./skill.md")

# Check result
if result.has_error:
    print(f"Error: {result.error}")
    exit(1)

if result.is_clean:
    print(f"Clean ({result.scan_time_ms}ms)")
else:
    print(f"Risk: {result.risk_score:.1f}  Severity: {result.max_severity.value}")
    for f in result.findings:
        print(f"  [{f.severity.value}] {f.rule_id}  line={f.line}")
    for tf in result.toxic_flows:
        print(f"  CHAIN: {tf.title}  aivss={tf.aivss_score}")

# Serialise
import json
print(json.dumps(result.to_dict(), indent=2))
```
