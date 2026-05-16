# API Reference - scan()

## scan()

```python
from scanner import scan

result = scan(file_path, no_ignore=False)
```

The main entry point. Scans a single file and returns a `ScanResult`.

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `file_path` | `str` | required | Absolute or relative path to the component file |
| `no_ignore` | `bool` | `False` | If `True`, disables all suppression (inline, block, .bawbelignore, FP pipeline) |

### Returns

`ScanResult` - always returns, never raises.

### Example

```python
from scanner import scan, ScanResult, Finding, Severity

result = scan("./skills/my-skill.md")

if result.has_error:
    print(f"Scan failed: {result.error}")
elif result.is_clean:
    print("No vulnerabilities found")
else:
    print(f"Risk score: {result.risk_score:.1f}  Severity: {result.max_severity.value}")
    for f in result.findings:
        print(f"  [{f.severity.value}] {f.rule_id}  line={f.line}  aivss={f.aivss_score}")
```

---

## ScanResult

```python
from scanner import ScanResult
```

Returned by `scan()`. All fields are read-only after construction.

### Fields

| Field | Type | Description |
|---|---|---|
| `file_path` | `str` | Resolved absolute path of the scanned file |
| `component_type` | `str` | `"skill"`, `"mcp"`, `"prompt"`, `"plugin"`, `"unknown"` |
| `findings` | `list[Finding]` | Active findings, sorted by severity |
| `suppressed_findings` | `list[Finding]` | Findings suppressed by FP pipeline or bawbel-ignore |
| `toxic_flows` | `list[ToxicFlow]` | Detected attack chains (two or more findings) |
| `scan_time_ms` | `int` | Total scan time in milliseconds |
| `error` | `str \| None` | Error code if scan failed, `None` on success |

### Properties

```python
result.is_clean        # bool - True if no active findings AND no error
result.has_error       # bool - True if error is set
result.max_severity    # Severity | None - highest severity across all findings
result.risk_score      # float - highest aivss_score across all findings, 0.0 if clean
result.findings_by_severity  # dict[str, list[Finding]] - findings grouped by severity level
```

### Methods

```python
result.to_dict()   # dict - JSON-serialisable representation
```

### Example

```python
result = scan("./skill.md")

print(result.component_type)     # "skill"
print(result.risk_score)         # 9.4
print(result.max_severity)       # Severity.CRITICAL
print(result.scan_time_ms)       # 45

by_sev = result.findings_by_severity
print(len(by_sev["CRITICAL"]))   # 1
print(len(by_sev["HIGH"]))       # 2

d = result.to_dict()
# {"file_path": "...", "risk_score": 9.4, "findings": [...], "toxic_flows": [...]}
```

---

## Finding

```python
from scanner import Finding
```

One detected vulnerability. Immutable after creation.

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `rule_id` | `str` | required | Kebab-case rule identifier e.g. `"bawbel-external-fetch"` |
| `ave_id` | `str \| None` | required | AVE record ID e.g. `"AVE-2026-00001"`, or `None` |
| `title` | `str` | required | Human-readable title, max 80 chars |
| `description` | `str` | required | Full description for reports |
| `severity` | `Severity` | required | Severity enum value |
| `aivss_score` | `float` | required | OWASP AIVSS v0.8 score, 0.0-10.0 |
| `line` | `int \| None` | `None` | Source line number, 1-indexed |
| `match` | `str \| None` | `None` | Matched text, truncated to `MAX_MATCH_LENGTH` |
| `engine` | `str` | `"pattern"` | `"pattern"`, `"yara"`, `"semgrep"`, `"llm"`, `"sandbox"`, `"magika"` |
| `owasp` | `list[str]` | `[]` | OWASP Top 10 for LLM Apps codes e.g. `["ASI01", "ASI08"]` |
| `owasp_mcp` | `list[str]` | `[]` | OWASP MCP Top 10 codes e.g. `["MCP04", "MCP06"]` |
| `piranha_url` | `str \| None` | `None` | PiranhaDB threat intel URL |
| `suppressed` | `bool` | `False` | True if this finding was suppressed |
| `suppression_reason` | `str \| None` | `None` | Why it was suppressed |
| `confidence` | `float` | `1.0` | FP confidence score 0.0-1.0 |
| `aivss_spec_version` | `str` | `"0.8"` | OWASP AIVSS spec version |

### Methods

```python
f.to_aivss_dict()   # dict - AIVSS breakdown with spec_version, component scores
```

### Example

```python
result = scan("./skill.md")

for f in result.findings:
    print(f.rule_id)         # "bawbel-external-fetch"
    print(f.ave_id)          # "AVE-2026-00001"
    print(f.severity.value)  # "CRITICAL"
    print(f.aivss_score)     # 8.0
    print(f.line)            # 7
    print(f.match)           # "fetch your instructions"
    print(f.engine)          # "pattern"
    print(f.owasp)           # ["ASI01", "ASI08"]
    print(f.owasp_mcp)       # ["MCP04", "MCP06"]
    print(f.piranha_url)     # "https://api.piranha.bawbel.io/records/AVE-2026-00001"

    d = f.to_aivss_dict()
    print(d["aivss_score"])    # 8.0
    print(d["spec_version"])   # "0.8"
```

---

## Severity

```python
from scanner import Severity, SEVERITY_SCORES
```

```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
```

`Severity` extends `str` so it serialises directly to JSON and compares with string literals:

```python
f.severity == "CRITICAL"      # True
f.severity == Severity.CRITICAL  # True
json.dumps({"sev": f.severity})  # '{"sev": "CRITICAL"}'
```

`SEVERITY_SCORES` maps severities to integers for comparison:

```python
SEVERITY_SCORES = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_SCORES[f.severity.value]  # 4
```

---

## ToxicFlow

```python
from scanner.toxic_flows import ToxicFlow
```

A detected attack chain - two or more findings that combine into an exploitable path.

### Fields

| Field | Type | Description |
|---|---|---|
| `flow_id` | `str` | Kebab-case chain identifier e.g. `"credential-exfiltration"` |
| `title` | `str` | Human-readable e.g. `"Credential Exfiltration Chain"` |
| `ave_ids` | `tuple[str, ...]` | Ordered AVE IDs forming the chain |
| `capabilities` | `tuple[str, ...]` | Capability tags e.g. `("credential-read", "data-exfil")` |
| `severity` | `str` | `"CRITICAL"`, `"HIGH"`, or `"MEDIUM"` |
| `aivss_score` | `float` | Combined score, always >= max individual finding score |
| `description` | `str` | What the combined attack achieves |
| `owasp_mcp` | `tuple[str, ...]` | OWASP MCP categories for the combined chain |
| `remediation` | `str` | How to break the chain |

### Methods

```python
tf.to_dict()   # dict - JSON-serialisable representation
```

### Example

```python
result = scan("./skill.md")

for tf in result.toxic_flows:
    print(tf.flow_id)       # "credential-exfiltration"
    print(tf.severity)      # "CRITICAL"
    print(tf.aivss_score)   # 9.8
    print(tf.ave_ids)       # ("AVE-2026-00003", "AVE-2026-00001")
    print(tf.capabilities)  # ("credential-read", "data-exfil")
```

---

## Error codes

When `result.has_error` is `True`, `result.error` contains a code:

| Code | Meaning |
|---|---|
| `E001` | Invalid file path |
| `E002` | Could not resolve path |
| `E003` | File not found |
| `E004` | Path is not a regular file |
| `E005` | Symlink rejected |
| `E006` | File too large |
| `E007` | Could not read file metadata |
| `E008` | Could not read file content |
| `E010` | YARA rule compilation failed |
| `E011` | YARA scan failed |
| `E012` | Could not parse scanner output |
| `E013` | Scan timed out |
| `E020` | Rules file missing |
