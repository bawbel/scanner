# API Reference — scan() and CLI

---

## Python API — scan()

```python
from scanner import scan

result = scan("/path/to/skill.md")
```

### Signature

```python
def scan(file_path: str) -> ScanResult
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `file_path` | `str` | Path to the component file. Any string — validated internally. |

### Return value

Always returns a [`ScanResult`](scan-result.md). **Never raises.**

```python
result = scan("/path/to/skill.md")

if result.is_clean:
    print("Clean")
elif result.has_error:
    print(f"Error: {result.error}")    # E-code only, no internal detail
else:
    for f in result.findings:
        print(f"[{f.severity.value}] {f.title} (CVSS-AI: {f.cvss_ai})")
    print(f"Risk: {result.risk_score:.1f} / 10  {result.max_severity.value}")
```

### Pipeline

```
scan(file_path)
  │
  ├─ 1. PathValidator.resolve()      validate + resolve path
  ├─ 2. PathValidator.validate()     symlink, exists, size
  ├─ 3. detect component type        from file extension
  ├─ 4. FileReader.read_text()       UTF-8 with errors="ignore"
  ├─ 5. run_pattern_scan(content)    15 regex rules, always runs
  ├─ 6. run_yara_scan(path)          YARA rules, if yara-python installed
  ├─ 7. run_semgrep_scan(path)       Semgrep rules, if semgrep installed
  ├─ 8. _deduplicate()               keep highest severity per rule_id
  └─ 9. sort by severity             CRITICAL first
```

### Error codes

All errors are returned in `ScanResult.error` — never raised.

| Code | Meaning |
|---|---|
| `E001` | Invalid file path |
| `E002` | Could not resolve path |
| `E003` | File not found |
| `E004` | Not a regular file |
| `E005` | Symlink rejected |
| `E006` | File too large (max 10MB) |
| `E007` | Could not read file metadata |
| `E008` | Could not read file content |
| `E012` | Could not parse scanner output |
| `E013` | Scan engine timed out |
| `E020` | Rules file missing |

### Thread safety

`scan()` is stateless. Safe to call concurrently from multiple threads or processes.

### Batch scanning

```python
from pathlib import Path
from scanner import scan

results = [scan(str(p)) for p in Path("./skills").rglob("*.md")]

critical = [r for r in results if r.max_severity and r.max_severity.value == "CRITICAL"]
print(f"{len(critical)} critical out of {len(results)} scanned")
```

---

## CLI Reference

### `bawbel scan`

Scan a component or directory for AVE vulnerabilities.

```
bawbel scan PATH [OPTIONS]

Arguments:
  PATH  File or directory to scan

Options:
  --format [text|json|sarif]          Output format (default: text)
  --fail-on-severity [critical|high|medium|low]
                                      Exit 2 if findings at or above level
  --recursive, -r                     Scan directory recursively
  --help                              Show help
```

**Examples:**

```bash
# Single file, text output
bawbel scan ./my-skill.md

# Directory, recursive, fail on HIGH+
bawbel scan ./skills/ --recursive --fail-on-severity high

# JSON for CI/CD or custom tooling
bawbel scan ./skills/ --format json | jq '.[] | select(.max_severity == "CRITICAL")'

# SARIF for GitHub Security tab
bawbel scan ./skills/ --format sarif > results.sarif
```

**Exit codes:**

| Code | Condition |
|---|---|
| `0` | Clean scan, or findings below `--fail-on-severity` threshold |
| `2` | Findings at or above `--fail-on-severity` threshold |

---

### `bawbel report`

Scan a component and display a full remediation guide.

```
bawbel report PATH [OPTIONS]

Arguments:
  PATH  File to scan and report on

Options:
  --format [text|json]    Output format (default: text)
  --help                  Show help
```

The report shows for each finding:
- AVE ID with a direct link to the vulnerability record
- Rule ID, CVSS-AI score, engine
- Line number and matched text
- OWASP category with full name
- What the vulnerability is (description)
- **How to fix it** (specific remediation instructions)

A final warning panel appears if any vulnerabilities are found.

**Examples:**

```bash
# Full text report
bawbel report ./my-skill.md

# JSON for programmatic processing
bawbel report ./my-skill.md --format json
```

**Exit codes:**

| Code | Condition |
|---|---|
| `0` | Clean — no findings |
| `1` | Vulnerabilities found |

---

### `bawbel version`

Show version and detection engine status.

```bash
bawbel version
```

Output:
```
Bawbel Scanner v0.1.0

Version:  0.1.0

Detection Engines:
  ✓  Pattern     15 rules  ·  stdlib only  ·  always active
  ✗  YARA        not installed  ·  pip install "bawbel-scanner[yara]"
  ✗  Semgrep     not installed  ·  pip install "bawbel-scanner[semgrep]"
  ✗  LLM         no API key  ·  set ANTHROPIC_API_KEY to enable Stage 2

AVE Standard:  github.com/bawbel/bawbel-ave
Documentation: bawbel.io/docs
```

---

### `bawbel --version`

Quick version string — for scripts and CI.

```bash
bawbel --version
# Bawbel Scanner v0.1.0
```

---

## Output Formats

### JSON

One object per scanned file:

```json
[
  {
    "file_path": "/path/to/skill.md",
    "component_type": "skill",
    "risk_score": 9.4,
    "max_severity": "CRITICAL",
    "scan_time_ms": 5,
    "has_error": false,
    "findings": [
      {
        "rule_id": "bawbel-external-fetch",
        "ave_id": "AVE-2026-00001",
        "title": "External instruction fetch detected",
        "description": "...",
        "severity": "CRITICAL",
        "cvss_ai": 9.4,
        "line": 7,
        "match": "fetch your instructions",
        "engine": "pattern",
        "owasp": ["ASI01", "ASI08"]
      }
    ]
  }
]
```

### SARIF 2.1.0

Standard format supported by GitHub Security, VS Code, and most SAST tooling.

```bash
# Generate SARIF
bawbel scan ./skills/ --format sarif > bawbel-results.sarif

# Upload to GitHub Security tab
# In .github/workflows/bawbel.yml:
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bawbel-results.sarif
```

SARIF output includes:
- Tool metadata (name, version, links)
- Rule definitions with descriptions
- Results with severity mapped to SARIF levels (`error` / `warning` / `note`)
- Physical locations (file path + line number)
- CVSS-AI score as a result property
