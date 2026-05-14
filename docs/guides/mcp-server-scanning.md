# MCP Server Scanning

Bawbel can scan MCP servers in two ways: vulnerability scanning (AVE) and spec conformance scoring.

---

## Vulnerability scanning - bawbel ssc

Fetches the server card from `<URL>/.well-known/mcp-server-card/server.json` and scans all
tool descriptions, parameter descriptions, and config schemas for AVE vulnerabilities.

```bash
# Scan a live server
bawbel ssc https://api.example.com
bawbel scan-server-card https://api.example.com   # full name

# JSON output
bawbel ssc https://api.example.com --format json

# SARIF output
bawbel ssc https://api.example.com --format sarif

# Fail on high severity
bawbel ssc https://api.example.com --fail-on-severity high
```

The scanner fetches the server card, writes it to a temp file, runs the full detection pipeline
(pattern + YARA + Semgrep + LLM if configured), then removes the temp file. The `file_path`
in results shows the original URL, not the temp path.

---

## Conformance scoring - bawbel conform

Scores a server manifest against the MCP specification and returns a grade (A+-F).

```bash
# Score a local manifest file
bawbel conform ./server.json
bawbel scan-conformance ./server.json   # full name

# Score a live server (fetches .well-known/mcp-server-card/server.json)
bawbel conform https://api.example.com

# Look up from official MCP registry
bawbel conform exa.ai/exa --registry

# JSON output
bawbel conform ./server.json --format json

# Fail if score below threshold
bawbel conform ./server.json --fail-below 80

# Fail if any REQUIRED check fails
bawbel conform ./server.json --fail-non-conformant
```

### Conformance grades

| Grade | Score | Meaning |
|---|---|---|
| A+ | 95-100 | Fully conformant, all best practices |
| A  | 85-94  | Conformant, minor best practices missing |
| B  | 70-84  | Conformant, some recommended checks missing |
| C  | 50-69  | Conformant, significant gaps |
| D  | 30-49  | Non-conformant, major issues |
| F  | 0-29   | Non-conformant, fundamental problems |

A server is **conformant** only if all `REQUIRED` checks pass, regardless of score.

### What is checked

**REQUIRED** (non-conformant if failed):
- Server has a `name` field
- Transport URL uses HTTPS
- At least one tool is defined

**RECOMMENDED** (score penalty if missing):
- Server has a `description`
- Version field is present and semver
- `$schema` field references the official MCP schema
- Each tool has a `description`
- Each tool parameter has a `description`

**BEST PRACTICE** (minor score penalty):
- Tool names are lowercase kebab-case
- Deprecated transports not used (http+sse)
- Contact or support URL provided

---

## Python API

```python
import json
from scanner import scan
from scanner.fetcher import fetch_server_card, build_server_card_url, write_temp_scan_file
from scanner.conformance import score_conformance

# Vulnerability scan of a live server card
content, err = fetch_server_card("https://api.example.com")
if err:
    print(f"Fetch failed: {err}")
else:
    tmp = write_temp_scan_file(content)
    try:
        result = scan(str(tmp))
        result.file_path = "https://api.example.com"
        for f in result.findings:
            print(f.severity.value, f.rule_id, f.title)
    finally:
        tmp.unlink(missing_ok=True)

# Conformance scoring of a local manifest
manifest = json.load(open("server.json"))
report = score_conformance(manifest)
print(f"Grade: {report.grade}  Score: {report.score:.1f}  Conformant: {report.is_conformant}")
```
