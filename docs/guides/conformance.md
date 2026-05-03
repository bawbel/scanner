# MCP Spec Conformance Scoring

## What is conformance scoring?

Conformance scoring answers the question: **does this MCP server actually
follow the spec?**

A server can be clean (no AVE findings) but still poorly formed — missing
tool descriptions, using deprecated transports, exposing HTTP endpoints,
or declaring duplicate tool names. Conformance scoring checks all of this
and gives the server a grade from A+ to F.

Think of it as a code quality linter, but for the MCP spec.

---

## Quick start

```bash
# Score a local manifest file
bawbel scan-conformance ./server.json
bawbel conform ./server.json           # alias

# Score a live server by base URL (fetches server-card)
bawbel scan-conformance https://api.example.com
bawbel conform https://api.example.com

# Score a server from the official MCP registry
bawbel scan-conformance ac.tandem/docs-mcp --registry
bawbel conform ac.tandem/docs-mcp --registry

# JSON output (for CI/CD)
bawbel conform https://api.example.com --format json

# Fail if score drops below 80
bawbel conform https://api.example.com --fail-below 80

# Fail if any REQUIRED check fails
bawbel conform https://api.example.com --fail-non-conformant
```

---

## Example output

```
Bawbel Scanner v1.0.1  ·  github.com/bawbel/bawbel-scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MCP Spec Conformance
───────────────────────────────────────────────────────────
Target:     https://api.example.com
Score:      87.3 / 100  Grade B
Status:     ✓ CONFORMANT
Checks:     15 passed  0 failed  3 warned  0 skipped

✓  Server has a name                         REQUIRED
✓  Server has a description                  REQUIRED
✓  Server has a version                      REQUIRED
✓  All transport URLs use HTTPS              REQUIRED
✓  Server declares transport endpoints       REQUIRED
✓  All tools have descriptions               REQUIRED
✓  All tools declare an inputSchema          REQUIRED
✓  All tool names follow the spec rules      REQUIRED
✓  Tool names are unique within the server   REQUIRED
~  Manifest references the official schema   RECOMMENDED   No '$schema' reference
~  All tool parameters have descriptions     RECOMMENDED   Parameters missing: search.max_results
~  Tools declare required parameters         RECOMMENDED   Tools with no 'required': fetch
✓  Server does not use deprecated transport  RECOMMENDED
✓  Sensitive parameters not in HTTP headers  BEST PRACTICE
–  Server uses streamable-http transport     RECOMMENDED   (skipped — no remotes)
```

---

## Grading scale

| Score | Grade | Meaning |
|---|---|---|
| 95–100 | A+ | Excellent — fully conformant, all best practices met |
| 90–94  | A  | Very good — all required checks pass, minor recommendations |
| 80–89  | B  | Good — conformant, some recommendations to address |
| 70–79  | C  | Fair — conformant, several recommendations failing |
| 60–69  | D  | Poor — conformant but many issues |
| 0–59   | F  | Non-conformant — one or more REQUIRED checks fail |

A server is **conformant** when all applicable REQUIRED checks pass, regardless
of score. A score of 60 with grade F means the server fails a REQUIRED check
and may not work correctly with all MCP clients.

---

## All 18 conformance checks

### REQUIRED (weight 3 — failure = non-conformant)

| Check ID | What it verifies |
|---|---|
| `has-name` | Manifest has a non-empty `name` or `displayName` field |
| `has-description` | Manifest has a non-empty `description` field |
| `has-version` | Manifest has a `version` field |
| `has-remotes` | Manifest declares at least one transport endpoint in `remotes` |
| `uses-https` | All remote endpoint URLs use `https://` |
| `tools-have-descriptions` | Every tool has a non-empty `description` |
| `tools-have-input-schema` | Every tool declares an `inputSchema` of type `object` |
| `tool-names-valid` | Tool names are 1–128 chars, only `A-Za-z0-9_-.`, no spaces |
| `tool-names-unique` | No two tools share the same name |

### RECOMMENDED (weight 2 — failure = warning, still conformant)

| Check ID | What it verifies |
|---|---|
| `has-schema-ref` | Manifest has `$schema` pointing to `static.modelcontextprotocol.io` |
| `uses-streamable-http` | At least one remote uses `streamable-http` (not deprecated `http+sse`) |
| `tools-params-have-descriptions` | Every `inputSchema` property has a `description` |
| `tools-declare-required-params` | Tools with properties include a `required` array |
| `no-deprecated-sse-transport` | No remote uses the deprecated `http+sse` transport |

### BEST PRACTICE (weight 1)

| Check ID | What it verifies |
|---|---|
| `no-sensitive-params-in-headers` | No sensitive param (password, token, key) has `x-mcp-header` set |
| `has-repository` | Manifest declares a `repository.url` for supply chain transparency |
| `description-not-too-long` | Server description is under 500 characters |
| `tool-descriptions-not-too-long` | No tool description exceeds 1000 characters |

---

## Scoring formula

```
score = (earned_points / applicable_points) × 100

PASS  → full weight  (REQUIRED=3, RECOMMENDED=2, BEST_PRACTICE=1)
WARN  → half weight
FAIL  → 0 points
SKIP  → excluded from denominator (not applicable)
```

A server with no tools will SKIP all tool-related checks — those checks
don't penalise the score.

---

## JSON output

```bash
bawbel conform https://api.example.com --format json
```

```json
{
  "target": "https://api.example.com",
  "conformance": {
    "score": 87.3,
    "grade": "B",
    "is_conformant": true,
    "passed": 15,
    "failed": 0,
    "warned": 3,
    "skipped": 0,
    "results": [
      {
        "check_id":    "has-name",
        "category":    "REQUIRED",
        "title":       "Server has a name",
        "status":      "pass",
        "message":     "",
        "remediation": ""
      },
      {
        "check_id":    "has-schema-ref",
        "category":    "RECOMMENDED",
        "title":       "Manifest references the official schema",
        "status":      "warn",
        "message":     "No '$schema' reference to MCP spec",
        "remediation": "Add '$schema': 'https://static.modelcontextprotocol.io/...'"
      }
    ]
  }
}
```

---

## CI/CD integration

### Fail on non-conformant servers

```yaml
# GitHub Actions
- name: MCP conformance check
  run: |
    pip install bawbel-scanner
    bawbel conform https://your-mcp-server.com --fail-non-conformant
```

### Fail below a score threshold

```yaml
- name: MCP conformance check
  run: |
    bawbel conform https://your-mcp-server.com --fail-below 80
```

### Scan a local manifest in CI

```yaml
- name: MCP conformance check
  run: |
    bawbel conform ./mcp-server.json --fail-non-conformant
```

### Combined scan + conformance

```yaml
- name: Bawbel full check
  run: |
    pip install "bawbel-scanner[all]"
    # Security scan
    bawbel scan . --recursive --fail-on-severity high
    # Spec conformance
    bawbel conform ./mcp-server.json --fail-non-conformant
```

---

## Writing a conformant manifest

Use `tests/fixtures/mcp/sample.json` as your reference — it scores 100/100.

Minimum conformant manifest:

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "your-org/your-server",
  "description": "What your server does in plain language.",
  "version": "1.0.0",
  "remotes": [
    {
      "type": "streamable-http",
      "url": "https://your-server.com/mcp"
    }
  ],
  "tools": [
    {
      "name": "your_tool",
      "description": "What this tool does and when to use it.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "param_name": {
            "type": "string",
            "description": "What this parameter does"
          }
        },
        "required": ["param_name"]
      }
    }
  ]
}
```

**Common mistakes that cause F grade:**

```json
// ✗ Missing description
{ "name": "my-server" }

// ✗ HTTP instead of HTTPS
"remotes": [{"type": "streamable-http", "url": "http://..."}]

// ✗ Invalid tool name (spaces, special chars)
"name": "My Tool!"

// ✗ Duplicate tool names
"tools": [{"name": "search"}, {"name": "search"}]

// ✗ Tool missing description
"tools": [{"name": "search", "inputSchema": {...}}]

// ✗ Deprecated transport
"remotes": [{"type": "http+sse", "url": "https://..."}]
```

---

## Combining with security scanning

Conformance scoring and security scanning are complementary:

| | `bawbel scan` | `bawbel conform` |
|---|---|---|
| **Checks for** | Malicious patterns, AVE vulnerabilities | Spec violations, missing fields |
| **Output** | Findings with AVE IDs | Score with grade |
| **Failure means** | Component is dangerous | Component may not work correctly |
| **Use in CI** | `--fail-on-severity high` | `--fail-non-conformant` |

Run both:

```bash
bawbel scan ./server.json                      # security
bawbel conform ./server.json --fail-below 80   # conformance
```

---

## Python API

```python
from scanner.conformance import score_conformance
import json

manifest = json.load(open("server.json"))
report = score_conformance(manifest)

print(f"Score: {report.score:.1f}/100  Grade: {report.grade}")
print(f"Conformant: {report.is_conformant}")

for result in report.results:
    icon = "✓" if result.status.value == "pass" else \
           "✗" if result.status.value == "fail" else "~"
    print(f"  {icon}  {result.check.title}")
    if result.message:
        print(f"       {result.message}")
```

---

## References

- MCP Specification: https://spec.modelcontextprotocol.io/specification/
- MCP Tools spec: https://modelcontextprotocol.io/specification/draft/server/tools
- SEP-1649 (server-card discovery): https://github.com/modelcontextprotocol/modelcontextprotocol
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- Reference fixture: `tests/fixtures/mcp/sample.json` (100/100 A+)
