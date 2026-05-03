# Toxic Flow Detection

## What is a toxic flow?

A toxic flow is when two or more findings in the same component combine to
form a **complete, exploitable attack chain**.

A single finding is bad. Two findings that work together are catastrophic.

```
AVE-2026-00003  credential-read   reads .env, API keys, tokens
AVE-2026-00026  data-exfil        encodes and transmits data externally

Individually:   HIGH 8.5  +  CRITICAL 9.1
As a chain:     CRITICAL 9.8  Credential Exfiltration Chain
```

The attacker doesn't need two separate skills. One skill that reads secrets
AND transmits them is a complete theft operation. Bawbel detects this
automatically and elevates the combined risk score.

---

## How it works

After running all detection engines and deduplicating findings, Bawbel maps
each finding to a **capability tag** based on its AVE ID:

```
AVE-2026-00003  →  credential-read, data-exfil
AVE-2026-00004  →  command-exec
AVE-2026-00001  →  external-fetch, supply-chain
```

It then checks all capability pairs against a library of 12 toxic flow
definitions. If two capabilities form a known attack chain, a `ToxicFlow`
is reported alongside the individual findings.

The risk score is elevated to the combined chain score — always higher than
any individual finding.

---

## Toxic flow output

```
FINDINGS
─────────────────────────────────────────────────────────────
🔴  CRITICAL  AVE-2026-00001   External instruction fetch
🟠  HIGH      AVE-2026-00004   Shell pipe injection

TOXIC FLOWS DETECTED
  These findings form complete attack chains.

  ⛓  CRITICAL  Remote Code Execution Chain  CVSS-AI 9.7
  Component fetches instructions from an external URL AND executes shell
  commands. Classic RCE attack chain — fetches a malicious script from an
  attacker-controlled server and pipes it directly to bash or sh.
  Chain:    external-fetch → command-exec
  AVEs:     AVE-2026-00001, AVE-2026-00004
  OWASP MCP: MCP04 (Software Supply Chain Attacks), MCP05 (Command Injection)

SUMMARY
─────────────────────────────────────────────────────────────
Risk score:   9.7 / 10  CRITICAL   ← elevated from 9.4 individual max
Findings:     2
Toxic flows:  1
```

**JSON output** includes a `toxic_flows` array on every result:

```json
{
  "file_path": "skills/search.md",
  "risk_score": 9.7,
  "findings": [...],
  "toxic_flows": [
    {
      "flow_id":      "rce-via-command-execution",
      "title":        "Remote Code Execution Chain",
      "ave_ids":      ["AVE-2026-00001", "AVE-2026-00004"],
      "capabilities": ["external-fetch", "command-exec"],
      "severity":     "CRITICAL",
      "cvss_ai":      9.7,
      "description":  "...",
      "owasp_mcp":    ["MCP04", "MCP05"],
      "remediation":  "..."
    }
  ]
}
```

---

## All 12 toxic flow definitions

Ordered by combined CVSS-AI score:

| Flow ID | Title | Capabilities | Severity | CVSS-AI |
|---|---|---|---|---|
| `credential-exfiltration` | Credential Exfiltration Chain | credential-read → data-exfil | CRITICAL | 9.8 |
| `rce-via-command-execution` | Remote Code Execution Chain | external-fetch → command-exec | CRITICAL | 9.7 |
| `supply-chain-rce` | Supply Chain RCE Chain | supply-chain → command-exec | CRITICAL | 9.6 |
| `goal-override-with-execution` | Goal Override + Command Execution | goal-override → command-exec | CRITICAL | 9.5 |
| `lateral-movement-with-execution` | Lateral Movement + Execution | lateral-move → command-exec | CRITICAL | 9.4 |
| `tool-poison-with-exfil` | Tool Poisoning + Exfiltration | tool-poison → data-exfil | CRITICAL | 9.3 |
| `identity-spoof-with-escalation` | Identity Spoofing + Privilege Escalation | identity-spoof → permission-claim | CRITICAL | 9.2 |
| `persistence-with-exfil` | Persistence + Data Exfiltration | persistence → data-exfil | CRITICAL | 9.1 |
| `context-inject-with-memory-write` | Context Injection + Memory Poisoning | context-inject → memory-write | HIGH | 8.9 |
| `goal-override-with-exfil` | Goal Override + Exfiltration | goal-override → data-exfil | HIGH | 8.8 |
| `scope-expand-with-exfil` | Scope Expansion + Exfiltration | scope-expand → data-exfil | HIGH | 8.7 |
| `covert-exfil-with-persistence` | Covert Channel + Persistence | covert-channel → persistence | HIGH | 8.6 |

---

## Capability tags

Each AVE ID maps to one or more capability tags. The detector uses these
to find toxic pairs without being tied to specific rule IDs.

| Capability | What it means | Example AVE IDs |
|---|---|---|
| `credential-read` | Reads secrets, API keys, .env files, tokens | AVE-2026-00003, 00013 |
| `data-exfil` | Transmits data to external destinations | AVE-2026-00026, 00039 |
| `command-exec` | Executes shell commands or arbitrary code | AVE-2026-00004, 00005 |
| `goal-override` | Overrides agent instructions or goals | AVE-2026-00007, 00009 |
| `persistence` | Survives context resets, installs hooks | AVE-2026-00008, 00027 |
| `permission-claim` | Falsely claims elevated permissions | AVE-2026-00012, 00030 |
| `external-fetch` | Fetches instructions from external URLs | AVE-2026-00001 |
| `tool-poison` | Injects instructions via tool descriptions | AVE-2026-00002, 00041 |
| `memory-write` | Writes to agent memory or long-term store | AVE-2026-00019 |
| `lateral-move` | Pivots to other systems or agents | AVE-2026-00020, 00036 |
| `supply-chain` | Imports or modifies third-party components | AVE-2026-00001, 00034 |
| `identity-spoof` | Impersonates trusted entities | AVE-2026-00014, 00017 |
| `context-inject` | Injects via conversation history or RAG | AVE-2026-00016, 00028 |
| `covert-channel` | Uses steganography or hidden channels | AVE-2026-00026, 00039 |
| `ui-inject` | Injects via rendered UI elements | AVE-2026-00043 |
| `scope-expand` | Accesses undeclared resources | AVE-2026-00021, 00022 |

---

## Why toxic flows matter for CI

Individual findings set a severity threshold — fail on HIGH+. But a
component with two MEDIUM findings that form a CRITICAL chain would pass
that check. Toxic flows close this gap.

```yaml
# GitHub Actions — fail on toxic flows regardless of individual severity
- name: Bawbel scan
  run: |
    pip install "bawbel-scanner[all]"
    bawbel scan . --recursive --format json > results.json

    # Check for any toxic flows in the output
    python3 -c "
    import json, sys
    results = json.load(open('results.json'))
    flows = [f for r in results for f in r.get('toxic_flows', [])]
    if flows:
        print(f'TOXIC FLOWS DETECTED: {len(flows)}')
        for f in flows:
            print(f'  [{f[\"severity\"]}] {f[\"title\"]}  CVSS-AI {f[\"cvss_ai\"]}')
        sys.exit(2)
    "
```

Or use `--fail-on-severity` — since toxic flows elevate the risk score,
a CRITICAL chain will cause `--fail-on-severity critical` to trigger even
if no individual finding is CRITICAL.

---

## Using toxic flows in the Python API

```python
from scanner import scan

result = scan("/path/to/skill.md")

# Individual findings
for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.ave_id}  {finding.title}")

# Toxic flows — attack chains
for flow in result.toxic_flows:
    print(f"\n⛓  TOXIC FLOW: {flow.title}")
    print(f"   Severity:  {flow.severity}  CVSS-AI {flow.cvss_ai}")
    print(f"   Chain:     {' → '.join(flow.capabilities)}")
    print(f"   AVEs:      {', '.join(flow.ave_ids)}")
    print(f"   Fix:       {flow.remediation}")

# Risk score includes toxic flows — always >= individual max
print(f"\nCombined risk: {result.risk_score:.1f} / 10")
```

---

## Adding a new flow definition

Flow definitions are pure data in `scanner/toxic_flows/flows.py`. Adding
a new attack chain takes one entry — no logic changes required.

```python
# scanner/toxic_flows/flows.py
FlowDef(
    flow_id     = "your-flow-id",
    title       = "Your Attack Chain Title",
    cap_a       = "capability-one",    # must exist in capabilities.py
    cap_b       = "capability-two",    # must exist in capabilities.py
    severity    = "CRITICAL",
    cvss_ai     = 9.5,
    description = "What the combined attack achieves.",
    owasp_mcp   = ("MCP05", "MCP06"),
    remediation = "How to break the chain.",
),
```

If you need a new capability tag, add it to `scanner/toxic_flows/capabilities.py`
first, then map your AVE IDs to it.

---

## References

- AVE Standard: [github.com/bawbel/bawbel-ave](https://github.com/bawbel/bawbel-ave)
- OWASP MCP Top 10: [owasp.org/www-project-mcp-top-10](https://owasp.org/www-project-mcp-top-10/)
- PiranhaDB: [api.piranha.bawbel.io](https://api.piranha.bawbel.io)
