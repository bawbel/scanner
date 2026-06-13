"""
Bawbel Scanner - Toxic flow definitions.

Each FlowDef defines a toxic pair: two capability tags that, when
detected together in the same file, form a complete attack chain.

Flow definitions are pure data - no logic here. The detector in
detector.py reads this table. Adding a new flow = one new entry.

Design principles:
    - Capabilities pair in one direction only (A → B, not B → A twice)
    - severity is the COMBINED risk - always >= max(individual findings)
    - aivss_boost is added on top of the highest individual finding score
    - Each flow has a unique flow_id in kebab-case
    - owasp_mcp maps to OWASP MCP Top 10 for the combined attack class

Attack chain taxonomy:
    read → transmit    : exfiltration chains  (credential-read + data-exfil)
    override → exec    : execution chains     (goal-override + command-exec)
    spoof → escalate   : privilege chains     (identity-spoof + permission-claim)
    inject → persist   : persistence chains   (context-inject + memory-write)
    supply → exec      : supply chain attacks (supply-chain + command-exec)
    lateral → escalate : pivot chains         (lateral-move + permission-claim)
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowDef:
    """
    Definition of a toxic capability pair.

    cap_a + cap_b in the same file → ToxicFlow is detected.
    cap_a and cap_b are interchangeable - order does not matter for detection.
    """

    flow_id: str  # unique kebab-case identifier
    title: str  # human-readable title
    cap_a: str  # first capability tag
    cap_b: str  # second capability tag (different from cap_a)
    severity: str  # CRITICAL | HIGH | MEDIUM
    aivss_score: float  # combined AIVSS v0.8 score
    description: str  # what the combined attack achieves
    owasp_mcp: tuple[str, ...]
    remediation: str


# ── Flow definitions ──────────────────────────────────────────────────────────
# Ordered by combined AIVSS score descending.

FLOW_DEFINITIONS: list[FlowDef] = [
    FlowDef(
        flow_id="credential-exfiltration",
        title="Credential Exfiltration Chain",
        cap_a="credential-read",
        cap_b="data-exfil",
        severity="CRITICAL",
        aivss_score=9.8,
        description=(
            "Component reads credentials or secrets AND transmits data externally. "
            "Complete credential theft attack chain - reads API keys, .env files, or "
            "tokens, then encodes and exfiltrates them to an attacker-controlled endpoint."
        ),
        owasp_mcp=("MCP01", "MCP05"),
        remediation=(
            "1. Remove all credential-read patterns - agent should never instruct "
            "the model to read .env, API keys, or tokens. "
            "2. Remove all external transmission instructions. "
            "3. If both cannot be removed, isolate them into separate components "
            "with no shared execution context."
        ),
    ),
    FlowDef(
        flow_id="rce-via-command-execution",
        title="Remote Code Execution Chain",
        cap_a="external-fetch",
        cap_b="command-exec",
        severity="CRITICAL",
        aivss_score=9.7,
        description=(
            "Component fetches instructions from an external URL AND executes shell "
            "commands. Classic RCE attack chain - fetches a malicious script from an "
            "attacker-controlled server and pipes it directly to bash or sh."
        ),
        owasp_mcp=("MCP04", "MCP05"),
        remediation=(
            "1. Remove all external URL fetches - instructions must be embedded, "
            "not fetched at runtime. "
            "2. Remove all shell execution patterns. "
            "3. Never combine external fetch with command execution in the same component."
        ),
    ),
    FlowDef(
        flow_id="supply-chain-rce",
        title="Supply Chain RCE Chain",
        cap_a="supply-chain",
        cap_b="command-exec",
        severity="CRITICAL",
        aivss_score=9.6,
        description=(
            "Component imports or modifies a third-party skill or plugin AND executes "
            "shell commands. Supply chain attack chain - installs a malicious component "
            "that executes arbitrary code on the target system."
        ),
        owasp_mcp=("MCP04", "MCP05"),
        remediation=(
            "1. Remove all dynamic import or install instructions. "
            "2. Remove all shell execution patterns. "
            "3. Pin all skill dependencies and verify hashes with bawbel pin."
        ),
    ),
    FlowDef(
        flow_id="goal-override-with-execution",
        title="Goal Override + Command Execution Chain",
        cap_a="goal-override",
        cap_b="command-exec",
        severity="CRITICAL",
        aivss_score=9.5,
        description=(
            "Component overrides agent goals AND executes shell commands. "
            "The override disables safety constraints, then execution runs "
            "arbitrary commands - a complete safety bypass + RCE chain."
        ),
        owasp_mcp=("MCP06", "MCP05"),
        remediation=(
            "1. Remove all goal override instructions. "
            "2. Remove all shell execution patterns. "
            "3. These two capabilities should never appear in the same component."
        ),
    ),
    FlowDef(
        flow_id="lateral-movement-with-execution",
        title="Lateral Movement + Execution Chain",
        cap_a="lateral-move",
        cap_b="command-exec",
        severity="CRITICAL",
        aivss_score=9.4,
        description=(
            "Component instructs the agent to pivot to other systems AND execute "
            "commands. Complete lateral movement chain - gains foothold on adjacent "
            "system and executes arbitrary code."
        ),
        owasp_mcp=("MCP05", "MCP02"),
        remediation=(
            "1. Remove all lateral movement instructions. "
            "2. Remove all command execution patterns. "
            "3. Audit all connected systems for signs of compromise."
        ),
    ),
    FlowDef(
        flow_id="tool-poison-with-exfil",
        title="Tool Poisoning + Exfiltration Chain",
        cap_a="tool-poison",
        cap_b="data-exfil",
        severity="CRITICAL",
        aivss_score=9.3,
        description=(
            "Component poisons tool descriptions AND exfiltrates data. "
            "The tool poisoning hijacks agent behavior, while the exfil "
            "instructions transmit the stolen data - a silent harvest chain."
        ),
        owasp_mcp=("MCP03", "MCP01"),
        remediation=(
            "1. Remove all behavioral instructions from tool descriptions. "
            "2. Remove all data transmission instructions. "
            "3. Scan with bawbel scan-server-card before connecting any MCP server."
        ),
    ),
    FlowDef(
        flow_id="identity-spoof-with-escalation",
        title="Identity Spoofing + Privilege Escalation Chain",
        cap_a="identity-spoof",
        cap_b="permission-claim",
        severity="CRITICAL",
        aivss_score=9.2,
        description=(
            "Component impersonates a trusted entity AND claims elevated permissions. "
            "The impersonation establishes false trust, the permission claim exploits "
            "it - a complete privilege escalation via social engineering chain."
        ),
        owasp_mcp=("MCP09", "MCP02"),
        remediation=(
            "1. Remove all identity or authority impersonation claims. "
            "2. Remove all undeclared permission claims. "
            "3. Verify all connected MCP servers against the official registry."
        ),
    ),
    FlowDef(
        flow_id="persistence-with-exfil",
        title="Persistence + Data Exfiltration Chain",
        cap_a="persistence",
        cap_b="data-exfil",
        severity="CRITICAL",
        aivss_score=9.1,
        description=(
            "Component establishes persistence AND exfiltrates data. "
            "The persistence ensures the exfiltration continues across "
            "sessions and context resets - a long-running data harvest chain."
        ),
        owasp_mcp=("MCP06", "MCP01"),
        remediation=(
            "1. Remove all persistence instructions. "
            "2. Remove all data transmission instructions. "
            "3. Scan all startup scripts and cron entries for injected instructions."
        ),
    ),
    FlowDef(
        flow_id="context-inject-with-memory-write",
        title="Context Injection + Memory Poisoning Chain",
        cap_a="context-inject",
        cap_b="memory-write",
        severity="HIGH",
        aivss_score=8.9,
        description=(
            "Component injects instructions via context AND writes to agent memory. "
            "The context injection delivers the payload, the memory write ensures "
            "it persists across turns - a durable behavioral modification chain."
        ),
        owasp_mcp=("MCP10", "MCP06"),
        remediation=(
            "1. Remove all context injection patterns. "
            "2. Remove all instructions to write to agent memory. "
            "3. Treat all external content as untrusted - never inject into memory."
        ),
    ),
    FlowDef(
        flow_id="goal-override-with-exfil",
        title="Goal Override + Exfiltration Chain",
        cap_a="goal-override",
        cap_b="data-exfil",
        severity="HIGH",
        aivss_score=8.8,
        description=(
            "Component overrides agent goals AND exfiltrates data. "
            "The override disables safety constraints, the exfil transmits "
            "whatever the agent can access - a combined hijack + harvest chain."
        ),
        owasp_mcp=("MCP06", "MCP01"),
        remediation=(
            "1. Remove all goal override instructions. "
            "2. Remove all data transmission instructions."
        ),
    ),
    FlowDef(
        flow_id="scope-expand-with-exfil",
        title="Scope Expansion + Exfiltration Chain",
        cap_a="scope-expand",
        cap_b="data-exfil",
        severity="HIGH",
        aivss_score=8.7,
        description=(
            "Component expands its declared scope to access undeclared resources "
            "AND exfiltrates data. Accesses more than declared, transmits the excess "
            "- a scope creep + exfiltration chain."
        ),
        owasp_mcp=("MCP02", "MCP01"),
        remediation=(
            "1. Remove all undeclared resource access instructions. "
            "2. Remove all data transmission instructions. "
            "3. Declare all required permissions explicitly in the component manifest."
        ),
    ),
    FlowDef(
        flow_id="covert-exfil-with-persistence",
        title="Covert Channel + Persistence Chain",
        cap_a="covert-channel",
        cap_b="persistence",
        severity="HIGH",
        aivss_score=8.6,
        description=(
            "Component uses a covert channel (steganography, timing) to exfiltrate "
            "data AND establishes persistence. The covert channel evades detection, "
            "the persistence ensures long-term access - a stealthy harvest chain."
        ),
        owasp_mcp=("MCP08", "MCP06"),
        remediation=(
            "1. Remove all steganographic encoding or covert channel instructions. "
            "2. Remove all persistence instructions. "
            "3. Audit agent outputs for encoded data using forensic tooling."
        ),
    ),
]


# ── Fast lookup ───────────────────────────────────────────────────────────────
# Build a set of (frozenset({cap_a, cap_b})) → FlowDef for O(1) detection.

_FLOW_INDEX: dict[frozenset, FlowDef] = {frozenset({f.cap_a, f.cap_b}): f for f in FLOW_DEFINITIONS}


def get_flow(cap_a: str, cap_b: str) -> FlowDef | None:
    """Return the FlowDef for a capability pair, or None if not toxic."""
    return _FLOW_INDEX.get(frozenset({cap_a, cap_b}))
