"""
Bawbel Scanner - AVE capability tags.

Maps each AVE ID to the capability it represents in an attack chain.
Capabilities are the vocabulary of toxic flow detection - they abstract
over specific rule IDs so flow definitions remain stable even as new
AVE records are added.

Capability taxonomy:
    credential-read      reads secrets, API keys, .env files, tokens
    data-exfil           transmits data to external destinations
    command-exec         executes shell commands or arbitrary code
    goal-override        overrides agent instructions or goals
    persistence          survives context resets, installs hooks
    permission-claim     falsely claims elevated permissions
    external-fetch       fetches instructions from external URLs
    tool-poison          injects instructions via tool descriptions
    memory-write         writes to agent memory or long-term store
    lateral-move         pivots to other systems or agents
    supply-chain         imports or modifies third-party components
    identity-spoof       impersonates trusted entities
    context-inject       injects via conversation history or RAG
    covert-channel       uses steganography or hidden channels
    ui-inject            injects via rendered UI elements
    scope-expand         accesses undeclared resources or capabilities

Adding a new AVE record:
    1. Identify the capability(ies) it represents
    2. Add the AVE ID to AVE_CAPABILITIES below
    3. If it's a new capability, add it to the taxonomy above
    4. Check flows.py - does the new capability create new toxic pairs?
"""

# AVE ID → set of capability tags
AVE_CAPABILITIES: dict[str, set[str]] = {
    # ── External fetch ────────────────────────────────────────────────────────
    "AVE-2026-00001": {"external-fetch", "supply-chain"},
    # ── Tool poisoning ────────────────────────────────────────────────────────
    "AVE-2026-00002": {"tool-poison"},
    "AVE-2026-00011": {"tool-poison"},
    "AVE-2026-00018": {"tool-poison"},
    "AVE-2026-00035": {"tool-poison"},
    "AVE-2026-00041": {"tool-poison", "identity-spoof"},
    # ── Credential / data exfiltration ────────────────────────────────────────
    "AVE-2026-00003": {"credential-read", "data-exfil"},
    "AVE-2026-00013": {"credential-read", "data-exfil"},
    "AVE-2026-00026": {"data-exfil", "covert-channel"},
    "AVE-2026-00039": {"data-exfil", "covert-channel"},
    # ── Command execution ─────────────────────────────────────────────────────
    "AVE-2026-00004": {"command-exec"},
    "AVE-2026-00005": {"command-exec"},
    "AVE-2026-00032": {"command-exec"},
    "AVE-2026-00033": {"command-exec"},
    "AVE-2026-00042": {"command-exec"},
    # ── Cryptocurrency drain ──────────────────────────────────────────────────
    "AVE-2026-00006": {"command-exec", "credential-read"},
    # ── Goal override / jailbreak ─────────────────────────────────────────────
    "AVE-2026-00007": {"goal-override"},
    "AVE-2026-00009": {"goal-override"},
    "AVE-2026-00010": {"goal-override"},
    "AVE-2026-00023": {"goal-override"},
    "AVE-2026-00025": {"goal-override", "context-inject"},
    "AVE-2026-00027": {"goal-override", "persistence"},
    "AVE-2026-00031": {"goal-override"},
    "AVE-2026-00044": {"goal-override", "context-inject"},
    # ── Persistence ───────────────────────────────────────────────────────────
    "AVE-2026-00008": {"persistence"},
    # ── Permission / privilege ────────────────────────────────────────────────
    "AVE-2026-00012": {"permission-claim"},
    "AVE-2026-00030": {"permission-claim"},
    "AVE-2026-00038": {"scope-expand"},
    "AVE-2026-00045": {"scope-expand", "lateral-move"},
    # ── Memory ────────────────────────────────────────────────────────────────
    "AVE-2026-00019": {"memory-write"},
    # ── Lateral movement ──────────────────────────────────────────────────────
    "AVE-2026-00020": {"lateral-move"},
    "AVE-2026-00036": {"lateral-move"},
    # ── Identity / trust ─────────────────────────────────────────────────────
    "AVE-2026-00014": {"identity-spoof"},
    "AVE-2026-00017": {"identity-spoof"},
    # ── Supply chain ──────────────────────────────────────────────────────────
    "AVE-2026-00024": {"supply-chain"},
    "AVE-2026-00029": {"supply-chain"},
    "AVE-2026-00034": {"supply-chain"},
    # ── Context / RAG injection ───────────────────────────────────────────────
    "AVE-2026-00015": {"context-inject"},
    "AVE-2026-00016": {"context-inject"},
    "AVE-2026-00028": {"context-inject"},
    "AVE-2026-00037": {"context-inject", "ui-inject"},
    "AVE-2026-00043": {"ui-inject"},
    # ── Scope expansion ───────────────────────────────────────────────────────
    "AVE-2026-00021": {"scope-expand"},
    "AVE-2026-00022": {"scope-expand"},
    # ── Insecure output ───────────────────────────────────────────────────────
    "AVE-2026-00040": {"command-exec", "data-exfil"},
}


def get_capabilities(ave_id: str | None) -> set[str]:
    """Return capability tags for a given AVE ID. Empty set if unknown."""
    if not ave_id:
        return set()
    return AVE_CAPABILITIES.get(ave_id, set())
