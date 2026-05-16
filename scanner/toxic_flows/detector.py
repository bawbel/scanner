"""
Bawbel Scanner - Toxic flow detector.

Takes a deduplicated list of Finding objects and returns a list of
ToxicFlow objects representing detected attack chains.

Performance:
    O(c²) where c = number of unique capabilities in the findings list.
    c is always small (typically 2-8) because:
    - Most files have < 20 findings
    - Each AVE ID maps to 1-2 capabilities
    - We operate on unique capability pairs, not all finding pairs
    In practice this runs in < 1ms on any realistic input.

Design:
    - Zero side effects - pure function
    - Does not modify Finding objects
    - Does not call external APIs or engines
    - Safe to call concurrently
"""

from itertools import combinations

from scanner.models.finding import Finding
from scanner.toxic_flows.capabilities import get_capabilities
from scanner.toxic_flows.flows import get_flow
from scanner.toxic_flows.models import ToxicFlow


def detect_toxic_flows(findings: list[Finding]) -> list[ToxicFlow]:
    """
    Detect toxic flows from a list of findings.

    Args:
        findings: Deduplicated list of Finding objects from the scan pipeline.

    Returns:
        List of ToxicFlow objects, sorted by aivss_score descending.
        Empty list if no toxic flows are detected.
    """
    if len(findings) < 2:
        return []

    # Build capability map: capability_tag → set of AVE IDs that have it
    # This is more useful than a flat set because we preserve which AVE IDs
    # contributed to each capability for the ToxicFlow report.
    cap_to_ave: dict[str, set[str]] = {}

    for finding in findings:
        if not finding.ave_id:
            continue
        for cap in get_capabilities(finding.ave_id):
            cap_to_ave.setdefault(cap, set()).add(finding.ave_id)

    all_caps = list(cap_to_ave.keys())
    if len(all_caps) < 2:
        return []

    # Check all capability pairs for toxic flows - O(c²) where c ≤ ~16
    detected: list[ToxicFlow] = []
    seen_flow_ids: set[str] = set()

    for cap_a, cap_b in combinations(all_caps, 2):
        flow_def = get_flow(cap_a, cap_b)
        if flow_def is None:
            continue
        if flow_def.flow_id in seen_flow_ids:
            continue  # dedup - a capability can match multiple AVE IDs

        # Collect contributing AVE IDs from both sides of the chain
        ave_ids_a = cap_to_ave[cap_a]
        ave_ids_b = cap_to_ave[cap_b]
        contributing = tuple(sorted(ave_ids_a | ave_ids_b))

        detected.append(
            ToxicFlow(
                flow_id=flow_def.flow_id,
                title=flow_def.title,
                ave_ids=contributing,
                capabilities=(flow_def.cap_a, flow_def.cap_b),
                severity=flow_def.severity,
                aivss_score=flow_def.aivss_score,
                description=flow_def.description,
                owasp_mcp=flow_def.owasp_mcp,
                remediation=flow_def.remediation,
            )
        )
        seen_flow_ids.add(flow_def.flow_id)

    # Sort by combined risk score - highest first
    detected.sort(key=lambda tf: tf.aivss_score, reverse=True)
    return detected
