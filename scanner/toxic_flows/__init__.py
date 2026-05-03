"""
Bawbel Scanner — Toxic flow detection.

Public API:
    from scanner.toxic_flows import detect_toxic_flows
    flows = detect_toxic_flows(findings)  # list[ToxicFlow]

Toxic flows are attack chains — two or more findings whose capabilities
combine to form a complete, exploitable attack path. A credential-read
finding alone is HIGH. Combined with a data-exfil finding it becomes
a CRITICAL credential exfiltration chain.

Adding a new flow definition:
    1. Add any new capability tags to capabilities.py
    2. Add the AVE IDs that exhibit those capabilities
    3. Add a FlowDef to flows.py — that's it, no other files change
"""

from scanner.toxic_flows.detector import detect_toxic_flows
from scanner.toxic_flows.models import ToxicFlow

__all__ = ["detect_toxic_flows", "ToxicFlow"]
