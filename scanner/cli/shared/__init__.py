"""
Bawbel Scanner — shared CLI utilities.

Re-exports the most commonly used helpers so command modules can do:

    from scanner.cli.shared import console, print_banner, print_scan_result
    from scanner.cli.shared import print_json, print_sarif
    from scanner.cli.shared import sev_value, worst_severity_score
"""

from scanner.cli.shared.constants import (  # noqa: F401
    OWASP_DESCRIPTIONS,
    REMEDIATION_GUIDE,
    SEVERITY_COLORS,
    SEVERITY_ICONS,
)
from scanner.cli.shared.display import (  # noqa: F401
    console,
    print_banner,
    print_scan_result,
    print_summary,
    sev_color,
    sev_icon,
    sev_value,
    worst_severity_score,
)
from scanner.cli.shared.formatters import (  # noqa: F401
    print_json,
    print_sarif,
)
