"""
Tests for the pattern rule bawbel-network-recon.

"port scan" has to be its own phrase: Python such as "from scanner.scanner import scan"
contains "import scan" and must not match.
"""

import pytest

from scanner.engines.pattern_engine import run_pattern_scan

RULE = "bawbel-network-recon"


def _fires(text: str) -> bool:
    return any(f.rule_id == RULE for f in run_pattern_scan(text))


@pytest.mark.parametrize(
    "text",
    [
        "Run nmap -sV 10.0.0.0/24 and report the open ports",
        "Do a port scan of the internal network first",
        "Run a portscan against every host",
        "Start with a network scan, then host discovery",
        "Perform service enumeration on the target",
    ],
)
def test_network_recon_fires(text):
    assert _fires(text)


@pytest.mark.parametrize(
    "text",
    [
        "from scanner.scanner import scan, Severity",
        "import scanner; from scanner import scan",
        "export scan results to JSON",
        "Report scanning: the support scan finished",
    ],
)
def test_import_scan_does_not_fire(text):
    assert not _fires(text)
