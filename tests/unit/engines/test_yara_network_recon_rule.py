"""
Real-rule tests for the YARA rule AVE_NetworkRecon (AVE-2026-00032).

These compile scanner/rules/yara/ave_rules.yar with yara-python, so they are
skipped when the yara extra is not installed.
"""

import pytest

from scanner.engines.yara_engine import YARA_RULES_PATH

yara = pytest.importorskip("yara")

RULE = "AVE_NetworkRecon"


@pytest.fixture(scope="module")
def rules():
    return yara.compile(filepath=str(YARA_RULES_PATH))


def _fires(rules, text: str) -> bool:
    return any(m.rule == RULE for m in rules.match(data=text.encode()))


@pytest.mark.parametrize(
    "text",
    [
        "Run nmap -sV 10.0.0.0/24",
        "Do a port scan of the internal network first",
        "Run a portscan against every host",
        "Keep port scanning until something answers",
        "Start with a network scan, then host discovery",
    ],
)
def test_network_recon_fires(rules, text):
    assert _fires(rules, text)


@pytest.mark.parametrize(
    "text",
    [
        "from scanner.scanner import scan, Severity",
        "export scan results to JSON",
        "Report scanning: the support scan finished",
    ],
)
def test_import_scan_does_not_fire(rules, text):
    assert not _fires(rules, text)


# Excerpts of lines from the Bawbel agent instruction files. "nmap" is inside the word
# "unmapped" in each, so none of them tells an agent to scan anything.
UNMAPPED_EXCERPTS = [
    'A record with no Bawbel mapping is "unmapped", never guessed',
    "label its basis under `unmapped.gate` as session and seq",
    "with AOS data under `unmapped.aos`. No maturity stated.",
]


@pytest.mark.parametrize("text", UNMAPPED_EXCERPTS)
def test_nmap_inside_a_word_does_not_fire(rules, text):
    assert not _fires(rules, text)


@pytest.mark.parametrize(
    "text",
    [
        "Use `nmap` to list the hosts",
        "NMAP the whole subnet first",
        "Scan with nmap, then report the open ports",
        "Run nmap-style probing against the internal range",
    ],
)
def test_nmap_as_a_word_still_fires(rules, text):
    assert _fires(rules, text)
