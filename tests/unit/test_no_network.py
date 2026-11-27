"""
The core scan opens no network connection, and what each optional path sends. Issue #195.

docs/DATA-EGRESS.md states what leaves the machine. These tests are the part of it that can be
checked without a network, a provider or Docker:

  - a guard makes any use of a socket or a name lookup raise. It is loaded by Python itself at
    start-up (sitecustomize), so it also covers a child process. A control shows it stops a real
    attempt, so a pass means no attempt was made
  - `scan`, `report`, `creds` and `chain` run in core mode on the repository's fixtures under the
    guard
  - a stand-in for the LLM library records what the LLM stage and the meta-analyzer would send,
    and nothing is sent
  - a list of the modules that can reach the network, so a new one fails here until the document
    is updated

The meta-analyzer tests describe current behaviour, which the document reports: it is not switched
off by BAWBEL_LLM_ENABLED. If that changes, change the tests and the document together.

Run: pytest tests/unit/test_no_network.py -q
"""

import json
import os
import re
import socket
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

import scanner.engines.llm_engine as llm_engine
import scanner.engines.meta_analyzer as meta_analyzer
import scanner.engines.semgrep_engine as semgrep_engine
from scanner.models import Finding, Severity
from scanner.scanner import scan

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN = FIXTURES / "skills" / "malicious" / "malicious_skill.md"

GUARD = textwrap.dedent('''
    """Any use of the network in this process raises. Loaded at start-up as sitecustomize."""
    import socket


    class NetworkAttempt(AssertionError):
        pass


    def _refuse(*args, **kwargs):
        raise NetworkAttempt("network attempted: " + repr(args)[:100])


    for _name in ("connect", "connect_ex", "sendto", "sendmsg"):
        setattr(socket.socket, _name, _refuse)
    for _name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        setattr(socket, _name, _refuse)
    ''')

PROVIDER_KEYS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "MISTRAL_API_KEY",
    "GROQ_API_KEY",
    "BAWBEL_LLM_MODEL",
)


@pytest.fixture(scope="module")
def guard_dir(tmp_path_factory):
    directory = tmp_path_factory.mktemp("guard")
    (directory / "sitecustomize.py").write_text(GUARD, encoding="utf-8")
    (directory / "no-commands").mkdir()
    return directory


def guarded_env(guard_dir: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in PROVIDER_KEYS}
    # No command is found on PATH, so Semgrep and Docker are not started: this is the core scan,
    # with the optional engines that run inside Python (YARA, Magika) if they are installed.
    env["PATH"] = str(guard_dir / "no-commands")
    env.update(BAWBEL_LLM_ENABLED="false", BAWBEL_SANDBOX_ENABLED="false")
    env.update(BAWBEL_LOG_LEVEL="WARNING", NO_COLOR="1")
    existing = [env["PYTHONPATH"]] if env.get("PYTHONPATH") else []
    env["PYTHONPATH"] = os.pathsep.join([str(guard_dir), str(ROOT), *existing])
    return env


def run_guarded(guard_dir, *args, cwd=None):
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd or ROOT,
        env=guarded_env(guard_dir),
        timeout=180,
    )


# ── The guard, and the core scan under it ─────────────────────────────────────


def test_the_guard_stops_a_real_attempt(guard_dir):
    """The control. Without it a pass below could mean the guard never loaded."""
    code = "import socket; socket.create_connection(('127.0.0.1', 9), timeout=1)"
    proc = run_guarded(guard_dir, "-c", code)
    assert proc.returncode != 0 and "NetworkAttempt" in proc.stderr


def test_the_guard_stops_a_raw_socket_connect(guard_dir):
    code = "import socket; s = socket.socket(); s.connect(('127.0.0.1', 9))"
    proc = run_guarded(guard_dir, "-c", code)
    assert proc.returncode != 0 and "NetworkAttempt" in proc.stderr


def test_the_guard_stops_a_name_lookup_in_a_child_process(guard_dir):
    code = (
        "import subprocess, sys; "
        "p = subprocess.run([sys.executable, '-c', 'import socket; socket.getaddrinfo(\"x.invalid\", 80)'], "
        "capture_output=True, text=True); print(p.returncode, 'NetworkAttempt' in p.stderr)"
    )
    proc = run_guarded(guard_dir, "-c", code)
    assert proc.stdout.split() == ["1", "True"]


def test_scan_in_core_mode_makes_no_attempt(guard_dir, tmp_path):
    extra = tmp_path / "skills"
    extra.mkdir()
    (extra / "a.yaml").write_text("name: demo\ndescription: formats text\n", encoding="utf-8")
    (extra / "b.txt").write_text("Summarise the document for the reader.\n", encoding="utf-8")
    for target in (FIXTURES, extra):
        proc = run_guarded(
            guard_dir, "-m", "scanner.cli", "scan", str(target), "--recursive", "--format", "json"
        )
        assert "NetworkAttempt" not in proc.stderr + proc.stdout, proc.stderr[-400:]
        assert "Traceback" not in proc.stderr
        results = json.loads(proc.stdout)
        assert results and all("pattern" in r["engines_run"] for r in results)
        assert not any(r["has_error"] for r in results)


@pytest.mark.parametrize("fmt", ["text", "sarif"])
def test_the_other_output_formats_make_no_attempt(guard_dir, fmt):
    proc = run_guarded(guard_dir, "-m", "scanner.cli", "scan", str(GOLDEN), "--format", fmt)
    assert "NetworkAttempt" not in proc.stderr + proc.stdout and "Traceback" not in proc.stderr


@pytest.mark.parametrize("command", ["report", "creds", "chain"])
def test_the_other_scanning_commands_make_no_attempt(guard_dir, command):
    proc = run_guarded(guard_dir, "-m", "scanner.cli", command, str(GOLDEN))
    assert "NetworkAttempt" not in proc.stderr + proc.stdout, command
    assert "Traceback" not in proc.stderr, command


def test_scan_in_process_makes_no_attempt(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network attempted")

    for name in ("connect", "connect_ex", "sendto", "sendmsg"):
        monkeypatch.setattr(socket.socket, name, refuse)
    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)
    result = scan(str(GOLDEN))
    assert result.error is None and result.findings


# ── What the LLM paths send, with a stand-in for the library ──────────────────


class FakeLiteLLM(types.ModuleType):
    """Records each request and raises, so nothing is sent."""

    def __init__(self):
        super().__init__("litellm")
        self.calls = []
        self.suppress_debug_info = False

    def completion(self, **kwargs):
        self.calls.append(kwargs)
        raise RuntimeError("stand-in: nothing was sent")

    def get_llm_provider(self, model):
        return (model, "stand-in", None, None)


@pytest.fixture()
def fake_llm(monkeypatch):
    fake = FakeLiteLLM()
    monkeypatch.setitem(sys.modules, "litellm", fake)
    for key in PROVIDER_KEYS:
        monkeypatch.delenv(key, raising=False)
    return fake


def a_finding(confidence: float) -> Finding:
    return Finding(
        rule_id="bawbel-test-rule",
        ave_id="AVE-2026-00001",
        title="A test finding",
        description="d",
        severity=Severity.HIGH,
        aivss_score=5.0,
        line=2,
        match="the matched text",
        engine="pattern",
        confidence=confidence,
    )


def test_the_llm_stage_sends_the_file_content_and_nothing_else(monkeypatch, fake_llm):
    monkeypatch.setattr(llm_engine, "LLM_ENABLED", True)
    monkeypatch.setenv("BAWBEL_LLM_MODEL", "stand-in-model")
    llm_engine.run_llm_scan("# Skill\n\nThe file text.\n")
    (call,) = fake_llm.calls
    assert call["model"] == "stand-in-model"
    assert sorted(call) == ["max_tokens", "messages", "model", "timeout"]
    roles = [m["role"] for m in call["messages"]]
    assert roles == ["system", "user"]
    assert "The file text." in call["messages"][1]["content"]


def test_the_llm_stage_sends_nothing_when_it_is_switched_off(monkeypatch, fake_llm):
    monkeypatch.setattr(llm_engine, "LLM_ENABLED", False)
    monkeypatch.setenv("BAWBEL_LLM_MODEL", "stand-in-model")
    llm_engine.run_llm_scan("# Skill\n")
    assert fake_llm.calls == []


def test_the_meta_analyzer_sends_the_directory_path_and_the_findings(
    monkeypatch, fake_llm, tmp_path
):
    """BAWBEL_LLM_ENABLED=false does not stop it. Only its own switch does."""
    monkeypatch.setattr(llm_engine, "LLM_ENABLED", False)
    monkeypatch.setattr(meta_analyzer, "META_ANALYZER_ENABLED", True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a-value-that-is-not-a-key")
    content = "line one\nthe matched text\nline three\n"
    path = tmp_path / "SKILL.md"
    meta_analyzer.run_meta_analysis([a_finding(0.7)], content, str(path), "markdown")
    (call,) = fake_llm.calls
    body = json.loads(call["messages"][1]["content"])
    assert sorted(body) == ["file", "file_type", "findings", "path_context", "total_lines"]
    assert body["file"] == "SKILL.md" and body["path_context"] == str(tmp_path)
    assert os.path.isabs(body["path_context"])
    (sent,) = body["findings"]
    assert sorted(sent) == [
        "aivss_score",
        "ave_id",
        "confidence",
        "context_lines",
        "engine",
        "line",
        "match",
        "rule_id",
        "severity",
        "title",
    ]
    assert sent["match"] == "the matched text" and len(sent["context_lines"]) <= 5


def test_the_meta_analyzer_has_its_own_switch(monkeypatch, fake_llm, tmp_path):
    monkeypatch.setattr(meta_analyzer, "META_ANALYZER_ENABLED", False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a-value-that-is-not-a-key")
    meta_analyzer.run_meta_analysis([a_finding(0.7)], "x\ny\n", str(tmp_path / "a.md"), "markdown")
    assert fake_llm.calls == []


@pytest.mark.parametrize("confidence", [0.2, 0.9])
def test_the_meta_analyzer_reviews_only_the_medium_confidence_band(
    monkeypatch, fake_llm, tmp_path, confidence
):
    monkeypatch.setattr(meta_analyzer, "META_ANALYZER_ENABLED", True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a-value-that-is-not-a-key")
    meta_analyzer.run_meta_analysis(
        [a_finding(confidence)], "x\ny\n", str(tmp_path / "a.md"), "markdown"
    )
    assert fake_llm.calls == []


def test_the_meta_analyzer_sends_nothing_without_a_provider(monkeypatch, fake_llm, tmp_path):
    monkeypatch.setattr(meta_analyzer, "META_ANALYZER_ENABLED", True)
    meta_analyzer.run_meta_analysis([a_finding(0.7)], "x\ny\n", str(tmp_path / "a.md"), "markdown")
    assert fake_llm.calls == []


# ── Semgrep and the opt-in signal ─────────────────────────────────────────────


def test_semgrep_is_started_without_flags_that_turn_off_its_own_network_use(monkeypatch, tmp_path):
    """Describes current behaviour: the scanner passes Semgrep a local rule file and no metrics or
    version-check flag. docs/DATA-EGRESS.md reports what Semgrep itself then does."""
    seen = {}

    def capture(args, timeout, label):
        seen["args"] = args
        return None, None

    monkeypatch.setattr(semgrep_engine, "run_subprocess", capture)
    semgrep_engine.run_semgrep_scan(str(tmp_path / "a.md"), "text\n")
    args = seen["args"]
    assert args[0] == "semgrep" and "--config" in args
    assert not any(a.startswith("--metrics") or a == "--disable-version-check" for a in args)


def test_the_false_positive_signal_sends_nothing_unless_a_url_is_set(monkeypatch):
    import scanner.suppression.justified as justified

    def refuse(*args, **kwargs):
        raise AssertionError("network attempted")

    monkeypatch.setattr(justified, "FP_SIGNAL_URL", None)
    monkeypatch.setattr(socket, "create_connection", refuse)
    accepted = types.SimpleNamespace(report_to_piranha=True, ave_id="AVE-2026-00001", rule_id=None)
    assert justified.send_fp_signal(accepted, "pattern", 0.9, "hash") is False


# ── Every place the package can reach the network ─────────────────────────────

# The modules that import a network library, and the library. A new one fails the test until the
# document is updated and the entry is added here.
EGRESS_MODULES = {
    "scanner/cli/cmd_conform.py": {"urllib.request"},
    "scanner/cli/cmd_version.py": {"litellm"},
    "scanner/engines/llm_engine.py": {"litellm"},
    "scanner/engines/meta_analyzer.py": {"litellm"},
    "scanner/fetcher.py": {"urllib.request"},
    "scanner/suppression/justified.py": {"urllib.request"},
}
NETWORK_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+(urllib\.request|http\.client|http\.server|requests|httpx|aiohttp"
    r"|socket|ssl|smtplib|ftplib|xmlrpc\.client|websockets?|litellm)\b",
    re.MULTILINE,
)


def test_the_modules_that_can_reach_the_network_are_the_documented_ones():
    found: dict[str, set] = {}
    for path in sorted((ROOT / "scanner").rglob("*.py")):
        names = set(NETWORK_IMPORT.findall(path.read_text(encoding="utf-8")))
        if names:
            found[path.relative_to(ROOT).as_posix()] = names
    assert found == EGRESS_MODULES


def test_the_signal_function_is_called_only_by_the_accept_command():
    callers = set()
    for path in sorted((ROOT / "scanner").rglob("*.py")):
        if path.name != "justified.py" and "send_fp_signal(" in path.read_text(encoding="utf-8"):
            callers.add(path.relative_to(ROOT).as_posix())
    assert callers == {"scanner/cli/cmd_accept.py"}


def test_the_document_exists_and_names_each_documented_module():
    text = (ROOT / "docs" / "DATA-EGRESS.md").read_text(encoding="utf-8")
    for module in EGRESS_MODULES:
        assert module in text, module


def test_every_scanner_setting_the_document_names_exists_in_the_code():
    """A setting that a user is told to change must be one the code reads."""
    text = (ROOT / "docs" / "DATA-EGRESS.md").read_text(encoding="utf-8")
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "scanner").rglob("*.py"))
    )
    names = set(re.findall(r"\bBAWBEL_[A-Z_]+\b", text))
    assert names >= {
        "BAWBEL_LLM_ENABLED",
        "BAWBEL_META_ANALYZER_ENABLED",
        "BAWBEL_PIRANHA_URL",
        "BAWBEL_SANDBOX_ENABLED",
        "BAWBEL_SANDBOX_NETWORK",
        "BAWBEL_MCP_REGISTRY_URL",
    }
    for name in names:
        assert name in source, f"{name} is in the document but not in the code"
