"""
Engine accounting: a scan reports which engines ran and which could not, and why.
Issue #124: a core-only install runs 1 of 6 engines and used to print the same result as a
full install.

Run: pytest tests/unit/test_engine_accounting.py -q
"""

import json
import sys
import threading
import types
from pathlib import Path

import pytest
from click.testing import CliRunner

import scanner.engines.llm_engine as llm_engine
import scanner.engines.magika_engine as magika_engine
import scanner.engines.sandbox_engine as sandbox_engine
import scanner.engines.semgrep_engine as semgrep_engine
import scanner.engines.yara_engine as yara_engine
import scanner.scanner as scanner_module
from scanner.cli import cli
from scanner.cli.shared.utils import missing_required_engines, parse_required_engines
from scanner.core.engine_ledger import (
    EngineLedger,
    engine_ledger,
    error_code,
    report_degraded,
    report_ran,
)
from scanner.engines.pattern_engine import run_pattern_scan
from scanner.models import ENGINES, DegradedReason, EngineDegradation, Finding, ScanResult, Severity
from scanner.scanner import scan

MALICIOUS = (
    Path(__file__).resolve().parents[1] / "fixtures" / "skills" / "malicious" / "malicious_skill.md"
)

R = DegradedReason


def _runner() -> CliRunner:
    """A runner whose result has a separate .stderr on every click version.

    click before 8.2 needs mix_stderr=False for that; 8.2 removed the argument and always
    keeps stderr separate.
    """
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()


def _degraded(ledger: EngineLedger) -> dict:
    return {d.engine: (d.reason, d.detail) for d in ledger.engines_degraded}


@pytest.fixture
def skill(tmp_path) -> str:
    path = tmp_path / "skill.md"
    path.write_text("# A skill\nFormats a date as ISO 8601.\n", encoding="utf-8")
    return str(path)


@pytest.fixture
def no_llm_env(monkeypatch):
    for var in (
        "BAWBEL_LLM_MODEL",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "MISTRAL_API_KEY",
        "GROQ_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(llm_engine, "LLM_ENABLED", True)


@pytest.fixture
def core_only(monkeypatch, no_llm_env):
    """A machine with only the core install: no yara, semgrep, magika, litellm, or sandbox."""
    for module in ("yara", "magika", "litellm"):
        monkeypatch.setitem(sys.modules, module, None)  # `import x` raises ImportError
    monkeypatch.setattr(semgrep_engine, "run_subprocess", lambda **kw: (None, None))
    monkeypatch.setattr(scanner_module, "SANDBOX_ENABLED", False)
    monkeypatch.setattr(magika_engine, "MAGIKA_ENABLED", True)


# ── The ledger ────────────────────────────────────────────────────────────────


class TestLedger:
    def test_reports_outside_a_scan_do_nothing(self):
        report_ran("yara")
        report_degraded("yara", R.NOT_INSTALLED)  # must not raise

    def test_engines_are_listed_in_run_order(self):
        with engine_ledger() as ledger:
            for engine in ("sandbox", "pattern", "magika", "yara"):
                report_ran(engine)
        assert ledger.engines_run == ["pattern", "yara", "magika", "sandbox"]

    def test_a_degraded_engine_did_not_run(self):
        with engine_ledger() as ledger:
            report_ran("yara")
            report_degraded("yara", R.ENGINE_ERROR, "E011")
        assert ledger.engines_run == []
        assert _degraded(ledger) == {"yara": (R.ENGINE_ERROR, "E011")}

    def test_ran_after_degraded_is_ignored(self):
        with engine_ledger() as ledger:
            report_degraded("llm", R.NO_API_KEY)
            report_ran("llm")
        assert ledger.engines_run == [] and "llm" in _degraded(ledger)

    def test_the_first_reason_is_kept(self):
        with engine_ledger() as ledger:
            report_degraded("llm", R.NOT_INSTALLED)
            report_degraded("llm", R.API_ERROR)
        assert _degraded(ledger) == {"llm": (R.NOT_INSTALLED, None)}

    def test_ledgers_do_not_leak_between_scans(self):
        with engine_ledger() as first:
            report_ran("pattern")
        with engine_ledger() as second:
            pass
        assert first.engines_run == ["pattern"] and second.engines_run == []

    def test_a_nested_ledger_is_independent_and_the_outer_one_is_restored(self):
        with engine_ledger() as outer:
            report_ran("pattern")
            with engine_ledger() as inner:
                report_ran("yara")
            report_ran("semgrep")
        assert inner.engines_run == ["yara"]
        assert outer.engines_run == ["pattern", "semgrep"]

    def test_ledgers_are_isolated_between_threads(self):
        seen: dict = {}

        def worker(name: str, engine: str) -> None:
            with engine_ledger() as ledger:
                report_ran(engine)
                threading.Event().wait(0.05)  # let the other thread run in between
                seen[name] = ledger.engines_run

        threads = [
            threading.Thread(target=worker, args=("a", "pattern")),
            threading.Thread(target=worker, args=("b", "yara")),
        ]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert seen == {"a": ["pattern"], "b": ["yara"]}

    @pytest.mark.parametrize(
        "message, code",
        [
            ("E013: Scan timed out after 30s.", "E013"),
            ("E011: YARA scan failed.", "E011"),
            ("E0130: too long", None),
            ("timed out", None),
            ("", None),
            (None, None),
        ],
    )
    def test_error_code_is_the_code_and_never_the_text(self, message, code):
        assert error_code(message) == code

    def test_the_reason_values_are_stable(self):
        # These strings appear in JSON and SARIF output. Renaming one breaks consumers.
        assert {v for k, v in vars(R).items() if k.isupper()} == {
            "not_installed",
            "no_api_key",
            "timeout",
            "api_error",
            "docker_unavailable",
            "disabled_by_config",
            "rules_missing",
            "engine_error",
            "skipped_content_type",
        }
        assert ENGINES == ("pattern", "yara", "semgrep", "llm", "magika", "sandbox")


# ── Each engine ───────────────────────────────────────────────────────────────


class TestPatternEngine:
    def test_always_runs(self):
        with engine_ledger() as ledger:
            run_pattern_scan("anything\n")
        assert ledger.engines_run == ["pattern"]


class TestYaraEngine:
    def test_not_installed(self, monkeypatch, skill):
        monkeypatch.setitem(sys.modules, "yara", None)
        with engine_ledger() as ledger:
            assert yara_engine.run_yara_scan(skill) == []
        assert _degraded(ledger) == {"yara": (R.NOT_INSTALLED, None)}

    def test_rules_missing(self, monkeypatch, skill, tmp_path):
        pytest.importorskip("yara")
        monkeypatch.setattr(yara_engine, "YARA_RULES_PATH", tmp_path / "none.yar")
        with engine_ledger() as ledger:
            assert yara_engine.run_yara_scan(skill) == []
        assert _degraded(ledger) == {"yara": (R.RULES_MISSING, None)}

    def test_a_rule_that_does_not_compile(self, monkeypatch, skill, tmp_path):
        pytest.importorskip("yara")
        bad = tmp_path / "bad.yar"
        bad.write_text("rule broken { condition: nonsense }\n", encoding="utf-8")
        monkeypatch.setattr(yara_engine, "YARA_RULES_PATH", bad)
        with engine_ledger() as ledger:
            assert yara_engine.run_yara_scan(skill) == []
        assert _degraded(ledger) == {"yara": (R.ENGINE_ERROR, "E010")}

    def test_runs(self, skill):
        pytest.importorskip("yara")
        with engine_ledger() as ledger:
            yara_engine.run_yara_scan(skill)
        assert ledger.engines_run == ["yara"]


class TestSemgrepEngine:
    def _run(self, monkeypatch, skill, outcome):
        monkeypatch.setattr(semgrep_engine, "run_subprocess", lambda **kw: outcome)
        with engine_ledger() as ledger:
            assert semgrep_engine.run_semgrep_scan(skill) == []
        return ledger

    def test_not_installed(self, monkeypatch, skill):
        assert _degraded(self._run(monkeypatch, skill, (None, None))) == {
            "semgrep": (R.NOT_INSTALLED, None)
        }

    def test_a_timeout_is_reported_not_dropped(self, monkeypatch, skill):
        ledger = self._run(monkeypatch, skill, (None, "E013: Scan timed out after 30s."))
        assert _degraded(ledger) == {"semgrep": (R.TIMEOUT, "E013")}

    def test_a_failed_run(self, monkeypatch, skill):
        ledger = self._run(monkeypatch, skill, (None, "E011: YARA scan failed."))
        assert _degraded(ledger) == {"semgrep": (R.ENGINE_ERROR, "E011")}

    def test_unparseable_output(self, monkeypatch, skill):
        ledger = self._run(monkeypatch, skill, ("this is not json", None))
        assert _degraded(ledger) == {"semgrep": (R.ENGINE_ERROR, "E012")}

    def test_runs(self, monkeypatch, skill):
        ledger = self._run(monkeypatch, skill, ('{"results": []}', None))
        assert ledger.engines_run == ["semgrep"] and ledger.engines_degraded == []

    def test_rules_missing(self, monkeypatch, skill, tmp_path):
        monkeypatch.setattr(semgrep_engine, "SEMGREP_RULES_PATH", tmp_path / "none.yaml")
        with engine_ledger() as ledger:
            semgrep_engine.run_semgrep_scan(skill)
        assert _degraded(ledger) == {"semgrep": (R.RULES_MISSING, None)}


def _fake_litellm(monkeypatch, completion):
    module = types.SimpleNamespace(completion=completion, suppress_debug_info=False)
    monkeypatch.setitem(sys.modules, "litellm", module)


def _reply(text):
    message = types.SimpleNamespace(content=text)
    return types.SimpleNamespace(choices=[types.SimpleNamespace(message=message)])


class TestLlmEngine:
    def test_disabled_by_config(self, monkeypatch):
        monkeypatch.setattr(llm_engine, "LLM_ENABLED", False)
        with engine_ledger() as ledger:
            assert llm_engine.run_llm_scan("x") == []
        assert _degraded(ledger) == {"llm": (R.DISABLED_BY_CONFIG, None)}

    def test_no_api_key(self, no_llm_env):
        with engine_ledger() as ledger:
            assert llm_engine.run_llm_scan("x") == []
        assert _degraded(ledger) == {"llm": (R.NO_API_KEY, None)}

    def test_litellm_not_installed(self, monkeypatch, no_llm_env):
        monkeypatch.setenv("BAWBEL_LLM_MODEL", "some-model")
        monkeypatch.setitem(sys.modules, "litellm", None)
        with engine_ledger() as ledger:
            assert llm_engine.run_llm_scan("x") == []
        assert _degraded(ledger) == {"llm": (R.NOT_INSTALLED, None)}

    def test_a_timeout(self, monkeypatch, no_llm_env):
        class APITimeoutError(Exception):
            pass

        def boom(**kw):
            raise APITimeoutError("secret detail that must not be recorded")

        monkeypatch.setenv("BAWBEL_LLM_MODEL", "some-model")
        _fake_litellm(monkeypatch, boom)
        with engine_ledger() as ledger:
            assert llm_engine.run_llm_scan("x") == []
        assert _degraded(ledger) == {"llm": (R.TIMEOUT, None)}

    def test_a_provider_error_records_no_exception_text(self, monkeypatch, no_llm_env):
        def boom(**kw):
            raise RuntimeError("sk-secret-token in the message")

        monkeypatch.setenv("BAWBEL_LLM_MODEL", "some-model")
        _fake_litellm(monkeypatch, boom)
        with engine_ledger() as ledger:
            llm_engine.run_llm_scan("x")
        degraded = ledger.engines_degraded[0]
        assert (degraded.reason, degraded.detail) == (R.API_ERROR, None)
        assert "secret" not in json.dumps(degraded.to_dict())

    def test_an_empty_reply(self, monkeypatch, no_llm_env):
        monkeypatch.setenv("BAWBEL_LLM_MODEL", "some-model")
        _fake_litellm(monkeypatch, lambda **kw: _reply(""))
        with engine_ledger() as ledger:
            llm_engine.run_llm_scan("x")
        assert _degraded(ledger) == {"llm": (R.API_ERROR, None)}

    def test_a_reply_that_is_not_json(self, monkeypatch, no_llm_env):
        monkeypatch.setenv("BAWBEL_LLM_MODEL", "some-model")
        _fake_litellm(monkeypatch, lambda **kw: _reply("not json at all"))
        with engine_ledger() as ledger:
            llm_engine.run_llm_scan("x")
        assert _degraded(ledger) == {"llm": (R.ENGINE_ERROR, "E012")}

    def test_runs(self, monkeypatch, no_llm_env):
        monkeypatch.setenv("BAWBEL_LLM_MODEL", "some-model")
        _fake_litellm(monkeypatch, lambda **kw: _reply("[]"))
        with engine_ledger() as ledger:
            assert llm_engine.run_llm_scan("x") == []
        assert ledger.engines_run == ["llm"] and ledger.engines_degraded == []


class _FakeMagika:
    """Stands in for magika.Magika."""

    def __init__(self, label="markdown", score=0.99, error=False):
        self._label, self._score, self._error = label, score, error

    def __call__(self):
        return self

    def identify_path(self, path):
        if self._error:
            raise RuntimeError("model file missing")
        output = types.SimpleNamespace(label=self._label)
        return types.SimpleNamespace(output=output, score=self._score)


class TestMagikaEngine:
    def test_disabled_by_config(self, monkeypatch, skill):
        monkeypatch.setattr(magika_engine, "MAGIKA_ENABLED", False)
        with engine_ledger() as ledger:
            assert magika_engine.run_magika_scan(skill) == []
        assert _degraded(ledger) == {"magika": (R.DISABLED_BY_CONFIG, None)}

    def test_not_installed(self, monkeypatch, skill):
        monkeypatch.setattr(magika_engine, "MAGIKA_ENABLED", True)
        monkeypatch.setitem(sys.modules, "magika", None)
        with engine_ledger() as ledger:
            assert magika_engine.run_magika_scan(skill) == []
        assert _degraded(ledger) == {"magika": (R.NOT_INSTALLED, None)}

    @pytest.mark.parametrize("score", [0.99, 0.10], ids=["confident", "unsure"])
    def test_runs_even_when_it_is_unsure(self, monkeypatch, skill, score):
        monkeypatch.setattr(magika_engine, "MAGIKA_ENABLED", True)
        monkeypatch.setitem(
            sys.modules, "magika", types.SimpleNamespace(Magika=_FakeMagika(score=score))
        )
        with engine_ledger() as ledger:
            magika_engine.run_magika_scan(skill)
        assert ledger.engines_run == ["magika"]

    def test_a_failure(self, monkeypatch, skill):
        monkeypatch.setattr(magika_engine, "MAGIKA_ENABLED", True)
        monkeypatch.setitem(
            sys.modules, "magika", types.SimpleNamespace(Magika=_FakeMagika(error=True))
        )
        with engine_ledger() as ledger:
            assert magika_engine.run_magika_scan(skill) == []
        assert ledger.engines_run == [] and _degraded(ledger) == {"magika": (R.ENGINE_ERROR, None)}


class TestSandboxEngine:
    def test_disabled_by_config(self, monkeypatch, skill):
        monkeypatch.setattr(sandbox_engine, "SANDBOX_ENABLED", False)
        with engine_ledger() as ledger:
            assert sandbox_engine.run_sandbox_scan(skill) == []
        assert _degraded(ledger) == {"sandbox": (R.DISABLED_BY_CONFIG, None)}

    def test_docker_not_running(self, monkeypatch, skill):
        monkeypatch.setattr(sandbox_engine, "SANDBOX_ENABLED", True)
        monkeypatch.setattr(sandbox_engine, "is_docker_available", lambda: False)
        with engine_ledger() as ledger:
            sandbox_engine.run_sandbox_scan(skill)
        assert _degraded(ledger) == {"sandbox": (R.DOCKER_UNAVAILABLE, None)}

    def test_no_image(self, monkeypatch, skill):
        monkeypatch.setattr(sandbox_engine, "SANDBOX_ENABLED", True)
        monkeypatch.setattr(sandbox_engine, "is_docker_available", lambda: True)
        monkeypatch.setattr(sandbox_engine, "_resolve_image", lambda: None)
        with engine_ledger() as ledger:
            sandbox_engine.run_sandbox_scan(skill)
        assert _degraded(ledger) == {"sandbox": (R.NOT_INSTALLED, None)}

    @pytest.mark.parametrize(
        "outcome, expected",
        [
            ((None, None), (R.DOCKER_UNAVAILABLE, None)),
            ((None, "E013: Scan timed out after 35s."), (R.TIMEOUT, "E013")),
            ((None, "E011: YARA scan failed."), (R.ENGINE_ERROR, "E011")),
            (("not json", None), (R.ENGINE_ERROR, "E012")),
        ],
    )
    def test_container_outcomes(self, monkeypatch, skill, outcome, expected):
        monkeypatch.setattr(sandbox_engine, "run_subprocess", lambda **kw: outcome)
        with engine_ledger() as ledger:
            assert sandbox_engine._run_container(skill, "image") == []
        assert _degraded(ledger) == {"sandbox": expected}

    def test_runs(self, monkeypatch, skill):
        monkeypatch.setattr(sandbox_engine, "run_subprocess", lambda **kw: ("{}", None))
        with engine_ledger() as ledger:
            sandbox_engine._run_container(skill, "image")
        assert ledger.engines_run == ["sandbox"]


# ── scan() ────────────────────────────────────────────────────────────────────


class TestScan:
    def test_a_core_only_install_reports_five_degraded_engines(self, core_only, skill):
        result = scan(skill)
        assert result.engines_run == ["pattern"]
        assert {d.engine: d.reason for d in result.engines_degraded} == {
            "yara": R.NOT_INSTALLED,
            "semgrep": R.NOT_INSTALLED,
            "llm": R.NO_API_KEY,
            "magika": R.NOT_INSTALLED,
            "sandbox": R.DISABLED_BY_CONFIG,
        }

    def test_every_engine_is_accounted_for_exactly_once(self, skill):
        result = scan(skill)
        run, degraded = set(result.engines_run), {d.engine for d in result.engines_degraded}
        assert run | degraded == set(ENGINES) and not run & degraded

    def test_a_dangerous_content_type_skips_the_text_engines_and_says_so(
        self, core_only, monkeypatch, skill
    ):
        dangerous = Finding(
            rule_id="bawbel-content-type-dangerous",
            ave_id="AVE-2026-00024",
            title="t",
            description="t",
            severity=Severity.HIGH,
            aivss_score=7.0,
            match="detected: elf",
            engine="magika",
        )
        calls = []
        monkeypatch.setattr(scanner_module, "run_magika_scan", lambda p: [dangerous])
        monkeypatch.setattr(
            scanner_module, "run_pattern_scan", lambda c: calls.append("pattern") or []
        )
        result = scan(skill)
        assert calls == []
        reasons = {d.engine: d.reason for d in result.engines_degraded}
        assert all(
            reasons[e] == R.SKIPPED_CONTENT_TYPE for e in ("pattern", "yara", "semgrep", "llm")
        )

    def test_the_sandbox_when_enabled_but_docker_is_down(self, core_only, monkeypatch, skill):
        monkeypatch.setattr(scanner_module, "SANDBOX_ENABLED", True)
        monkeypatch.setattr(scanner_module, "is_docker_available", lambda: False)
        degraded = {d.engine: d.reason for d in scan(skill).engines_degraded}
        assert degraded["sandbox"] == R.DOCKER_UNAVAILABLE

    def test_a_failed_scan_ran_no_engines(self, tmp_path):
        result = scan(str(tmp_path / "missing.md"))
        assert result.error and result.engines_run == [] and result.engines_degraded == []

    def test_scan_still_never_raises_when_an_engine_blows_up(self, core_only, monkeypatch, skill):
        monkeypatch.setattr(semgrep_engine, "run_subprocess", lambda **kw: ("{", None))
        assert scan(skill).error is None

    def test_findings_are_unchanged_by_accounting(self, core_only):
        result = scan(str(MALICIOUS))
        assert result.findings and result.engines_run == ["pattern"]


# ── Output formats ────────────────────────────────────────────────────────────


class TestOutputs:
    def test_to_dict_has_both_fields(self):
        result = ScanResult(
            file_path="f",
            component_type="skill",
            engines_run=["pattern"],
            engines_degraded=[EngineDegradation("yara", R.NOT_INSTALLED)],
        )
        data = result.to_dict()
        assert data["engines_run"] == ["pattern"]
        assert data["engines_degraded"] == [
            {"engine": "yara", "reason": "not_installed", "detail": None}
        ]

    def test_a_default_result_has_empty_lists(self):
        data = ScanResult(file_path="f", component_type="skill").to_dict()
        assert data["engines_run"] == [] and data["engines_degraded"] == []

    def test_json_output(self, core_only, skill):
        out = CliRunner().invoke(cli, ["scan", skill, "--format", "json"]).output
        record = json.loads(out)[0]
        assert record["engines_run"] == ["pattern"]
        assert [d["engine"] for d in record["engines_degraded"]] == [
            "yara",
            "semgrep",
            "llm",
            "magika",
            "sandbox",
        ]
        assert {"findings", "risk_score", "file_path"} <= set(record)  # nothing renamed

    def test_sarif_output(self, core_only, skill):
        out = CliRunner().invoke(cli, ["scan", skill, "--format", "sarif"]).output
        run = json.loads(out)["runs"][0]
        invocation = run["invocations"][0]
        assert invocation["executionSuccessful"] is True
        assert invocation["properties"]["enginesRun"] == ["pattern"]
        notes = invocation["toolExecutionNotifications"]
        assert [n["properties"]["engine"] for n in notes] == [
            "yara",
            "semgrep",
            "llm",
            "magika",
            "sandbox",
        ]
        assert all(n["level"] == "warning" and n["message"]["text"] for n in notes)
        assert "invocation" not in run and "toolExecutionNotices" not in invocation

    def test_sarif_for_a_directory_names_how_many_files(self, core_only, tmp_path):
        for name in ("a.md", "b.md"):
            (tmp_path / name).write_text("# Skill\n", encoding="utf-8")
        out = CliRunner().invoke(cli, ["scan", str(tmp_path), "--format", "sarif"]).output
        text = json.loads(out)["runs"][0]["invocations"][0]["toolExecutionNotifications"][0][
            "message"
        ]["text"]
        assert "2 of 2 file(s)" in text

    def test_text_output_says_how_many_ran(self, core_only, skill):
        out = CliRunner().invoke(cli, ["scan", skill]).output
        assert "Engines:" in out and "1 of 6 ran" in out and "yara (not_installed)" in out


# ── --require-engines ─────────────────────────────────────────────────────────


class TestRequireEngines:
    def test_parse(self):
        assert parse_required_engines("yara, Semgrep ,yara") == ["yara", "semgrep"]
        assert parse_required_engines("") == []

    def test_parse_rejects_an_unknown_engine(self):
        with pytest.raises(ValueError, match="unknown engine bogus"):
            parse_required_engines("yara,bogus")

    def test_missing_names_the_reason_once_per_engine(self):
        ok = ScanResult("a", "skill", engines_run=["pattern", "yara"])
        bad = ScanResult(
            "b",
            "skill",
            engines_run=["pattern"],
            engines_degraded=[EngineDegradation("yara", R.NOT_INSTALLED)],
        )
        failed = ScanResult("c", "skill", error="E003")
        # A failed scan ran nothing, so it is missing pattern too; each engine is named once.
        assert missing_required_engines([ok, bad, failed], ["pattern", "yara"]) == [
            ("pattern", "scan_failed"),
            ("yara", R.NOT_INSTALLED),
        ]
        assert missing_required_engines([ok, bad], ["pattern", "yara"]) == [
            ("yara", R.NOT_INSTALLED)
        ]
        assert missing_required_engines([failed], ["pattern"]) == [("pattern", "scan_failed")]
        assert missing_required_engines([ok], ["pattern", "yara"]) == []

    def test_exit_0_when_the_required_engines_ran(self, core_only, skill):
        result = CliRunner().invoke(cli, ["scan", skill, "--require-engines", "pattern"])
        assert result.exit_code == 0

    def test_exit_3_and_a_message_when_one_did_not(self, core_only, skill):
        result = _runner().invoke(cli, ["scan", skill, "--require-engines", "yara,semgrep"])
        assert result.exit_code == 3
        assert "required engine did not run: yara (not_installed)" in result.stderr
        assert "required engine did not run: semgrep (not_installed)" in result.stderr

    def test_it_takes_precedence_over_the_severity_threshold(self, core_only):
        result = CliRunner().invoke(
            cli, ["scan", str(MALICIOUS), "--fail-on-severity", "high", "--require-engines", "yara"]
        )
        assert result.exit_code == 3

    def test_the_severity_threshold_still_applies_when_engines_are_fine(self, core_only):
        result = CliRunner().invoke(
            cli,
            ["scan", str(MALICIOUS), "--fail-on-severity", "high", "--require-engines", "pattern"],
        )
        assert result.exit_code == 2

    def test_an_unknown_engine_is_a_usage_error(self, skill):
        result = CliRunner().invoke(cli, ["scan", skill, "--require-engines", "yara,bogus"])
        assert result.exit_code == 2 and "unknown engine bogus" in result.output

    def test_without_the_flag_nothing_changes(self, core_only, skill):
        assert CliRunner().invoke(cli, ["scan", skill]).exit_code == 0
