"""
Bawbel Scanner — Detection engines.

Each engine is a separate module. Adding a new engine = adding a new file here
and registering it in scanner.py. No other files need to change.

Engine contract:
    def run_X_scan(file_path: str) -> list[Finding]:
        - Never raises — returns [] on any failure
        - Skips silently if optional dependency not installed
        - Uses Timer() for elapsed time measurement
        - Uses Logs.ENGINE_* for all log messages
        - Uses _make_finding() for all Finding construction
        - Logs exception type at WARNING — never exception message

Current engines:
    pattern  — regex matching, stdlib only, always runs     (scanner/engines/pattern.py)
    yara     — YARA rules, requires yara-python             (scanner/engines/yara_engine.py)
    semgrep  — Semgrep rules, requires semgrep CLI          (scanner/engines/semgrep_engine.py)
    llm      — LLM semantic analysis, requires API key      (scanner/engines/llm_engine.py)

Planned engines:
    sandbox  — Behavioral sandbox, requires Docker + eBPF   (scanner/engines/sandbox_engine.py)
"""

from scanner.engines.pattern import run_pattern_scan
from scanner.engines.yara_engine import run_yara_scan
from scanner.engines.semgrep_engine import run_semgrep_scan
from scanner.engines.llm_engine import run_llm_scan

__all__ = [
    "run_pattern_scan",
    "run_yara_scan",
    "run_semgrep_scan",
    "run_llm_scan",
]
