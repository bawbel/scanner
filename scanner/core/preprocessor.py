"""
Bawbel Scanner - FP-1: Code fence preprocessing.

Replaces fenced code block content with blank lines, preserving line numbers
so Finding.line values remain accurate after preprocessing.
"""

import re as _re

_FENCE_RE = _re.compile(r"```[^\n]*\n(.*?)```", _re.DOTALL)
_TILDE_RE = _re.compile(r"~~~[^\n]*\n(.*?)~~~", _re.DOTALL)


def strip_code_fences(content: str) -> str:
    """Replace fenced code block interiors with blank lines, preserving line numbers."""

    def _blank_backtick(m: _re.Match) -> str:
        interior = m.group(1)
        blank_lines = "\n" * interior.count("\n")
        fence_open = m.group(0).split("\n")[0]
        return fence_open + "\n" + blank_lines + "```"

    def _blank_tilde(m: _re.Match) -> str:
        interior = m.group(1)
        blank_lines = "\n" * interior.count("\n")
        fence_open = m.group(0).split("\n")[0]
        return fence_open + "\n" + blank_lines + "~~~"

    result = _FENCE_RE.sub(_blank_backtick, content)
    result = _TILDE_RE.sub(_blank_tilde, result)
    return result
