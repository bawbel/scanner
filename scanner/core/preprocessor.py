"""
Bawbel Scanner - Preprocessing before the engines run.

FP-1: replaces fenced code block content with blank lines.
Suppression comments: replaces the text of bawbel-ignore / bawbel-accept directives with
spaces, so a comment cannot raise findings of its own (issue #122).

Both preserve line numbers so Finding.line values remain accurate.
"""

import re as _re

from scanner.config import SUPPRESSION_COMMENT_MAX_CHARS

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


# ── Suppression comments ───────────────────────────────────────────────────────
#
# A bawbel-ignore / bawbel-accept comment is free text: ids, a reason, a reviewer. If the
# engines read it, suppressing one finding can create another (issue #122). The text is
# replaced with spaces before the engines run. Newlines and columns are kept, so finding
# line numbers do not move. The suppression parsers keep reading the original content.
#
# Only when suppressions are honored: under --no-ignore a comment is ordinary text.
# Only well-formed directives are masked. An HTML comment must close within
# SUPPRESSION_COMMENT_MAX_CHARS and hold no second "<!--"; anything else is scanned, so the
# mask cannot swallow content that follows an unterminated or oversized comment.

_DIRECTIVE = r"bawbel-(?:ignore|accept)(?:-start|-end)?"

_HTML_DIRECTIVE_RE = _re.compile(
    rf"<!--\s*{_DIRECTIVE}\b(?:(?!<!--)[\s\S]){{0,{SUPPRESSION_COMMENT_MAX_CHARS}}}?-->",
    _re.IGNORECASE,
)
# "# bawbel-ignore ..." or "// bawbel-accept: ..." to the end of the line. The marker must start
# the line or follow whitespace, so "https://bawbel-ignore.example/" is not a comment.
_LINE_DIRECTIVE_RE = _re.compile(rf"(?<!\S)(?:#|//)\s*{_DIRECTIVE}\b[^\n]*", _re.IGNORECASE)
# Metadata lines that continue a line directive: "# reason: ...", "// reviewer: ...".
_LINE_METADATA_RE = _re.compile(
    r"^[ \t]*(?:#|//)[^\n]*\b(?:reason|reviewer|reviewed|expires)\s*:", _re.IGNORECASE
)


def _blank(text: str) -> str:
    """Spaces of the same length, keeping line breaks."""
    return _re.sub(r"[^\n]", " ", text)


def mask_suppression_comments(content: str) -> str:
    """Replace the text of suppression directives with spaces, preserving layout."""
    masked = _HTML_DIRECTIVE_RE.sub(lambda m: _blank(m.group(0)), content)
    out: list[str] = []
    in_directive = False
    for line in masked.split("\n"):
        match = _LINE_DIRECTIVE_RE.search(line)
        if match:
            line = line[: match.start()] + _blank(line[match.start() :])
            in_directive = True
        elif in_directive and _LINE_METADATA_RE.match(line):
            line = _blank(line)
        else:
            in_directive = False
        out.append(line)
    return "\n".join(out)
