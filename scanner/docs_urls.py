"""
Bawbel Scanner - documentation URLs the CLI prints or carries in its data.

One constant per URL. Code that shows a documentation link to a user imports it
from here, so a change is one line, and tests/test_doc_links.py and
scripts/check_doc_links.py can see every one of them.

A URL that points into this repository uses the ``main`` branch, because that is
the branch a user reads. tests/test_doc_links.py checks that the path exists in
the working tree. A file that exists only on ``develop`` is a dead link until the
next promotion to ``main``, so point a constant only at a file already on ``main``.

Not here: per-finding AVE record URLs and the PiranhaDB record URLs. Their shape
is owned by the AVE consumption work, not by this module.
"""

_REPO_BLOB_MAIN = "https://github.com/bawbel/scanner/blob/main/"

# The guide the pre-commit hook points at when it lists findings.
SUPPRESSION_GUIDE = _REPO_BLOB_MAIN + "docs/guides/suppression.md"

# Landing page of the published documentation, shown by `bawbel version`.
DOCS_HOME = "https://bawbel.io/docs"

# Project home, written into SARIF output as the tool's informationUri.
WEBSITE = "https://bawbel.io"

# The AVE standard, shown by `bawbel version` and `bawbel report` and used as the
# SARIF helpUri. github.com/bawbel/ave redirects to github.com/aveproject/ave.
AVE_STANDARD = "https://github.com/bawbel/ave"

# MCP specification, referenced by the conformance checks.
MCP_SPECIFICATION = "https://modelcontextprotocol.io/specification"


def all_urls() -> dict[str, str]:
    """Return every public URL constant in this module, keyed by its name."""
    return {
        name: value
        for name, value in globals().items()
        if name.isupper()
        and not name.startswith("_")
        and isinstance(value, str)
        and value.startswith("https://")
    }
