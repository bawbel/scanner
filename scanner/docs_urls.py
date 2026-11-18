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

WEBSITE and AVE_STANDARD are not written here. scanner.config owns those two values
(PROJECT_HOMEPAGE_URL and AVE_PROJECT_URL, used by the SARIF output too), and this
module names them so that the weekly link check covers them. The imports carry a
leading underscore so that all_urls() lists each URL once.
"""

from scanner.config import AVE_PROJECT_URL as _AVE_PROJECT_URL
from scanner.config import PROJECT_HOMEPAGE_URL as _PROJECT_HOMEPAGE_URL

_REPO_BLOB_MAIN = "https://github.com/bawbel/scanner/blob/main/"

# The guide the pre-commit hook points at when it lists findings.
SUPPRESSION_GUIDE = _REPO_BLOB_MAIN + "docs/guides/suppression.md"

# Landing page of the published documentation, shown by `bawbel version`.
DOCS_HOME = "https://bawbel.io/docs"

# Project home, written into SARIF output as the tool's informationUri.
WEBSITE = _PROJECT_HOMEPAGE_URL

# The AVE standard, shown by `bawbel version` and `bawbel report`. It is also the SARIF
# helpUri for a finding that has no record URL of its own.
AVE_STANDARD = _AVE_PROJECT_URL

# MCP specification, referenced by the conformance checks.
MCP_SPECIFICATION = "https://modelcontextprotocol.io/specification"


def display_text(url: str) -> str:
    """Return a URL without its scheme and trailing slash, for the visible text of a link."""
    return url.removeprefix("https://").rstrip("/")


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
