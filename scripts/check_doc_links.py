#!/usr/bin/env python3
"""
Fetch every documentation URL in scanner/docs_urls.py and fail when one does not resolve.

Run weekly by .github/workflows/doc-links.yml, and on a pull request that changes the
URLs. It needs the network. The offline check is tests/test_doc_links.py.

Standard library only: it loads docs_urls.py by path, so it needs no install.

Exit 0 when every URL answers 2xx after redirects, 1 when at least one does not.

    python scripts/check_doc_links.py
"""

from __future__ import annotations

import importlib.util
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_URLS = REPO_ROOT / "scanner" / "docs_urls.py"

TIMEOUT_S = 15
ATTEMPTS = 3
BACKOFF_S = 2.0
READ_BYTES = 1024
USER_AGENT = "bawbel-scanner-doc-link-check"


class Result(NamedTuple):
    ok: bool
    status: str  # an HTTP status code, or the name of the exception that stopped the fetch
    final_url: str


# What: fetches one documentation URL and reports whether it resolves
# How:  urllib.request GET with a 15s timeout, redirects followed, at most 1 KiB read
# Sec:  INPUT  - the URLs come from the constants in scanner/docs_urls.py, never from
#               a scanned file or from user input; only https:// and http:// are fetched
#       TRUST  - the response body is read to at most 1 KiB and discarded, never parsed,
#               never written to disk, never executed
#       ERROR  - HTTPError and OSError (URLError, TimeoutError, connection errors) are
#               caught; the status or exception class name is reported, nothing more
def check_url(
    url: str,
    attempts: int = ATTEMPTS,
    backoff_s: float = BACKOFF_S,
    sleep: Callable[[float], None] = time.sleep,
) -> Result:
    """Return whether `url` resolves. A 4xx answer is final. A 5xx or a network error retries."""
    if not url.startswith(("https://", "http://")):
        return Result(False, "BadScheme", url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    result = Result(False, "NotTried", url)
    for attempt in range(1, attempts + 1):
        try:
            opened = urllib.request.urlopen(request, timeout=TIMEOUT_S)  # nosec B310  # noqa: S310
            with opened as response:
                response.read(READ_BYTES)
                # urlopen raises HTTPError for a non-2xx answer, so the range is a second guard
                code = response.status
                return Result(200 <= code < 300, str(code), response.geturl())
        except urllib.error.HTTPError as exc:
            result = Result(False, str(exc.code), url)
            if exc.code < 500:
                return result
        except OSError as exc:  # URLError, TimeoutError and connection errors
            result = Result(False, type(exc).__name__, url)
        if attempt < attempts:
            sleep(backoff_s * attempt)
    return result


def load_urls(path: Path = DOCS_URLS) -> dict[str, str]:
    """Load docs_urls.py by path and return its URL constants, keyed by name."""
    spec = importlib.util.spec_from_file_location("docs_urls", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.all_urls()


def main() -> int:
    urls = load_urls()
    if not urls:
        print("FAIL: scanner/docs_urls.py defines no URL, so nothing was checked")
        return 1
    failed = 0
    for name, url in urls.items():
        result = check_url(url)
        if result.ok:
            moved = "" if result.final_url == url else f" -> {result.final_url}"
            print(f"ok    {result.status}  {name}  {url}{moved}")
        else:
            failed += 1
            print(f"FAIL  {result.status}  {name}  {url}")
    print(f"{len(urls) - failed} of {len(urls)} documentation URLs resolve")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
