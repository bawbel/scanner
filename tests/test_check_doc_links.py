"""
scripts/check_doc_links.py, the weekly network check of the documentation URLs.
Issue #133.

The script is tested against a real HTTP server on the loopback interface, so these tests
need no outside network. They cover what makes the weekly check trustworthy: a dead link
fails the run, a 5xx or a dropped connection is retried, a redirect is followed, and a
scheme other than http or https is never fetched.

Run: pytest tests/test_check_doc_links.py -q
"""

import http.server
import importlib.util
import socket
import threading
from pathlib import Path

import pytest

from scanner import docs_urls

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check_doc_links.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("check_doc_links", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_doc_links = _load_script()


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves the paths the tests ask for, and counts every request per path."""

    def do_GET(self):  # noqa: N802 (the name is fixed by http.server)
        self.server.hits[self.path] = self.server.hits.get(self.path, 0) + 1
        if self.path == "/ok":
            self._reply(200, b"fine")
        elif self.path == "/missing":
            self._reply(404, b"no such page")
        elif self.path == "/down":
            self._reply(503, b"unavailable")
        elif self.path == "/flaky":
            # First request fails, every later one succeeds.
            self._reply(503 if self.server.hits[self.path] == 1 else 200, b"x")
        elif self.path == "/choices":
            # A 3xx that names nowhere to go: urllib cannot follow it.
            self._reply(300, b"multiple choices")
        elif self.path == "/moved":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._reply(404, b"unknown")

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the test output quiet
        pass


@pytest.fixture
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.hits = {}
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def _base(httpd):
    return f"http://127.0.0.1:{httpd.server_port}"


def _no_sleep(sleeps):
    return lambda seconds: sleeps.append(seconds)


class TestCheckUrl:
    def test_a_200_resolves(self, server):
        result = check_doc_links.check_url(_base(server) + "/ok")
        assert result.ok is True
        assert result.status == "200"

    def test_a_404_fails_and_is_not_retried(self, server):
        sleeps = []
        result = check_doc_links.check_url(_base(server) + "/missing", sleep=_no_sleep(sleeps))
        assert result.ok is False
        assert result.status == "404"
        assert server.hits["/missing"] == 1
        assert sleeps == []

    def test_a_persistent_5xx_is_retried_then_fails(self, server):
        sleeps = []
        result = check_doc_links.check_url(
            _base(server) + "/down", attempts=3, sleep=_no_sleep(sleeps)
        )
        assert result.ok is False
        assert result.status == "503"
        assert server.hits["/down"] == 3
        assert len(sleeps) == 2

    def test_a_transient_5xx_that_recovers_passes(self, server):
        result = check_doc_links.check_url(_base(server) + "/flaky", sleep=_no_sleep([]))
        assert result.ok is True
        assert server.hits["/flaky"] == 2

    def test_a_3xx_that_cannot_be_followed_fails_and_is_not_retried(self, server):
        result = check_doc_links.check_url(_base(server) + "/choices", sleep=_no_sleep([]))
        assert result.ok is False
        assert result.status == "300"
        assert server.hits["/choices"] == 1

    def test_a_redirect_is_followed_and_the_final_url_reported(self, server):
        result = check_doc_links.check_url(_base(server) + "/moved")
        assert result.ok is True
        assert result.final_url == _base(server) + "/ok"

    def test_a_refused_connection_fails_after_retrying(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        sleeps = []
        result = check_doc_links.check_url(
            f"http://127.0.0.1:{port}/", attempts=2, sleep=_no_sleep(sleeps)
        )
        assert result.ok is False
        assert result.status == "URLError"
        assert len(sleeps) == 1

    @pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.invalid/x", "x"])
    def test_a_scheme_other_than_http_is_never_fetched(self, url):
        result = check_doc_links.check_url(url)
        assert result.ok is False
        assert result.status == "BadScheme"


class TestMain:
    def test_exit_0_when_every_url_resolves(self, server, monkeypatch, capsys):
        urls = {"ONE": _base(server) + "/ok", "TWO": _base(server) + "/moved"}
        monkeypatch.setattr(check_doc_links, "load_urls", lambda: urls)
        assert check_doc_links.main() == 0
        out = capsys.readouterr().out
        assert "2 of 2 documentation URLs resolve" in out
        assert "FAIL" not in out

    def test_exit_1_and_the_dead_url_named_when_one_fails(self, server, monkeypatch, capsys):
        urls = {"GOOD": _base(server) + "/ok", "DEAD": _base(server) + "/missing"}
        monkeypatch.setattr(check_doc_links, "load_urls", lambda: urls)
        assert check_doc_links.main() == 1
        out = capsys.readouterr().out
        assert f"FAIL  404  DEAD  {urls['DEAD']}" in out
        assert "1 of 2 documentation URLs resolve" in out

    def test_exit_1_when_there_is_nothing_to_check(self, monkeypatch, capsys):
        monkeypatch.setattr(check_doc_links, "load_urls", lambda: {})
        assert check_doc_links.main() == 1
        assert "nothing was checked" in capsys.readouterr().out


class TestLoadUrls:
    def test_the_script_reads_the_same_urls_as_the_package(self):
        assert check_doc_links.load_urls() == docs_urls.all_urls()
        assert check_doc_links.load_urls()
