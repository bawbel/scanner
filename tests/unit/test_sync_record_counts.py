"""
Tests for scripts/sync_record_counts.py

The script derives the counts in README.md from the AVE corpus and the scanner's rule files.
Issue #120: a count typed by hand drifts (the corpus grew from 80 to 87 records in a week).

Run: pytest tests/unit/test_sync_record_counts.py -q
"""

import importlib.util
import json
import re
import textwrap
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sync_record_counts.py"

_spec = importlib.util.spec_from_file_location("sync_record_counts", SCRIPT)
src = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(src)


# ── A small scanner tree and corpus ───────────────────────────────────────────

PIN = "a" * 40
NEW_PIN = "b" * 40


def _record(n: int, stage: str = "static_detection") -> dict:
    return {
        "ave_id": f"AVE-2026-{n:05d}",
        "schema_version": "1.1.0",
        "detection_stage": stage,
        "aivss": {"spec_version": "0.8"},
    }


# 1-6 published. 1,2 pattern. 3 yara. 4 semgrep. 5 magika. 6 runtime, no rule.
RECORDS = [
    _record(1),
    _record(2),
    _record(3),
    _record(4),
    _record(5),
    _record(6, "runtime_observed"),
    _record(7, "runtime_drift_detected"),
    _record(8),
]


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A minimal scanner checkout with a known number of rules."""

    def write(relative: str, text: str) -> None:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")

    write(
        src.PATTERN_RULES_FILE,
        """
        PATTERN_RULES: list[dict] = [
            {"rule_id": "bawbel-a", "ave_id": "AVE-2026-00001"},
            {"rule_id": "bawbel-b", "ave_id": None},
        ]
        PATTERN_RULES_V2: list[dict] = [
            {"rule_id": "bawbel-c", "ave_id": "AVE-2026-00002"},
        ]
        PATTERN_RULES = PATTERN_RULES + PATTERN_RULES_V2
        """,
    )
    write(
        src.YARA_RULES_FILE,
        """
        rule one {
            meta:
                ave_id = "AVE-2026-00003"
        }
        rule two : tag {
            meta:
                ave_id = "AVE-2026-00003"
        }
        """,
    )
    write(
        src.SEMGREP_RULES_FILE,
        """
        rules:
          - id: ave-four
            metadata:
              ave_id: AVE-2026-00004
          - id: ave-four-b
            metadata:
              ave_id: "AVE-2026-00004"
        """,
    )
    write(src.MAGIKA_ENGINE_FILE, 'f = Finding(ave_id="AVE-2026-00005", title="x")\n')
    write(
        src.FLOWS_FILE,
        """
        FLOW_DEFINITIONS: list = [
            FlowDef(name="a"),
            FlowDef(name="b"),
            FlowDef(name="c"),
        ]
        """,
    )
    write(
        src.AVE_META_FILE,
        """
        AVE_META: dict = {
            "AVE-2026-00001": 1,
            "AVE-2026-00002": 1,
            "AVE-2026-00006": 1,
            "AVE-2026-00008": 1,
        }
        """,
    )
    return tmp_path


# ── Measuring ─────────────────────────────────────────────────────────────────


class TestMeasure:
    def test_every_count(self, tree):
        values, warnings = src.measure(RECORDS, tree)
        assert warnings == []
        assert values["published"] == "8"
        assert (values["id_first"], values["id_last"]) == ("AVE-2026-00001", "AVE-2026-00008")
        assert values["pattern_rules"] == "3"  # V1 and V2 are joined, bawbel-b has no ave_id
        assert values["yara_rules"] == "2"
        assert values["semgrep_rules"] == "2"
        assert values["chains"] == "3"
        assert values["detected"] == "5"  # 1, 2, 3, 4 and Magika's 5
        assert values["detected_static"] == "4"
        assert values["magika_only_ids"] == "AVE-2026-00005"
        assert values["uncovered"] == "3"  # 6, 7, 8
        assert values["uncovered_static"] == "1"
        assert values["uncovered_runtime"] == "2"
        assert values["runtime_observed"] == "1"
        assert values["runtime_drift_detected"] == "1"
        assert values["metadata_only"] == "2"  # 6 and 8 have metadata but no rule
        assert values["metadata_only_ids"] == "AVE-2026-00006, 00008"
        assert values["schema_version"] == "1.1.0"
        assert values["aivss_spec"] == "0.8"
        assert (
            values["badge"].startswith("[![AVE Records](") and "AVE_Records-8-" in values["badge"]
        )

    def test_a_rule_citing_an_unpublished_id_is_a_warning_not_a_count(self, tree):
        values, warnings = src.measure(
            [r for r in RECORDS if r["ave_id"] != "AVE-2026-00002"], tree
        )
        assert values["detected"] == "4"
        assert any("AVE-2026-00002" in w for w in warnings)

    def test_mixed_schema_versions_are_both_named(self, tree):
        records = [dict(r) for r in RECORDS]
        records[0]["schema_version"] = "1.0.0"
        assert src.measure(records, tree)[0]["schema_version"] == "1.0.0 and 1.1.0"

    @pytest.mark.parametrize(
        "relative, text, message",
        [
            (src.PATTERN_RULES_FILE, "PATTERN_RULES = build_rules()\n", "cannot read"),
            (src.PATTERN_RULES_FILE, "OTHER = []\n", "not found"),
            (src.PATTERN_RULES_FILE, 'PATTERN_RULES = [{"title": "no id"}]\n', "no rule_id"),
            (src.YARA_RULES_FILE, "rule x {\n meta:\n  note = 1\n}\n", "cites no ave_id"),
            (src.YARA_RULES_FILE, "// no rules here\n", "no rules found"),
            (src.SEMGREP_RULES_FILE, "rules:\n  - id: a\n  - id: b\n", "ave_id lines"),
            (src.FLOWS_FILE, "FLOW_DEFINITIONS = [make_flow()]\n", "not a FlowDef"),
            (src.AVE_META_FILE, "AVE_META = load()\n", "not a dict literal"),
        ],
    )
    def test_an_unrecognized_layout_fails_closed(self, tree, relative, text, message):
        (tree / relative).write_text(text, encoding="utf-8")
        with pytest.raises(src.CountsError, match=message):
            src.measure(RECORDS, tree)

    def test_a_missing_rule_file_fails_closed(self, tree):
        (tree / src.YARA_RULES_FILE).unlink()
        with pytest.raises(src.CountsError, match="cannot read"):
            src.measure(RECORDS, tree)


class TestFormatIdRanges:
    @pytest.mark.parametrize(
        "ids, expected",
        [
            ([], "none"),
            (["AVE-2026-00024"], "AVE-2026-00024"),
            (["AVE-2026-00041", "AVE-2026-00042", "AVE-2026-00043"], "AVE-2026-00041 to 00043"),
            (["AVE-2026-00049", "AVE-2026-00051"], "AVE-2026-00049, 00051"),
            (
                [f"AVE-2026-{n:05d}" for n in (41, 42, 43, 44, 45, 49, 50, 51)],
                "AVE-2026-00041 to 00045, 00049 to 00051",
            ),
            (["AVE-2027-00001", "AVE-2026-00099"], "AVE-2026-00099, AVE-2027-00001"),
            (["AVE-2026-00005", "AVE-2026-00003", "AVE-2026-00004"], "AVE-2026-00003 to 00005"),
        ],
    )
    def test_ranges(self, ids, expected):
        assert src.format_id_ranges(ids) == expected


# ── Reading the scanner as it really is ───────────────────────────────────────


class TestAgainstTheRealScanner:
    """The script parses the rule files. These tests check it agrees with what the scanner loads."""

    def test_pattern_rules_match_the_runtime_list(self):
        from scanner.engines.pattern_engine import PATTERN_RULES

        count, ids = src.pattern_rules(ROOT)
        assert count == len(PATTERN_RULES)
        assert ids == {r["ave_id"] for r in PATTERN_RULES if r.get("ave_id")}

    def test_chains_match_the_runtime_list(self):
        from scanner.core.toxic_flows.flows import FLOW_DEFINITIONS

        assert src.chain_count(ROOT) == len(FLOW_DEFINITIONS)

    def test_metadata_ids_match_the_runtime_table(self):
        from scanner.ave_meta import AVE_META

        assert src.metadata_ids(ROOT) == set(AVE_META)

    def test_yara_rules_match_the_compiled_rules(self):
        yara = pytest.importorskip("yara")
        compiled = yara.compile(filepath=str(ROOT / src.YARA_RULES_FILE))
        rules = list(compiled)
        count, ids = src.yara_rules(ROOT)
        assert count == len(rules)
        assert ids == {r.meta["ave_id"] for r in rules}

    def test_semgrep_rules_match_a_yaml_parse(self):
        yaml = pytest.importorskip("yaml")
        data = yaml.safe_load((ROOT / src.SEMGREP_RULES_FILE).read_text(encoding="utf-8"))
        count, ids = src.semgrep_rules(ROOT)
        assert count == len(data["rules"])
        assert ids == {str(r["metadata"]["ave_id"]) for r in data["rules"]}

    def test_magika_reports_the_content_type_mismatch_record(self):
        assert src.magika_ids(ROOT) == {"AVE-2026-00024"}


# ── The README ────────────────────────────────────────────────────────────────


class TestReadmeMarkers:
    """Offline checks on the real README; the live `--check` runs in CI."""

    text = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_there_is_one_valid_pin(self):
        pins = src.REF_RE.findall(self.text)
        assert len(pins) == 1

    def test_every_marker_names_a_measurement(self, tree):
        known = set(src.measure(RECORDS, tree)[0])
        used = {m["name"] for m in src.COUNT_RE.finditer(self.text)}
        assert used, "the README has no count markers"
        assert used <= known, f"unknown markers: {sorted(used - known)}"

    def test_no_marker_sits_inside_a_code_fence(self):
        # A comment inside a fence is printed literally, so a count there would show as markup.
        in_fence = False
        for number, line in enumerate(self.text.splitlines(), 1):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
            elif in_fence and ("<!-- count:" in line or "counts:corpus" in line):
                pytest.fail(f"README.md:{number}: marker inside a code fence")

    def test_markers_are_balanced(self):
        assert self.text.count("<!-- count:") == self.text.count("<!-- /count -->")

    def test_the_pin_is_the_only_corpus_reference(self):
        assert not re.search(r"ave-records-latest\.json\s*$", self.text, re.M) or src.REF_RE.search(
            self.text
        )


class TestApplyCounts:
    values = {"published": "8", "chains": "3", "badge": "[x](https://a.b/c\\d)"}

    def test_rewrites_every_marker_and_keeps_the_prose(self):
        text = "Total <!-- count:published -->7<!-- /count --> records, <!-- count:chains -->2<!-- /count --> chains.\n"
        new, changes = src.apply_counts(text, self.values)
        assert (
            new
            == "Total <!-- count:published -->8<!-- /count --> records, <!-- count:chains -->3<!-- /count --> chains.\n"
        )
        assert [(c[1], c[2], c[3]) for c in changes] == [
            ("published", "7", "8"),
            ("chains", "2", "3"),
        ]

    def test_reports_the_line_number(self):
        text = "a\nb\n<!-- count:published -->1<!-- /count -->\n"
        assert src.apply_counts(text, self.values)[1][0][0] == 3

    def test_a_current_value_is_not_a_change(self):
        text = "<!-- count:published -->8<!-- /count -->\n"
        new, changes = src.apply_counts(text, self.values)
        assert (new, changes) == (text, [])

    def test_the_same_name_can_appear_many_times(self):
        text = "<!-- count:published -->1<!-- /count --> and <!-- count:published -->2<!-- /count -->\n"
        new, changes = src.apply_counts(text, self.values)
        assert new.count(">8<") == 2 and len(changes) == 2

    def test_a_backslash_in_a_value_is_kept_literally(self):
        new, _ = src.apply_counts("<!-- count:badge -->old<!-- /count -->", self.values)
        assert new == "<!-- count:badge -->[x](https://a.b/c\\d)<!-- /count -->"

    def test_an_unknown_name_is_an_error(self):
        with pytest.raises(src.CountsError, match="no measurement: nope"):
            src.apply_counts("<!-- count:nope -->1<!-- /count -->", self.values)

    def test_text_with_no_markers_is_untouched(self):
        assert src.apply_counts("plain 87 records\n", self.values) == ("plain 87 records\n", [])


class TestPin:
    def test_reads_and_sets_the_pin(self):
        text = f"x\n<!-- counts:corpus ref={PIN} -->\ny\n"
        assert src.pinned_ref(text) == PIN
        assert src.pinned_ref(src.set_ref(text, NEW_PIN)) == NEW_PIN

    @pytest.mark.parametrize(
        "text",
        ["no pin\n", f"<!-- counts:corpus ref={PIN} -->\n" * 2, "<!-- counts:corpus ref=abc -->\n"],
    )
    def test_zero_two_or_a_malformed_pin_is_an_error(self, text):
        with pytest.raises(src.CountsError, match="exactly one"):
            src.pinned_ref(text)


# ── The corpus ────────────────────────────────────────────────────────────────


class TestCorpus:
    def test_a_list_and_an_object_with_records_both_load(self):
        assert len(src.parse_corpus(json.dumps(RECORDS).encode(), "t")) == 8
        assert len(src.parse_corpus(json.dumps({"records": RECORDS}).encode(), "t")) == 8

    @pytest.mark.parametrize(
        "raw, message",
        [
            (b"not json", "not valid JSON"),
            (b"[]", "no list of records"),
            (b'{"records": 3}', "no list of records"),
            (b'[{"title": "x"}]', "valid ave_id"),
            (b'[{"ave_id": "AVE-26-1"}]', "valid ave_id"),
            (b'["AVE-2026-00001"]', "valid ave_id"),
            (json.dumps([RECORDS[0], RECORDS[0]]).encode(), "repeats AVE-2026-00001"),
        ],
    )
    def test_bad_input_is_an_error(self, raw, message):
        with pytest.raises(src.CountsError, match=message):
            src.parse_corpus(raw, "t")

    def test_the_hash_ignores_key_order_and_changes_with_content(self):
        a = [{"ave_id": "AVE-2026-00001", "x": 1, "y": 2}]
        b = [{"y": 2, "x": 1, "ave_id": "AVE-2026-00001"}]
        c = [{"ave_id": "AVE-2026-00001", "x": 1, "y": 3}]
        assert src.corpus_sha256(a) == src.corpus_sha256(b) != src.corpus_sha256(c)
        assert re.fullmatch(r"[0-9a-f]{64}", src.corpus_sha256(a))

    def test_a_local_file_loads_without_the_network(self, tmp_path, monkeypatch):
        monkeypatch.setattr(src, "_https_get", lambda *a, **k: pytest.fail("network used"))
        path = tmp_path / "corpus.json"
        path.write_text(json.dumps(RECORDS), encoding="utf-8")
        assert len(src.load_corpus(str(path))) == 8


class _Response:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]


class _FakeOpener:
    """Stands in for the opener _https_get builds. Records what it was asked to open."""

    def __init__(self, handlers, outcome):
        self.handlers, self.outcome = handlers, outcome
        self.request = self.timeout = None

    def open(self, request, timeout):
        self.request, self.timeout = request, timeout
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return _Response(self.outcome)


def _patch_opener(monkeypatch, outcome=b"{}"):
    """Replace urllib's build_opener; returns the list of openers it created."""
    made: list = []

    def build(*handlers):
        made.append(_FakeOpener(handlers, outcome))
        return made[-1]

    monkeypatch.setattr(src.urllib.request, "build_opener", build)
    return made


class TestNetwork:
    @pytest.mark.parametrize(
        "url", ["http://example.com/x", "file:///etc/passwd", "ftp://x/y", "no-scheme", ""]
    )
    def test_only_https_is_fetched(self, url, monkeypatch):
        made = _patch_opener(monkeypatch)
        with pytest.raises(src.CountsError, match="not an https URL"):
            src._https_get(url, "application/json")
        assert made == []

    def test_a_network_error_becomes_a_counts_error(self, monkeypatch):
        _patch_opener(monkeypatch, urllib.error.URLError("down"))
        with pytest.raises(src.CountsError, match="could not fetch"):
            src._https_get("https://example.com/x", "application/json")

    def test_a_timeout_is_set_and_an_oversized_body_is_refused(self, monkeypatch):
        made = _patch_opener(monkeypatch, b"x" * (src.MAX_BYTES + 5))
        with pytest.raises(src.CountsError, match="larger than"):
            src._https_get("https://example.com/x", "application/json")
        assert made[0].timeout == src.FETCH_TIMEOUT_SEC

    def test_a_response_within_the_cap_is_returned(self, monkeypatch):
        _patch_opener(monkeypatch, b"hello")
        assert src._https_get("https://example.com/x", "application/json") == b"hello"


class TestGithubToken:
    """GITHUB_TOKEN goes to api.github.com and nowhere else, and never follows a redirect."""

    @pytest.mark.parametrize(
        "url, sent",
        [
            ("https://api.github.com/repos/aveproject/ave/commits/main", True),
            ("https://API.GITHUB.COM/repos/x", True),
            ("https://raw.githubusercontent.com/aveproject/ave/main/x.json", False),
            ("https://github.com/aveproject/ave", False),
            ("https://evil-github.com/x", False),
            ("https://notapi.github.com/x", False),
            ("https://api.github.com.evil.example/x", False),
            ("https://github.com.evil.example/x", False),
            ("https://api.github.com@evil.example/x", False),
            ("https://example.com/x", False),
        ],
    )
    def test_which_hosts_receive_the_token(self, url, sent, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret_value")
        made = _patch_opener(monkeypatch)
        src._https_get(url, "application/json")
        auth = made[0].request.get_header("Authorization")
        assert (auth == "Bearer ghp_secret_value") is sent
        assert sent or auth is None

    def test_no_token_means_no_header_even_for_github(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        made = _patch_opener(monkeypatch)
        src._https_get("https://api.github.com/x", "application/json")
        assert made[0].request.get_header("Authorization") is None
        assert made[0].handlers == ()  # redirects behave as usual without a token

    def test_an_authenticated_request_refuses_redirects(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret_value")
        made = _patch_opener(monkeypatch)
        src._https_get("https://api.github.com/x", "application/json")
        assert made[0].handlers == (src._NoRedirect,)
        assert (
            src._NoRedirect().redirect_request(
                None, None, 302, "Found", {}, "https://evil.example/"
            )
            is None
        )

    def test_a_redirect_from_the_api_is_an_error_not_a_second_request(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret_value")
        redirect = urllib.error.HTTPError("https://api.github.com/x", 302, "Found", {}, None)
        _patch_opener(monkeypatch, redirect)
        with pytest.raises(src.CountsError, match="could not fetch"):
            src._https_get("https://api.github.com/x", "application/json")

    def test_the_token_never_appears_in_an_error(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret_value")
        _patch_opener(monkeypatch, urllib.error.URLError("down"))
        with pytest.raises(src.CountsError) as exc:
            src._https_get("https://api.github.com/x", "application/json")
        assert "ghp_secret_value" not in str(exc.value)


class TestPinSource:
    def test_head_sha_must_look_like_a_commit(self, monkeypatch):
        monkeypatch.setattr(src, "_https_get", lambda *a, **k: b"<html>rate limited</html>")
        with pytest.raises(src.CountsError, match="did not return a commit sha"):
            src.head_sha()
        monkeypatch.setattr(src, "_https_get", lambda *a, **k: (NEW_PIN + "\n").encode())
        assert src.head_sha() == NEW_PIN

    def test_the_urls_have_one_definition(self):
        assert src.CORPUS_URL_TEMPLATE.format(ref=PIN).startswith(
            "https://raw.githubusercontent.com/"
        )
        assert src.HEAD_SHA_URL.startswith("https://api.github.com/")


# ── The command line ──────────────────────────────────────────────────────────


@pytest.fixture
def workspace(tree, tmp_path, monkeypatch):
    """A README with a pin and markers, a corpus file, and the small scanner tree."""
    readme = tmp_path / "README.md"
    readme.write_text(
        f"<!-- counts:corpus ref={PIN} -->\n"
        "Records: <!-- count:published -->8<!-- /count -->\n"
        "Chains: <!-- count:chains -->3<!-- /count -->\n",
        encoding="utf-8",
    )
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps(RECORDS), encoding="utf-8")
    real_measure = src.measure
    monkeypatch.setattr(src, "measure", lambda records, root=tree: real_measure(records, tree))
    return readme, corpus


class TestMain:
    def test_check_passes_when_current(self, workspace, capsys):
        readme, corpus = workspace
        assert src.main(["--check", "--corpus", str(corpus), "--readme", str(readme)]) == 0
        assert "match the corpus" in capsys.readouterr().out

    def test_check_fails_and_names_the_line_when_stale(self, workspace, capsys):
        readme, corpus = workspace
        readme.write_text(readme.read_text().replace(">8<", ">9<"), encoding="utf-8")
        before = readme.read_text()
        assert src.main(["--check", "--corpus", str(corpus), "--readme", str(readme)]) == 1
        assert "README.md:2: count:published is '9', measured '8'" in capsys.readouterr().err
        assert readme.read_text() == before  # --check writes nothing

    def test_write_mode_fixes_it(self, workspace):
        readme, corpus = workspace
        readme.write_text(readme.read_text().replace(">8<", ">9<"), encoding="utf-8")
        assert src.main(["--corpus", str(corpus), "--readme", str(readme)]) == 0
        assert ">8<" in readme.read_text()
        assert src.main(["--check", "--corpus", str(corpus), "--readme", str(readme)]) == 0

    def test_an_unreadable_corpus_exits_2_and_writes_nothing(self, workspace, tmp_path, capsys):
        readme, _ = workspace
        bad = tmp_path / "bad.json"
        bad.write_text("{", encoding="utf-8")
        readme.write_text(readme.read_text().replace(">8<", ">9<"), encoding="utf-8")
        before = readme.read_text()
        assert src.main(["--corpus", str(bad), "--readme", str(readme)]) == 2
        assert "not valid JSON" in capsys.readouterr().err
        assert readme.read_text() == before

    def test_a_missing_readme_exits_2(self, workspace, tmp_path):
        _, corpus = workspace
        assert (
            src.main(["--check", "--corpus", str(corpus), "--readme", str(tmp_path / "none.md")])
            == 2
        )

    def test_update_ref_moves_the_pin_and_rewrites(self, workspace, monkeypatch):
        readme, corpus = workspace
        monkeypatch.setattr(src, "head_sha", lambda: NEW_PIN)
        readme.write_text(readme.read_text().replace(">8<", ">9<"), encoding="utf-8")
        assert src.main(["--update-ref", "--corpus", str(corpus), "--readme", str(readme)]) == 0
        text = readme.read_text()
        assert src.pinned_ref(text) == NEW_PIN and ">8<" in text

    def test_update_ref_cannot_be_combined_with_check(self, workspace):
        readme, corpus = workspace
        with pytest.raises(SystemExit) as exc:
            src.main(["--check", "--update-ref", "--readme", str(readme)])
        assert exc.value.code == 2

    def test_the_pinned_commit_picks_the_url(self, workspace, monkeypatch):
        readme, _ = workspace
        seen = []
        monkeypatch.delenv(src.CORPUS_URL_ENV, raising=False)
        monkeypatch.setattr(src, "load_corpus", lambda source: seen.append(source) or RECORDS)
        assert src.main(["--check", "--readme", str(readme)]) == 0
        assert seen == [src.CORPUS_URL_TEMPLATE.format(ref=PIN)]

    def test_the_environment_variable_overrides_the_pin(self, workspace, monkeypatch):
        readme, _ = workspace
        seen = []
        monkeypatch.setenv(src.CORPUS_URL_ENV, "https://example.com/corpus.json")
        monkeypatch.setattr(src, "load_corpus", lambda source: seen.append(source) or RECORDS)
        assert src.main(["--check", "--readme", str(readme)]) == 0
        assert seen == ["https://example.com/corpus.json"]

    def test_the_flag_overrides_the_environment(self, workspace, monkeypatch):
        readme, _ = workspace
        seen = []
        monkeypatch.setenv(src.CORPUS_URL_ENV, "https://example.com/corpus.json")
        monkeypatch.setattr(src, "load_corpus", lambda source: seen.append(source) or RECORDS)
        assert src.main(["--check", "--corpus", "local.json", "--readme", str(readme)]) == 0
        assert seen == ["local.json"]

    def test_a_rule_citing_an_unpublished_id_warns_on_stderr(self, workspace, capsys, tmp_path):
        readme, _ = workspace
        corpus = tmp_path / "small.json"
        corpus.write_text(
            json.dumps([r for r in RECORDS if r["ave_id"] != "AVE-2026-00002"]), encoding="utf-8"
        )
        src.main(["--corpus", str(corpus), "--readme", str(readme)])
        assert "AVE-2026-00002" in capsys.readouterr().err
