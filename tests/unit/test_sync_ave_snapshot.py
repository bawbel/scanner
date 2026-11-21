"""
Tests for scripts/sync_ave_snapshot.py

The script writes scanner/_ave_snapshot.py from the AVE corpus that README.md pins, so the scanner
keeps no AVE data typed by hand (issue #148, AVE-CONSUMPTION R2 to R5 and R9).

No test here uses the network: a fixture makes any fetch fail the test.

Run: pytest tests/unit/test_sync_ave_snapshot.py -q
"""

import ast
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sync_ave_snapshot.py"

_spec = importlib.util.spec_from_file_location("sync_ave_snapshot", SCRIPT)
src = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(src)

PIN = "a" * 40
NEW_PIN = "b" * 40


def _record(n: int, **override) -> dict:
    rec = {
        "ave_id": f"AVE-2026-{n:05d}",
        "schema_version": "1.3.0",
        "title": f"Record {n}",
        "severity": "HIGH",
        "aivss_score": 7.5,
        "confidence_baseline": 0.83,
        "evidence_kind_default": "multi_engine",
        "detection_stage": "static_detection",
        "detection_layer": "content",
        "owasp_mcp": ["MCP04", "MCP06"],
        "owasp_asi": ["ASI01"],
        "mitre_atlas": ["AML.T0051"],
        "nist_ai_rmf": ["MAP-1.5"],
        "kill_switch_active": False,  # a field the scanner does not use
    }
    rec.update(override)
    return rec


RECORDS = [_record(1), _record(2, owasp_mcp=["MCP03"]), _record(3)]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any test that reaches the network fails, unless it installs its own fake."""

    def refuse(url, accept):
        raise AssertionError(f"the test reached the network: {url}")

    monkeypatch.setattr(src.counts, "_https_get", refuse)


@pytest.fixture
def work(tmp_path):
    """A README with a pin, a corpus file, and the path the snapshot is written to."""
    readme = tmp_path / "README.md"
    readme.write_text(f"# x\n<!-- counts:corpus ref={PIN} -->\n", encoding="utf-8")
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps(RECORDS), encoding="utf-8")
    return tmp_path


def _run(work, *flags, corpus="corpus.json"):
    return src.main(
        [
            "--readme",
            str(work / "README.md"),
            "--snapshot",
            str(work / "snapshot.py"),
            "--corpus",
            str(work / corpus),
            *flags,
        ]
    )


def _snapshot_text(work) -> str:
    return (work / "snapshot.py").read_text(encoding="utf-8")


# ── Reading the corpus ────────────────────────────────────────────────────────


class TestSchema:
    def test_accepts_the_known_major(self):
        versions, warnings = src.check_schema([_record(1), _record(2, schema_version="1.2.0")])
        assert versions == "1.2.0 and 1.3.0"
        assert warnings == []

    def test_warns_on_a_newer_minor_and_carries_on(self):
        newer = f"1.{src.KNOWN_SCHEMA_MINOR + 1}.0"
        versions, warnings = src.check_schema([_record(1, schema_version=newer)])
        assert versions == newer
        assert len(warnings) == 1 and newer in warnings[0]

    @pytest.mark.parametrize("version", ["2.0.0", "0.9.0", "10.1.0"])
    def test_refuses_an_unknown_major(self, version):
        with pytest.raises(src.CountsError, match="reads major"):
            src.check_schema([_record(1, schema_version=version)])

    @pytest.mark.parametrize("version", [None, "", "1.3", "v1.3.0", 1.3])
    def test_refuses_a_schema_version_it_cannot_read(self, version):
        with pytest.raises(src.CountsError, match="schema_version"):
            src.check_schema([_record(1, schema_version=version)])


class TestBuildSnapshot:
    def test_keeps_only_the_fields_the_scanner_uses_in_a_fixed_order(self):
        snapshot = src.build_snapshot([_record(2), _record(1)])
        assert list(snapshot) == ["AVE-2026-00001", "AVE-2026-00002"]
        assert tuple(snapshot["AVE-2026-00001"]) == src.FIELD_ORDER
        assert "kill_switch_active" not in snapshot["AVE-2026-00001"]

    def test_values_are_copied_not_changed(self):
        entry = src.build_snapshot([_record(1, aivss_score=8)])["AVE-2026-00001"]
        assert entry["aivss_score"] == 8 and isinstance(entry["aivss_score"], int)
        assert entry["owasp_mcp"] == ["MCP04", "MCP06"]

    def test_a_field_ave_does_not_provide_is_none_not_filled_in(self):
        rec = _record(1)
        del rec["owasp_asi"]
        rec["nist_ai_rmf"] = None
        entry = src.build_snapshot([rec])["AVE-2026-00001"]
        assert entry["owasp_asi"] is None and entry["nist_ai_rmf"] is None
        assert entry["mitre_atlas"] == ["AML.T0051"]

    @pytest.mark.parametrize(
        "field, value, message",
        [
            ("title", None, "title is missing"),
            ("title", "", "title is missing"),
            ("severity", 3, "severity is missing"),
            ("evidence_kind_default", None, "evidence_kind_default is missing"),
            ("detection_stage", None, "detection_stage is missing"),
            ("detection_layer", None, "detection_layer is missing"),
            ("aivss_score", "8.0", "aivss_score is missing or not a number"),
            ("confidence_baseline", True, "confidence_baseline is missing or not a number"),
            ("owasp_mcp", None, "owasp_mcp is missing"),
            ("owasp_mcp", "MCP01", "owasp_mcp is missing"),
            ("owasp_mcp", [1], "owasp_mcp is missing"),
            ("mitre_atlas", "AML.T0051", "mitre_atlas is present but not a list"),
        ],
    )
    def test_a_missing_or_malformed_field_refuses_the_corpus_naming_it(self, field, value, message):
        with pytest.raises(src.CountsError, match=f"AVE-2026-00001: {message}"):
            src.build_snapshot([_record(1, **{field: value})])

    def test_a_required_field_that_is_absent_refuses(self):
        rec = _record(1)
        del rec["confidence_baseline"]
        with pytest.raises(src.CountsError, match="confidence_baseline"):
            src.build_snapshot([rec])


# ── The file it writes ────────────────────────────────────────────────────────

META = {"corpus_sha256": "c" * 64, "schema_version": "1.3.0", "source_url": "file:corpus.json"}


class TestRender:
    def test_the_text_reads_back_to_the_same_data_without_running_it(self):
        snapshot = src.build_snapshot(RECORDS)
        found = src.parse_snapshot(src.render(snapshot, META, "2026-01-02T03:04:05Z"))
        assert found["AVE_SNAPSHOT"] == snapshot
        assert found["RECORD_COUNT"] == len(RECORDS)
        assert found["CORPUS_SHA256"] == "c" * 64
        assert found["GENERATED_AT"] == "2026-01-02T03:04:05Z"
        assert src.integrity_problems(found) == []

    def test_it_is_a_python_file_marked_generated_and_left_alone_by_the_formatters(self):
        text = src.render(src.build_snapshot(RECORDS), META, "2026-01-02T03:04:05Z")
        ast.parse(text)
        head = text.splitlines()[:3]
        assert head[0].startswith("# GENERATED by scripts/sync_ave_snapshot.py")
        assert "# fmt: off" in head and "# flake8: noqa" in head
        assert text.endswith("\n") and not text.endswith("\n\n")

    def test_the_same_input_gives_the_same_bytes(self):
        snapshot = src.build_snapshot(RECORDS)
        assert src.render(snapshot, META, "t") == src.render(dict(snapshot), META, "t")

    def test_text_with_quotes_and_non_ascii_survives(self):
        rec = _record(1, title='A "quoted" title \\ with caf\u00e9 and \u2192')
        snapshot = src.build_snapshot([rec])
        found = src.parse_snapshot(src.render(snapshot, META, "t"))
        assert found["AVE_SNAPSHOT"] == snapshot

    def test_the_content_hash_changes_when_any_value_changes(self):
        base = src.build_snapshot(RECORDS)
        edited = src.build_snapshot([RECORDS[0], RECORDS[1], _record(3, owasp_mcp=["MCP09"])])
        assert src.content_sha256(base) != src.content_sha256(edited)
        assert re.fullmatch(r"[0-9a-f]{64}", src.content_sha256(base))

    def test_a_local_file_is_labelled_so_it_cannot_pass_for_the_pinned_artifact(self):
        assert src.source_label("some/dir/corpus.json") == "file:corpus.json"
        url = "https://raw.githubusercontent.com/aveproject/ave/" + PIN + "/dist/x.json"
        assert src.source_label(url) == url


class TestIntegrity:
    def _found(self):
        return src.parse_snapshot(src.render(src.build_snapshot(RECORDS), META, "t"))

    def test_an_intact_file_has_no_problems(self):
        assert src.integrity_problems(self._found()) == []

    def test_an_edited_value_is_caught_without_the_corpus(self):
        found = self._found()
        found["AVE_SNAPSHOT"]["AVE-2026-00001"]["owasp_mcp"] = ["MCP10"]
        assert any("edited by hand" in p for p in src.integrity_problems(found))

    def test_a_dropped_record_is_caught(self):
        found = self._found()
        del found["AVE_SNAPSHOT"]["AVE-2026-00003"]
        assert any("RECORD_COUNT" in p for p in src.integrity_problems(found))

    def test_a_missing_constant_is_caught(self):
        found = self._found()
        del found["CORPUS_SHA256"]
        assert src.integrity_problems(found) == ["CORPUS_SHA256 is missing"]

    def test_a_malformed_digest_is_caught(self):
        found = self._found()
        found["CORPUS_SHA256"] = "not-a-digest"
        assert any("CORPUS_SHA256 is not a sha256" in p for p in src.integrity_problems(found))

    def test_a_snapshot_that_does_not_parse_is_an_error(self):
        with pytest.raises(src.CountsError, match="does not parse"):
            src.parse_snapshot("AVE_SNAPSHOT = {")


# ── Running it ────────────────────────────────────────────────────────────────


class TestWrite:
    def test_writes_the_snapshot_with_its_provenance(self, work, capsys):
        assert _run(work) == 0
        found = src.parse_snapshot(_snapshot_text(work))
        raw = (work / "corpus.json").read_bytes()
        assert found["CORPUS_SHA256"] == src.counts.corpus_sha256(raw)
        assert found["SCHEMA_VERSION"] == "1.3.0"
        assert found["RECORD_COUNT"] == len(RECORDS)
        assert found["SOURCE_URL"] == "file:corpus.json"
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", found["GENERATED_AT"])
        assert "written" in capsys.readouterr().out

    def test_running_it_again_on_the_same_corpus_writes_the_same_bytes(self, work, capsys):
        _run(work)
        first = _snapshot_text(work)
        capsys.readouterr()
        assert _run(work) == 0
        assert _snapshot_text(work) == first
        assert "already current" in capsys.readouterr().out

    def test_a_changed_corpus_rewrites_the_snapshot_and_the_timestamp(self, work):
        _run(work)
        before = src.parse_snapshot(_snapshot_text(work))
        changed = [_record(1, owasp_mcp=["MCP10"]), *RECORDS[1:]]
        (work / "corpus.json").write_text(json.dumps(changed), encoding="utf-8")
        # The timestamp is only reused for an identical corpus, so force a distinct value.
        text = _snapshot_text(work).replace(before["GENERATED_AT"], "2000-01-01T00:00:00Z")
        (work / "snapshot.py").write_text(text, encoding="utf-8")
        assert _run(work) == 0
        after = src.parse_snapshot(_snapshot_text(work))
        assert after["AVE_SNAPSHOT"]["AVE-2026-00001"]["owasp_mcp"] == ["MCP10"]
        assert after["CORPUS_SHA256"] != before["CORPUS_SHA256"]
        assert after["GENERATED_AT"] != "2000-01-01T00:00:00Z"

    def test_an_unknown_schema_major_writes_nothing_and_exits_2(self, work, capsys):
        (work / "corpus.json").write_text(
            json.dumps([_record(1, schema_version="2.0.0")]), encoding="utf-8"
        )
        assert _run(work) == 2
        assert not (work / "snapshot.py").exists()
        assert "reads major" in capsys.readouterr().err

    def test_a_missing_field_writes_nothing_and_exits_2(self, work, capsys):
        rec = _record(1)
        del rec["owasp_mcp"]
        (work / "corpus.json").write_text(json.dumps([rec]), encoding="utf-8")
        assert _run(work) == 2
        assert not (work / "snapshot.py").exists()
        assert "AVE-2026-00001: owasp_mcp" in capsys.readouterr().err

    def test_a_newer_minor_warns_and_still_writes(self, work, capsys):
        newer = f"1.{src.KNOWN_SCHEMA_MINOR + 1}.0"
        (work / "corpus.json").write_text(
            json.dumps([_record(1, schema_version=newer)]), encoding="utf-8"
        )
        assert _run(work) == 0
        assert "newer than" in capsys.readouterr().err
        assert (work / "snapshot.py").exists()

    def test_no_pin_in_the_readme_is_an_error(self, work, capsys):
        (work / "README.md").write_text("# no marker\n", encoding="utf-8")
        assert _run(work) == 2
        assert "counts:corpus" in capsys.readouterr().err

    def test_the_pinned_url_is_what_is_read_when_no_corpus_is_given(self, work, monkeypatch):
        seen = []

        def fake(url, accept):
            seen.append(url)
            return json.dumps(RECORDS).encode()

        monkeypatch.setattr(src.counts, "_https_get", fake)
        monkeypatch.delenv(src.counts.CORPUS_URL_ENV, raising=False)
        code = src.main(
            ["--readme", str(work / "README.md"), "--snapshot", str(work / "snapshot.py")]
        )
        assert code == 0
        expected = src.counts.CORPUS_URL_TEMPLATE.format(ref=PIN)
        assert seen == [expected]
        assert src.parse_snapshot(_snapshot_text(work))["SOURCE_URL"] == expected


class TestCheck:
    def test_passes_on_a_file_just_written(self, work, capsys):
        _run(work)
        capsys.readouterr()
        assert _run(work, "--check") == 0
        assert "matches the pinned corpus" in capsys.readouterr().out

    def test_check_changes_nothing(self, work):
        _run(work)
        before = _snapshot_text(work)
        _run(work, "--check")
        assert _snapshot_text(work) == before

    def test_fails_when_a_value_is_edited_by_hand(self, work, capsys):
        _run(work)
        text = _snapshot_text(work).replace('"MCP03"', '"MCP10"')
        assert text != _snapshot_text(work)
        (work / "snapshot.py").write_text(text, encoding="utf-8")
        assert _run(work, "--check") == 1
        assert "edited by hand" in capsys.readouterr().err

    def test_fails_when_the_edit_also_fixes_the_hash(self, work, capsys):
        """An editor who also repairs CONTENT_SHA256 is caught by the comparison with the corpus."""
        _run(work)
        found = src.parse_snapshot(_snapshot_text(work))
        found["AVE_SNAPSHOT"]["AVE-2026-00002"]["owasp_mcp"] = ["MCP10"]
        old_hash = found["CONTENT_SHA256"]
        new_hash = src.content_sha256(found["AVE_SNAPSHOT"])
        text = _snapshot_text(work).replace('"owasp_mcp": ["MCP03"]', '"owasp_mcp": ["MCP10"]')
        text = text.replace(old_hash, new_hash)
        (work / "snapshot.py").write_text(text, encoding="utf-8")
        assert src.integrity_problems(src.parse_snapshot(text)) == []
        assert _run(work, "--check") == 1
        assert "differs from what" in capsys.readouterr().err

    def test_fails_when_the_corpus_has_moved_on(self, work, capsys):
        _run(work)
        changed = [_record(1, owasp_mcp=["MCP10"]), *RECORDS[1:]]
        (work / "corpus.json").write_text(json.dumps(changed), encoding="utf-8")
        assert _run(work, "--check") == 1
        assert "stale" in capsys.readouterr().err

    def test_fails_when_the_file_is_missing(self, work, capsys):
        assert _run(work, "--check") == 1
        assert "missing" in capsys.readouterr().err

    def test_fails_when_the_file_does_not_parse(self, work):
        (work / "snapshot.py").write_text("AVE_SNAPSHOT = {\n", encoding="utf-8")
        assert _run(work, "--check") == 1

    def test_a_snapshot_made_from_a_local_file_does_not_pass_against_the_pinned_url(
        self, work, monkeypatch, capsys
    ):
        """R2: the one source is the published artifact, so a hand-fed file cannot satisfy CI."""
        _run(work)
        monkeypatch.setattr(
            src.counts, "_https_get", lambda url, accept: json.dumps(RECORDS).encode()
        )
        code = src.main(
            [
                "--readme",
                str(work / "README.md"),
                "--snapshot",
                str(work / "snapshot.py"),
                "--check",
            ]
        )
        assert code == 1
        assert "differs from what" in capsys.readouterr().err

    def test_a_corpus_it_can_read_but_does_not_accept_is_an_error_not_a_skip(self, work, capsys):
        _run(work)
        (work / "corpus.json").write_text(
            json.dumps([_record(1, schema_version="2.0.0")]), encoding="utf-8"
        )
        assert _run(work, "--check") == 2
        assert "reads major" in capsys.readouterr().err


class TestOffline:
    """On a network error the freshness comparison is skipped with a warning. Nothing else is."""

    def _offline(self, monkeypatch):
        def down(url, accept):
            raise src.FetchError(f"could not fetch {url}: unreachable")

        monkeypatch.setattr(src.counts, "_https_get", down)

    def _check_pinned(self, work):
        return src.main(
            [
                "--readme",
                str(work / "README.md"),
                "--snapshot",
                str(work / "snapshot.py"),
                "--check",
            ]
        )

    def test_an_intact_file_passes_with_a_warning(self, work, monkeypatch, capsys):
        _run(work)
        capsys.readouterr()
        self._offline(monkeypatch)
        assert self._check_pinned(work) == 0
        err = capsys.readouterr().err
        assert "freshness was not checked" in err

    def test_a_hand_edited_file_still_fails_offline(self, work, monkeypatch, capsys):
        _run(work)
        text = _snapshot_text(work).replace('"MCP03"', '"MCP10"')
        (work / "snapshot.py").write_text(text, encoding="utf-8")
        capsys.readouterr()
        self._offline(monkeypatch)
        assert self._check_pinned(work) == 1
        assert "CONTENT_SHA256 does not match" in capsys.readouterr().err

    def test_a_pin_that_does_not_exist_is_an_error_not_a_skip(self, work, monkeypatch, capsys):
        """The host answered 404: no retry fixes it, so --check must not read it as offline."""
        _run(work)
        capsys.readouterr()

        def gone(url, accept):
            raise src.CountsError(f"could not fetch {url}: HTTP Error 404: Not Found")

        monkeypatch.setattr(src.counts, "_https_get", gone)
        assert self._check_pinned(work) == 2
        assert "404" in capsys.readouterr().err

    def test_write_mode_cannot_skip_and_exits_2(self, work, monkeypatch, capsys):
        self._offline(monkeypatch)
        code = src.main(
            ["--readme", str(work / "README.md"), "--snapshot", str(work / "snapshot.py")]
        )
        assert code == 2
        assert not (work / "snapshot.py").exists()
        assert "could not fetch" in capsys.readouterr().err


# ── The snapshot that is committed ────────────────────────────────────────────


class TestCommittedSnapshot:
    """These run offline on the real file, so a hand edit or a moved pin fails the suite."""

    @pytest.fixture(scope="class")
    def found(self):
        return src.parse_snapshot((ROOT / src.SNAPSHOT_RELATIVE).read_text(encoding="utf-8"))

    def test_the_file_is_intact(self, found):
        assert src.integrity_problems(found) == []

    def test_it_was_made_from_the_commit_the_readme_pins(self, found):
        pin = src.counts.pinned_ref((ROOT / "README.md").read_text(encoding="utf-8"))
        assert found["SOURCE_URL"] == src.counts.CORPUS_URL_TEMPLATE.format(ref=pin), (
            "README.md pins a different AVE commit than the snapshot was made from. "
            "Run: python scripts/sync_ave_snapshot.py"
        )

    def test_it_carries_the_fields_the_scanner_uses_for_every_record(self, found):
        for ave_id, entry in found["AVE_SNAPSHOT"].items():
            assert tuple(entry) == src.FIELD_ORDER, ave_id

    def test_the_schema_is_one_this_script_reads(self, found):
        records = [{"ave_id": k, "schema_version": found["SCHEMA_VERSION"]} for k in ("AVE-0-0",)]
        for version in found["SCHEMA_VERSION"].split(" and "):
            records[0]["schema_version"] = version
            src.check_schema(records)
