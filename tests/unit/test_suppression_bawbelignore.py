from scanner.suppression.bawbelignore import check_bawbelignore, matches_pattern


def test_matches_pattern_exact_match():
    assert matches_pattern("docs/guide.md", "docs/guide.md") is True


def test_matches_pattern_glob_wildcard():
    assert matches_pattern("docs/guide.md", "docs/**") is True


def test_matches_pattern_no_match():
    assert matches_pattern("scanner/core/dedup.py", "docs/**") is False


def test_matches_pattern_basename_match():
    assert matches_pattern("some/path/skill.md", "skill.md") is True


def test_matches_pattern_directory_prefix():
    assert matches_pattern("tests/fixtures/bad.md", "tests/") is True


def test_check_bawbelignore_returns_false_when_no_ignore_file(tmp_path):
    skill = tmp_path / "skill.md"
    skill.write_text("content")
    assert check_bawbelignore(skill) is False


def test_check_bawbelignore_returns_true_when_path_matches(tmp_path):
    ignore = tmp_path / ".bawbelignore"
    ignore.write_text("tests/fixtures/**\n")
    skill = tmp_path / "tests" / "fixtures" / "bad.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("content")
    assert check_bawbelignore(skill) is True


def test_check_bawbelignore_returns_false_when_path_does_not_match(tmp_path):
    ignore = tmp_path / ".bawbelignore"
    ignore.write_text("tests/fixtures/**\n")
    skill = tmp_path / "scanner" / "core" / "dedup.py"
    skill.parent.mkdir(parents=True)
    skill.write_text("content")
    assert check_bawbelignore(skill) is False


def test_check_bawbelignore_ignores_comments_in_ignore_file(tmp_path):
    ignore = tmp_path / ".bawbelignore"
    ignore.write_text("# this is a comment\n\ntests/**\n")
    skill = tmp_path / "tests" / "skill.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("content")
    assert check_bawbelignore(skill) is True
