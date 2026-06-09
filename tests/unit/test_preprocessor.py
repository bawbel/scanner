from scanner.core.preprocessor import strip_code_fences


def test_strip_code_fences_removes_content_inside_backtick_fences():
    content = "before\n```python\nmalicious_code()\n```\nafter"
    result = strip_code_fences(content)
    assert "malicious_code" not in result


def test_strip_code_fences_preserves_line_count():
    content = "before\n```python\nmalicious_code()\n```\nafter"
    result = strip_code_fences(content)
    assert result.count("\n") == content.count("\n")


def test_strip_code_fences_preserves_fence_markers():
    content = "before\n```python\nmalicious_code()\n```\nafter"
    result = strip_code_fences(content)
    assert "```python" in result
    assert "```" in result


def test_strip_code_fences_returns_empty_string_unchanged():
    assert strip_code_fences("") == ""


def test_strip_code_fences_returns_unfenced_content_unchanged():
    content = "no fences here\njust regular text"
    assert strip_code_fences(content) == content


def test_strip_code_fences_handles_tilde_fences():
    content = "before\n~~~python\nmalicious_code()\n~~~\nafter"
    result = strip_code_fences(content)
    assert "malicious_code" not in result


def test_strip_code_fences_preserves_line_count_for_tilde_fences():
    content = "before\n~~~python\nmalicious_code()\n~~~\nafter"
    result = strip_code_fences(content)
    assert result.count("\n") == content.count("\n")
