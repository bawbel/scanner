# Publishing to PyPI

---

## Prerequisites

```bash
pip install build twine
```

Verify you have a PyPI account and the `bawbel-scanner` package is registered to your account.

---

## Version bump

Edit `scanner/__init__.py`:

```python
__version__ = "1.2.0"   # bump this
```

Edit `pyproject.toml`:

```toml
[project]
version = "1.2.0"        # must match __init__.py
```

---

## Build

```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info/

# Build source distribution and wheel
python -m build
```

Output:
```
dist/
  bawbel_scanner-1.2.0-py3-none-any.whl
  bawbel_scanner-1.2.0.tar.gz
```

---

## Test on TestPyPI first

```bash
# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Install from TestPyPI and verify
pip install --index-url https://test.pypi.org/simple/ bawbel-scanner==1.2.0
bawbel version
```

---

## Publish to PyPI

```bash
twine upload dist/*
```

Enter your PyPI credentials (or use an API token).

---

## Verify

```bash
pip install bawbel-scanner==1.2.0
bawbel version
# Should show: Bawbel Scanner v1.2.0
```

---

## GitHub Actions - automated publish

The `publish.yml` workflow publishes automatically on a version tag:

```bash
git tag v1.2.0
git push origin v1.2.0
```

This triggers `.github/workflows/publish.yml` which builds and uploads to PyPI
using the `PYPI_API_TOKEN` secret.

---

## Post-publish checklist

- [ ] Tag the release: `git tag v1.2.0 && git push origin v1.2.0`
- [ ] Create a GitHub release with changelog notes
- [ ] Update `CHANGELOG.md`
- [ ] Verify PyPI page renders correctly
- [ ] Verify `pip install bawbel-scanner` installs the new version
- [ ] Run `bawbel version` to confirm
