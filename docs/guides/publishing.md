# Publishing to PyPI

## Overview

Publishing happens in three steps:

```
1. Test locally       → build + install from wheel
2. Test on TestPyPI   → pip install from test.pypi.org
3. Publish to PyPI    → create GitHub Release → auto-publishes
```

After step 3, anyone can run `pip install bawbel-scanner`.

---

## One-time Setup (do this once)

### 1. Create PyPI accounts

- **PyPI:** https://pypi.org/account/register/
- **TestPyPI:** https://test.pypi.org/account/register/

Use the same email as your GitHub account.

### 2. Enable OIDC Trusted Publishing (no API keys needed)

PyPI supports publishing directly from GitHub Actions via OIDC — no secrets to manage.

**On PyPI:**
1. Go to https://pypi.org/manage/account/publishing/
2. Click "Add a new pending publisher"
3. Fill in:
   - PyPI project name: `bawbel-scanner`
   - GitHub owner: `bawbel`
   - Repository: `bawbel-scanner`
   - Workflow: `publish.yml`
   - Environment: `pypi`

**On TestPyPI:**
1. Go to https://test.pypi.org/manage/account/publishing/
2. Same as above, but Environment: `testpypi`

### 3. Create GitHub environments

In your GitHub repo → Settings → Environments:

Create **`pypi`** environment:
- Add protection rule: "Required reviewers" → add yourself
- This prevents accidental publishes

Create **`testpypi`** environment:
- No protection rules needed

---

## Before Every Release

Run the full checklist:

```bash
source .venv/bin/activate

# 1. Tests must be 100%
python -m pytest tests/ -v
# Expected: 125 passed

# 2. Bandit must be clean
bandit -r scanner/ -f screen
# Expected: 0 issues

# 3. Dependencies must have no CVEs
pip-audit -r requirements.txt
# Expected: No known vulnerabilities

# 4. Golden fixture must pass
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
# Expected: 2 findings, CRITICAL 9.4

# 5. Build must succeed
python -m build
twine check dist/*
# Expected: PASSED for both wheel and sdist
```

---

## Step 1 — Test Locally

```bash
# Build
python -m build

# Install from wheel into a fresh temp venv
python -m venv /tmp/test-install
/tmp/test-install/bin/pip install dist/bawbel_scanner-*.whl
/tmp/test-install/bin/bawbel scan tests/fixtures/skills/malicious/malicious_skill.md

# Expected: same output as running locally
# Clean up
rm -rf /tmp/test-install
```

---

## Step 2 — Test on TestPyPI

Trigger the workflow manually:

1. Go to GitHub → Actions → "Publish to PyPI"
2. Click "Run workflow"
3. Select `testpypi`
4. Click "Run workflow"

Once it completes:

```bash
# Install from TestPyPI (use --index-url to point to test registry)
pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  bawbel-scanner

# Verify it works
bawbel --version
bawbel scan --help
```

---

## Step 3 — Publish to PyPI (GitHub Release)

1. **Bump the version** in two places:
   ```bash
   # pyproject.toml
   version = "0.1.1"

   # scanner/__init__.py
   __version__ = "0.1.1"
   ```

2. **Update CHANGELOG.md** — add the new version section

3. **Commit and push** to `main`:
   ```bash
   git add pyproject.toml scanner/__init__.py CHANGELOG.md
   git commit -m "chore: bump version to 0.1.1"
   git push origin main
   ```

4. **Create a GitHub Release:**
   - Go to github.com/bawbel/bawbel-scanner → Releases → "Draft a new release"
   - Tag: `v0.1.1`
   - Title: `v0.1.1 — [brief description]`
   - Body: paste from CHANGELOG.md
   - Click "Publish release"

5. **The publish workflow runs automatically** — takes ~2 minutes.

6. **Verify on PyPI:**
   ```bash
   pip install bawbel-scanner==0.1.1
   bawbel --version
   ```

---

## Version Numbering

Follow semantic versioning: `MAJOR.MINOR.PATCH`

| Change | Version bump | Example |
|---|---|---|
| New detection rule | PATCH | 0.1.0 → 0.1.1 |
| New engine, new CLI flag | MINOR | 0.1.0 → 0.2.0 |
| Rename `scan()`, change `Finding` fields | MAJOR | 0.1.0 → 1.0.0 |

**Never reuse a version number.** Once published, it is permanent.

---

## If Something Goes Wrong

### Workflow fails at "Publish"

Check the Actions log. Common causes:
- Version already exists on PyPI — bump the version
- OIDC not configured — re-check the trusted publisher setup
- `twine check` failed — fix the distribution issue

### Wrong files in the wheel

```bash
# Inspect wheel contents
python -c "
import zipfile
with zipfile.ZipFile('dist/bawbel_scanner-X.Y.Z-py3-none-any.whl') as z:
    for f in sorted(z.namelist()): print(f)
"
```

Check `pyproject.toml` → `[tool.setuptools.package-data]` and `MANIFEST.in`.

### Accidentally published broken code

PyPI does not allow deleting releases (only yanking). Yank it:
1. Go to pypi.org → your project → manage → releases
2. Click "Yank" on the broken release
3. Fix the issue, publish a new PATCH version

---

## Quick Reference

```bash
# Build
python -m build

# Check
twine check dist/*

# Upload to TestPyPI manually
twine upload --repository testpypi dist/*

# Upload to PyPI manually (use GitHub Release instead)
twine upload dist/*
```
