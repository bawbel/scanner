Closes #

<!-- Every PR closes an issue. Open the issue first (CONTRIBUTING.md). Use Refs # when this is one of several PRs against the same issue. -->

## What and why

## Output contract impact

<!-- Finding and ScanResult fields, and the JSON and SARIF output. Additive only (CONTRIBUTING.md). -->

Fields added:
Fields renamed: none
Fields removed: none

## Checks

- [ ] Golden fixture unchanged: bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
- [ ] Tests pass: python -m pytest tests/ -v
- [ ] No em dashes
- [ ] pre-commit run --all-files clean
