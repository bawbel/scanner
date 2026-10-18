#!/usr/bin/env bash
# Self-scan: scan the agent-facing files this repository ships and fail on HIGH or above.
# The bawbel-self-scan pre-commit hook and the self-scan CI job both run this script.
#
# Not scanned, because they contain attack text on purpose: tests/fixtures/ (the golden
# fixture must stay out of .bawbelignore or its tests break), scanner/rules/ (detection
# rules), scripts/*.json (recorded scan data), docs/ and CHANGELOG.md (they describe attacks).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TARGETS=(
  CLAUDE.md
  README.md
  CONTRIBUTING.md
  SECURITY.md
  HOW-TO-USE.md
  ARCHITECTURE.md
  LANGUAGE.md
  PROJECT_STRUCTURE.md
  bawbel.yml
  server.json
  .github
)

status=0
for target in "${TARGETS[@]}"; do
  if [ ! -e "$target" ]; then
    echo "self-scan: missing target: $target" >&2
    status=1
    continue
  fi
  args=()
  if [ -d "$target" ]; then
    args+=(--recursive)
  fi
  # python3 -m scanner.cli runs this checkout's scanner, not an installed release.
  if ! python3 -m scanner.cli scan "$target" "${args[@]}" --fail-on-severity high --format text; then
    echo "self-scan: $target has a HIGH or CRITICAL finding, or the scan failed" >&2
    status=1
  fi
done
exit "$status"
