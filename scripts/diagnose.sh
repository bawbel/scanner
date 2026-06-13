#!/usr/bin/env bash
# Bawbel Scanner - Crash Diagnostics
# Run this when bawbel scan crashes immediately after the banner.
# Paste the full output here and share it.

set -euo pipefail

echo "=== Bawbel Scanner Diagnostics ==="
echo ""

echo "--- Python and package versions ---"
python3 --version
pip show bawbel-scanner 2>/dev/null | grep -E "^(Name|Version|Location)"
echo ""

echo "--- Full traceback from bawbel scan ---"
# Create a minimal fixture and run with full traceback
python3 -c "
import sys, traceback
try:
    from scanner import scan
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write('You are a helpful assistant.\n')
        path = f.name
    result = scan(path)
    print(f'SCAN OK: findings={len(result.findings)} clean={result.is_clean}')
except Exception as e:
    print(f'CRASH: {type(e).__name__}: {e}')
    traceback.print_exc()
"
echo ""

echo "--- Finding dataclass fields ---"
python3 -c "
import dataclasses
from scanner.models.finding import Finding
fields = [(f.name, f.type) for f in dataclasses.fields(Finding)]
for name, typ in fields:
    print(f'  {name}: {typ}')
"
echo ""

echo "--- Check aivss_score vs cvss_ai ---"
python3 -c "
from scanner.models.finding import Finding
import dataclasses
names = [f.name for f in dataclasses.fields(Finding)]
print('has aivss_score:', 'aivss_score' in names)
print('has cvss_ai:    ', 'cvss_ai' in names)
print('has owasp_mcp:  ', 'owasp_mcp' in names)
print('has piranha_url:', 'piranha_url' in names)
"
echo ""

echo "--- Check pattern engine rule dict keys ---"
python3 -c "
from scanner.engines.pattern_engine import PATTERN_RULES
r = PATTERN_RULES[0]
print('Rule dict keys:', sorted(r.keys()))
print('Has aivss_score:', 'aivss_score' in r)
print('Has cvss_ai:    ', 'cvss_ai' in r)
"
echo ""

echo "--- Check _make_finding signature ---"
python3 -c "
import inspect
from scanner.scanner import _make_finding
sig = inspect.signature(_make_finding)
for name, param in sig.parameters.items():
    print(f'  {name}: default={param.default}')
"
echo ""

echo "--- Check result.risk_score property ---"
python3 -c "
import inspect
from scanner.models.result import ScanResult
src = inspect.getsource(ScanResult.risk_score.fget)
print(src[:300])
"
echo ""

echo "--- display.py banner line ---"
python3 -c "
import inspect
from scanner.cli.shared.display import print_banner
src = inspect.getsource(print_banner)
print(src)
"
echo ""

echo "--- watchdog version ---"
python3 -c "
import watchdog
# watchdog doesn't always expose __version__ at top level
try:
    from watchdog import __version__
    print(__version__)
except ImportError:
    import importlib.metadata
    print(importlib.metadata.version('watchdog'))
" 2>/dev/null || echo "watchdog not installed or no version attribute"
echo ""

echo "=== End Diagnostics ==="
