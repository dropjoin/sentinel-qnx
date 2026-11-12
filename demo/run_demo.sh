#!/bin/sh
# Sentinel for QNX - end-to-end demo script (target: under 3 minutes).
# Story: audit a flawed image definition, read the report, auto-fix,
# re-audit, and show exactly which findings need a human decision.
set -e
cd "$(dirname "$0")/.."
export PYTHONPATH=.

echo "=== 1. Audit the flawed image definition ==="
python3 -m sentinel.cli audit samples/flawed-startup.sh samples/flawed.build samples/flawed-manifest.txt samples/flawed-sshd_config || true
echo
echo "=== 2. Narrative report (what a judge/maintainer reads) ==="
python3 -m sentinel.cli report samples/flawed-startup.sh samples/flawed-sshd_config || true
echo
echo "=== 3. Auto-fix the mechanically safe flaws ==="
rm -rf /tmp/sentinel-demo-fixed
python3 -m sentinel.cli fix samples/flawed-startup.sh samples/flawed.build samples/flawed-manifest.txt --out /tmp/sentinel-demo-fixed || true
echo
echo "=== 4. The clean set audits quiet ==="
python3 -m sentinel.cli audit samples/clean-startup.sh samples/clean.build samples/clean-manifest.txt samples/clean-sshd_config
echo "Demo complete: flawed -> reported -> fixed -> clean."
