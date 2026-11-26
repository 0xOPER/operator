#!/usr/bin/env bash
# Runs the full sealed probe battery (invisible, hostile-bind, void-missing, void-symlink, honest).
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
export ROOT
python3 -I "$ROOT/test/forge/sealed.py" all 2>&1 \
  | tail -1 | grep -q "sealed: OK" || exit 1
echo "sealed-probe: OK (all probes)"
