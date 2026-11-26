#!/usr/bin/env bash
# The hollow battery, as the ratchet's 5th-column test: recipes red with the
# pin, all green without it (the vacuous proof), honest green both ways.
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
export ROOT
python3 -I "$ROOT/test/forge/hollow.py" all 2>&1 | tail -1 \
  | grep -q "hollow: OK" || exit 1
echo "hollow-battery: OK (recipes bite)"
