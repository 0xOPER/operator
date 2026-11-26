#!/usr/bin/env bash
# The plan template's own pair, as the ratchet's 5th-column test: the lint
# holds on the shipped plan, and the forge catches its planted hollow.
set -uo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
python3 -I "$ROOT/profiles/templates/plan/checks/goals_lint.py" \
  "$ROOT/profiles/templates/plan/plan.md" || exit 1
python3 -I "$ROOT/profiles/templates/plan/checks/goals_forge.py" \
  "$ROOT/profiles/templates/plan/plan.md" --plant-forge || exit 1
echo "plan-template: OK (lint holds, forge caught)"

# bypass shapes refuse: an always-true tail, a trivial head, bare literals
B=$(mktemp -d)
printf '# P\n\n## g\n\ndesc: x\ncheck: `test -f src/x.py || true`\n' > "$B/plan.md"
if python3 -I "$ROOT/profiles/templates/plan/checks/goals_lint.py" \
     "$B/plan.md" 2>/dev/null; then
  echo "plan-bypass: the short-circuit passed"; rm -rf "$B"; exit 1
fi
printf '# P\n\n## g\n\ndesc: x\ncheck: `test -n "x"`\n' > "$B/plan.md"
if python3 -I "$ROOT/profiles/templates/plan/checks/goals_lint.py" \
     "$B/plan.md" 2>/dev/null; then
  echo "plan-bypass: the bare literal passed"; rm -rf "$B"; exit 1
fi
# a check that IS a trivial word (`true`) is a goal that cannot fail
printf '# P\n\n## g\n\ndesc: x\ncheck: `true`\n' > "$B/plan.md"
if python3 -I "$ROOT/profiles/templates/plan/checks/goals_lint.py" \
     "$B/plan.md" 2>/dev/null; then
  echo "plan-bypass: the trivial check passed"; rm -rf "$B"; exit 1
fi
# a trivial HEAD short-circuits too (`true || ...` can never fail), a shape
# the always-true TAIL regex never sees
printf '# P\n\n## g\n\ndesc: x\ncheck: `true || test -f src/x.py`\n' > "$B/plan.md"
if python3 -I "$ROOT/profiles/templates/plan/checks/goals_lint.py" \
     "$B/plan.md" 2>/dev/null; then
  echo "plan-bypass: the trivial head passed"; rm -rf "$B"; exit 1
fi
rm -rf "$B"
echo "plan-bypass: OK (short-circuit, bare literals, trivial checks and heads refuse)"
