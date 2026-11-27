#!/bin/sh
# plant-hooks.sh <repo> <marker-dir> -- what a worker with a writable .git could
# plant: every hook git knows, in the default directory and in a relative
# hooksPath, and config-driven commands (an fsmonitor, a credential helper, a
# required filter, a diff driver). Each appends to <marker-dir>/HOOK-RAN or
# CFG-RAN wherever it runs. The paths are absolute, so a plant fires on the
# host only when git runs in that repository on the host.
# Git reads ';' and '#' in a config value as a comment: one statement per value.
set -eu
repo=$1
marks=$2
mkdir -p "$marks" "$repo/.git/hooks" "$repo/.githooks"
for h in pre-commit commit-msg post-commit post-checkout post-merge pre-merge-commit \
         post-index-change reference-transaction pre-auto-gc post-rewrite \
         prepare-commit-msg pre-rebase sendpack-validate fsmonitor-watchman \
         push-to-checkout post-fetch; do
  for d in "$repo/.git/hooks" "$repo/.githooks"; do
    echo '#!/bin/sh' > "$d/$h"
    printf "printf '%%s\\\\n' \"\$0\" >> \"%s/HOOK-RAN\" 2>/dev/null\n" "$marks" >> "$d/$h"
    chmod +x "$d/$h"
  done
done
cat >> "$repo/.git/config" <<EOF
[core]
	hooksPath = .githooks
	fsmonitor = sh -c 'echo fsmonitor >> "$marks/CFG-RAN"'
[credential]
	helper = !sh -c 'echo credential >> "$marks/CFG-RAN"'
[filter "evil"]
	clean = sh -c 'echo filter-clean >> "$marks/CFG-RAN"'
	smudge = sh -c 'echo filter-smuggle >> "$marks/CFG-RAN"'
	required = true
[diff "evil"]
	command = sh -c 'echo diff >> "$marks/CFG-RAN"'
EOF
printf '* filter=evil diff=evil\n' >> "$repo/.gitattributes"
