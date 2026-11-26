#!/usr/bin/env bash
# setup-hooks.sh -- install tracked .githooks/ (pre-commit, commit-msg, pre-push)
# into this clone via git config core.hooksPath .githooks.
#
# usage:
#   scripts/setup-hooks.sh [--configure-identity]
#   scripts/setup-hooks.sh --selftest
# exit: 0 installed / selftest OK, 1 a check or hook failed, 2 VOID
set -uo pipefail
LC_ALL=C
export LC_ALL
exec </dev/null

ROOT=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd)
WANT_NAME="OPERATOR project"
WANT_EMAIL="351411109+0xOPER@users.noreply.github.com"
WANT_ID="$WANT_NAME <$WANT_EMAIL>"

selftest() {
  local T rc=0 out r sample
  unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
  T=$(mktemp -d) || exit 2
  trap 'rm -rf "${T:?}"' EXIT

  git init -q --bare "$T/remote.git" || exit 2
  git init -q -b main "$T/work" || exit 2

  mkdir -p "$T/work/.githooks" "$T/work/scripts" "$T/work/test/lint"
  for h in pre-commit commit-msg pre-push; do
    cp "$ROOT/.githooks/$h" "$T/work/.githooks/$h" || exit 2
    chmod +x "$T/work/.githooks/$h" || exit 2
  done
  cp "$ROOT/scripts/setup-hooks.sh" "$T/work/scripts/setup-hooks.sh" || exit 2
  chmod +x "$T/work/scripts/setup-hooks.sh" || exit 2
  cp "$ROOT/scripts/release-lint.py" "$T/work/scripts/release-lint.py" || exit 2
  chmod +x "$T/work/scripts/release-lint.py" || exit 2
  cp "$ROOT/test/lint/tier-a.tsv" "$T/work/test/lint/tier-a.tsv" || exit 2
  printf '.githooks/commit-msg\n.githooks/pre-commit\n.githooks/pre-push\nkeep-list\nscripts/release-lint.py\nscripts/setup-hooks.sh\ntest/lint/tier-a.tsv\n' | LC_ALL=C sort -u > "$T/work/keep-list"

  git -C "$T/work" remote add origin "$T/remote.git"
  git -C "$T/work" config user.name "Wrong User"
  git -C "$T/work" config user.email "wrong@example.com"
  git -C "$T/work" config commit.gpgsign false
  git -C "$T/work" add -A
  # Seed base commit before hooks are installed
  GIT_AUTHOR_NAME="$WANT_NAME" GIT_AUTHOR_EMAIL="$WANT_EMAIL" \
  GIT_COMMITTER_NAME="$WANT_NAME" GIT_COMMITTER_EMAIL="$WANT_EMAIL" \
  git -C "$T/work" -c commit.gpgsign=false commit -qm "seed base" || exit 2

  # Install hooks via setup-hooks.sh
  out=$(OPERATOR_TIER_B=/nonexistent "$T/work/scripts/setup-hooks.sh" 2>&1); r=$?
  hp=$(git -C "$T/work" config --get core.hooksPath || true)
  { [ "$r" -eq 0 ] && [ "$hp" = ".githooks" ]; } || { echo "FAIL install: rc=$r hp=$hp $out" >&2; rc=1; }

  wgit() {
    OPERATOR_TIER_B=/nonexistent git -C "$T/work" "$@"
  }

  # 1. Wrong identity refused (names fix), then accepted after --configure-identity
  printf 'ok\n' > "$T/work/note.txt"
  printf 'note.txt\n' >> "$T/work/keep-list"
  LC_ALL=C sort -u -o "$T/work/keep-list" "$T/work/keep-list"
  wgit add note.txt keep-list
  out=$(wgit commit -m "try wrong identity" 2>&1); r=$?
  { [ "$r" -ne 0 ] && printf '%s' "$out" | grep -q -- '--configure-identity'; } || {
    echo "FAIL 1a wrong identity not refused with fix: rc=$r $out" >&2; rc=1
  }
  out=$("$T/work/scripts/setup-hooks.sh" --configure-identity 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 1b --configure-identity: rc=$r $out" >&2; rc=1; }
  out=$(wgit commit -m "add note with valid identity" 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 1c valid identity commit failed: rc=$r $out" >&2; rc=1; }

  # 2. File missing from keep-list refused, then accepted once listed
  printf 'unlisted\n' > "$T/work/unlisted.txt"
  wgit add unlisted.txt
  out=$(wgit commit -m "unlisted file" 2>&1); r=$?
  { [ "$r" -ne 0 ] && printf '%s' "$out" | grep -q 'keep-list'; } || {
    echo "FAIL 2a unlisted file not refused: rc=$r $out" >&2; rc=1
  }
  printf 'unlisted.txt\n' >> "$T/work/keep-list"
  LC_ALL=C sort -u -o "$T/work/keep-list" "$T/work/keep-list"
  wgit add keep-list
  out=$(wgit commit -m "listed file" 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 2b listed file commit failed: rc=$r $out" >&2; rc=1; }

  # 3. Symlink refused, then accepted when replaced with regular file
  ln -s note.txt "$T/work/badlink"
  printf 'badlink\n' >> "$T/work/keep-list"
  LC_ALL=C sort -u -o "$T/work/keep-list" "$T/work/keep-list"
  wgit add badlink keep-list
  out=$(wgit commit -m "add symlink" 2>&1); r=$?
  { [ "$r" -ne 0 ] && printf '%s' "$out" | grep -q 'symlink'; } || {
    echo "FAIL 3a symlink not refused: rc=$r $out" >&2; rc=1
  }
  wgit rm -q --cached badlink
  rm -f "$T/work/badlink"
  printf 'regular\n' > "$T/work/badlink"
  wgit add badlink keep-list
  out=$(wgit commit -m "replace symlink with regular file" 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 3b regular file replacement failed: rc=$r $out" >&2; rc=1; }

  # 4. Co-authored-by trailer refused by commit-msg, then accepted without trailer
  printf 'v2\n' > "$T/work/note.txt"
  wgit add note.txt
  out=$(wgit commit -m "$(printf 'update note\n\nCo-authored-by: Helper <h@example.com>')" 2>&1); r=$?
  { [ "$r" -ne 0 ] && printf '%s' "$out" | grep -qi 'co-authored-by'; } || {
    echo "FAIL 4a Co-authored-by trailer not refused: rc=$r $out" >&2; rc=1
  }
  out=$(wgit commit -m "update note cleanly" 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 4b clean commit message failed: rc=$r $out" >&2; rc=1; }

  # 5. Tier-A hit refused by pre-commit, then accepted once scrubbed
  sample=$(python3 -I -c 'import sys; print(sys.argv[1][::-1])' 'moc.buhtig.ylperon.sresu@ecila')
  printf 'contact %s\n' "$sample" > "$T/work/note.txt"
  wgit add note.txt
  out=$(wgit commit -m "plant tier-a hit" 2>&1); r=$?
  { [ "$r" -ne 0 ] && printf '%s' "$out" | grep -q 'release-lint'; } || {
    echo "FAIL 5a tier-A hit not refused: rc=$r $out" >&2; rc=1
  }
  printf 'clean text\n' > "$T/work/note.txt"
  wgit add note.txt
  out=$(wgit commit -m "scrub tier-a hit" 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 5b scrubbed commit failed: rc=$r $out" >&2; rc=1; }

  # 6. Malformed SVG and broken Python/shell syntax refused, then accepted
  printf '<svg xmlns="http://www.w3.org/2000/svg"><g></svg>\n' > "$T/work/icon.svg"
  printf 'def broken(:\n' > "$T/work/mod.py"
  printf '#!/bin/sh\nif then\n' > "$T/work/sub.sh"
  printf 'icon.svg\nmod.py\nsub.sh\n' >> "$T/work/keep-list"
  LC_ALL=C sort -u -o "$T/work/keep-list" "$T/work/keep-list"
  wgit add icon.svg mod.py sub.sh keep-list
  out=$(wgit commit -m "broken syntax" 2>&1); r=$?
  [ "$r" -ne 0 ] || { echo "FAIL 6a broken syntax/SVG not refused" >&2; rc=1; }
  printf '#!/bin/sh\nexit 0\n' > "$T/work/sub.sh"
  wgit add sub.sh
  out=$(wgit commit -m "still broken py and svg" 2>&1); r=$?
  [ "$r" -ne 0 ] || { echo "FAIL 6b broken py not refused" >&2; rc=1; }
  printf 'x = 1\n' > "$T/work/mod.py"
  wgit add mod.py
  out=$(wgit commit -m "still broken svg" 2>&1); r=$?
  { [ "$r" -ne 0 ] && printf '%s' "$out" | grep -q 'SVG'; } || {
    echo "FAIL 6c malformed SVG not refused: rc=$r $out" >&2; rc=1
  }
  printf '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>\n' > "$T/work/icon.svg"
  wgit add icon.svg
  out=$(SETUP_HOOKS_STRICT_PATH=1 PATH="/usr/bin:/bin" OPERATOR_TIER_B=/nonexistent git -C "$T/work" commit -m "valid sh py svg" 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 6d valid syntax/SVG commit failed: rc=$r $out" >&2; rc=1; }

  # 7. pre-push: clean push succeeds; --no-verify bad commit is caught by pre-push, then fixed
  out=$(wgit push -q origin main 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 7a initial clean push failed: rc=$r $out" >&2; rc=1; }

  printf 'leak %s\n' "$sample" > "$T/work/note.txt"
  wgit add note.txt
  wgit commit --no-verify -qm "bypassed pre-commit leak"
  out=$(wgit push origin main 2>&1); r=$?
  { [ "$r" -ne 0 ] && printf '%s' "$out" | grep -q 'pre-push: REFUSED'; } || {
    echo "FAIL 7b pre-push did not block --no-verify leak: rc=$r $out" >&2; rc=1
  }
  wgit reset -q --hard HEAD~1
  printf 'clean after reset\n' > "$T/work/note.txt"
  wgit add note.txt
  wgit commit -qm "clean pushable commit"
  out=$(wgit push -q origin main 2>&1); r=$?
  [ "$r" -eq 0 ] || { echo "FAIL 7c clean push after reset failed: rc=$r $out" >&2; rc=1; }

  if [ "$rc" -eq 0 ]; then
    echo "selftest: OK (install, identity, keep-list, symlink, commit-msg, tier-a, syntax-svg, pre-push)"
  else
    echo "selftest: FAIL" >&2
  fi
  exit "$rc"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
fi

cfg_id=0
for arg in "$@"; do
  case "$arg" in
    --configure-identity) cfg_id=1 ;;
    -h|--help)
      sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "setup-hooks: unknown argument '$arg' (usage: scripts/setup-hooks.sh [--configure-identity | --selftest])" >&2
      exit 2
      ;;
  esac
done

if [ ! -e "$ROOT/.git" ]; then
  echo "setup-hooks: VOID, $ROOT has no .git directory" >&2
  exit 2
fi

for h in pre-commit commit-msg pre-push; do
  if [ ! -f "$ROOT/.githooks/$h" ]; then
    echo "setup-hooks: VOID, missing $ROOT/.githooks/$h" >&2
    exit 2
  fi
  chmod +x "$ROOT/.githooks/$h"
done

git -C "$ROOT" config core.hooksPath .githooks || exit 2

# Remove any legacy untracked .git/hooks/pre-push now folded into tracked .githooks/pre-push
git_dir=$(git -C "$ROOT" rev-parse --git-dir 2>/dev/null || echo "$ROOT/.git")
case "$git_dir" in
  /*) ;;
  *) git_dir="$ROOT/$git_dir" ;;
esac
if [ -f "$git_dir/hooks/pre-push" ]; then
  rm -f "$git_dir/hooks/pre-push"
fi

if [ "$cfg_id" -eq 1 ]; then
  git -C "$ROOT" config user.name "$WANT_NAME"
  git -C "$ROOT" config user.email "$WANT_EMAIL"
  git -C "$ROOT" config commit.gpgsign false
  git -C "$ROOT" config tag.gpgSign false
fi

cur_name=$(git -C "$ROOT" config --get user.name 2>/dev/null || true)
cur_email=$(git -C "$ROOT" config --get user.email 2>/dev/null || true)
echo "setup-hooks: core.hooksPath=.githooks (pre-commit, commit-msg, pre-push active)"
if [ "$cur_name <$cur_email>" != "$WANT_ID" ]; then
  echo "setup-hooks: note: repo identity is '$cur_name <$cur_email>'; run 'scripts/setup-hooks.sh --configure-identity' to set '$WANT_ID'"
fi
exit 0
