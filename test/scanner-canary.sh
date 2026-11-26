#!/usr/bin/env bash
# scanner-canary -- a secret scanner's clean result only counts if it flags a planted canary first.
# The canary is built at run time in a throwaway clone of the tree, so this file holds no live hit, and a
# committed allowlist or scanner config that blinds the real scan blinds this one too.
# Each scanner must exit with its own findings code, so a crash can't read as a finding.
# usage: test/scanner-canary.sh <gitleaks> <trufflehog> [repo]     exit: 0 both flagged it, 1 one missed it, 2 VOID
set -uo pipefail
[ $# -ge 2 ] || { echo "usage: scanner-canary.sh <gitleaks> <trufflehog> [repo]" >&2; exit 2; }
gl=$1; th=$2
command -v openssl >/dev/null || { echo "canary: VOID, no openssl" >&2; exit 2; }
for b in "$gl" "$th"; do [ -x "$b" ] || { echo "canary: VOID, scanner absent: $b" >&2; exit 2; }; done
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT
git clone -q "${3:-.}" "$T/c" || { echo "canary: VOID, can't copy the tree" >&2; exit 2; }
# A private key is flagged by both scanners without any network check.
{ printf '%s\n' "-----BEGIN RSA ""PRIVATE KEY-----"; openssl genrsa -traditional 2048 2>/dev/null | sed '1d;$d'; printf '%s\n' "-----END RSA ""PRIVATE KEY-----"; } > "$T/c/deploy.key"
printf 'aws_access_key_id = %s%s\naws_secret_access_key = %s\n' AKIA "$(head -c 400 /dev/urandom | tr -dc 'A-Z2-7' | head -c 16)" "$(head -c 800 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 40)" > "$T/c/settings.ini"
# Forced, because the tree's own .gitignore denies by default.
git -C "$T/c" add -f deploy.key settings.ini || { echo "canary: VOID, can't stage it" >&2; exit 2; }
git -C "$T/c" -c user.email=c@example.invalid -c user.name=c -c commit.gpgsign=false commit -qm canary || { echo "canary: VOID, can't commit it" >&2; exit 2; }
rc=0
"$gl" git --no-banner --redact --exit-code 99 "$T/c" >/dev/null 2>&1; r=$?
if [ "$r" = 99 ]; then echo "canary: gitleaks flagged it"; else echo "canary: gitleaks rc=$r, want 99"; rc=1; fi
"$th" git "file://$T/c" --no-verification --fail --no-update >/dev/null 2>&1; r=$?
if [ "$r" = 183 ]; then echo "canary: trufflehog flagged it"; else echo "canary: trufflehog rc=$r, want 183"; rc=1; fi
exit $rc
