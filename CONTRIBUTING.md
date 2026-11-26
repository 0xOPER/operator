# Contributing to OPERATOR

Thanks for your interest in contributing to OPERATOR. Every pull request runs through the same deterministic verification suite that OPERATOR uses to keep itself honest.

## Prerequisites

- **Linux (native, recommended):** Python 3.11+, `python3-venv`, `git`, `openssh-client` (`ssh-keygen`), `bubblewrap` (`bwrap`), `pytest`, and `pipx` (required by `test/ratchet.sh` and `zizmor`).
  - On Ubuntu 24.04+, allow unprivileged user namespaces for `bubblewrap` via a targeted AppArmor profile (preferred) or temporary `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (system-wide, resets on reboot); see [docs/quickstart.md](docs/quickstart.md).
- **macOS:** Use a Linux VM (Colima, OrbStack, or Docker Desktop) with `scripts/docker-operator.sh` or run tests inside your Ubuntu VM.

## Quick Verification Loop

Before opening a pull request, run the local verification checks:

```bash
# 1. 60-second offline demo (no API keys required)
bin/operator.sh demo run

# 2. Full cleanroom selftest battery (home hidden, no network, read-only tree)
test/cleanroom.sh scripts/run-all-selftests.sh

# 3. Release hygiene & static analysis ratchets
scripts/release-lint.py
scripts/release-lint.py --selftest
test/ratchet.sh

# 4. Mutation ratchet (verifies breaking any guard causes its selftest to fail)
test/cleanroom.sh test/neuter.py
```

If you modify a specific module (for example `bin/contract.py`), you can run its selftest directly while iterating:

```bash
bin/contract.py --selftest
```

## Repository Rules (Enforced by CI)

CI enforces a small set of strict invariants so the repository stays auditable and leak-free:

1. **`keep-list` & `.gitignore` default-deny:** Every tracked file must appear in `keep-list` (sorted with `LC_ALL=C sort`), and symlinks are disallowed. `.gitignore` uses default-deny (`/*`), so any new top-level file or directory must also be un-ignored in `.gitignore`.
2. **Text-only repository:** `scripts/release-lint.py` rejects binary files (PNG, PDF, archives, etc.), credential-shaped filenames, personal home paths, and accidental private URLs. Vector graphics should be plain UTF-8 `.svg` files.
3. **Commit identity & attribution law:** CI checks every commit on `main` and every pull request:
   - Commits must carry **no** `Co-authored-by:` trailer (from any author) and no AI/tool attribution lines.
   - Commits on `main` must be unsigned (`commit.gpgsign=false`) and authored/committed under the project identity (`OPERATOR project <351411109+0xOPER@users.noreply.github.com>`).
   - **How external pull requests land:** External contributors open normal PRs from their fork (without `Co-authored-by:` trailers). Once approved and green, maintainers squash-merge the change onto `main` under the project identity and credit the contributor in the release notes.
4. **Zero-regression lint ratchets:** `test/ratchet.sh` runs pinned `shellcheck` and `ruff` versions via `pipx` against `test/ratchet.tsv`. Counts may only stay flat or move down (if you fix an existing warning, lower the baseline in `test/ratchet.tsv` in the same PR).
5. **Mutation sensitivity & CI suites:** Every `--selftest` tool in `bin/` and `scripts/` must be covered by `test/neuters.py` (`0` allowed survivors against reduced selftests). CI also runs secret scanners (`gitleaks`, `trufflehog`), `zizmor`, CodeQL, OpenSSF Scorecard, and jailed CLI conformance cells (`claude-code`, `codex`, `opencode`).
6. **Workflow security:** All GitHub Actions workflows in `.github/workflows/` must pin actions by full 40-character commit SHA, declare minimal `permissions:`, set `persist-credentials: false`, and pass `zizmor --offline .github/workflows`.
7. **`CLAIMS.md` anchor:** Do not edit `CLAIMS.md` in regular PRs; its SHA-256 hash is anchored in Sigstore Rekor (`claims-rekor.json`) and verified offline by `scripts/verify-rekor.py --selftest`.

## Pull Request Process

1. Fork `0xOPER/operator` and create a focused branch from `main`.
2. Keep changes scoped, omit `Co-authored-by:` trailers, and include selftest coverage for new behavior or bug fixes.
3. Update `keep-list` (and `.gitignore` for new top-level entries) if you added or removed any files.
4. Open a PR using the repository template and wait for all CI, CodeQL, scanner, and conformance checks to pass. Maintainers will squash-merge accepted PRs under the project identity with credit in the release notes.
