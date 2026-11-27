# Changelog

All notable changes to OPERATOR are documented in this file.

## Unreleased (`main`)

### Fixes
- The push gate no longer hands its repository to what it runs. Git passes a hook its repository as `GIT_DIR`; inside a linked worktree that is an absolute path, and `scripts/release-lint.py --selftest` builds a scratch repository with `git init`, which re-initialised the pushed repository instead: the scratch commits landed on the branch being pushed and the repository was turned bare. It worked from a main clone only because `GIT_DIR=.git` is relative there. The gate now unsets the discovery variables after it changes to the tree, the lint's own git calls take an environment without them, the lint selftest proves its scratch repository is its own under a caller's `GIT_DIR`, and the hooks selftest pushes from a linked worktree. Rows `HK-prepush-gitdir` and `RL-scratch-hermetic`.
- `bin/review.py`: both selftest suites now report a failure (exit 1) when an arm crashes with VOID after an earlier arm already recorded a failure. A break that lets a forged verdict deliver moves the fixture out from under the arms after it; the suite used to exit 2 and forget the failure it had printed, which is why the ratchet reported four review rows as VOID. The truncated-pack arm also records a pack that got past the guard, whatever the unguarded path dies of afterwards.
- `test/neuter.py`: a row that does not die prints the last lines of the mutated test's output, so a VOID or a survivor can be told apart from an environment that broke the test.

### Documentation & Branding
- Rebuilt `assets/logo.svg` from exact measured geometry and `assets/banner.svg` at 880 px width with outlined Chakra Petch Bold (OFL) wordmark paths.
- Added an architectural comparison of common coding-agent orchestrator patterns and a clickable narrated overview video preview (`assets/video-preview.svg`) to `README.md`.
- Repaired `README.md` and `docs/quickstart.md` command sequences (passing the program directory positionally instead of `cd`ing into a directory without `bin/`), added the real-CLI and `[seat.op]` setup step, and aligned `ssh-keygen` passphrase usage.
- Aligned documentation wording with code and `LIMITATIONS` (`tamper-sealed`, bounded `[seat.op]` effect, call-log tail truncation boundary, `max_parallel = 1`, demo vs. first-level suite scope, and experimental `zcode` status).
- Completed `docs/authoring.md` (including `[seat.op]`, waivers, `budget.minutes`/`budget.context`, contract keys, and a valid `contract.toml` example), refreshed `INTERFACES.md`, and updated `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md`, and `docs/architecture.md`.
- Added Ubuntu 24.04 AppArmor `bwrap` profile instructions, macOS `--mount` Docker workflow, Real CLIs configuration guide (`spawn preflight`, `OPERATOR_ZAI_*`, `OPERATOR_TURN_*`, `OPERATOR_PAGER_COMMAND`), and `LICENSE` appendix notice.

### CI
- `Dockerfile`: the base image is pinned by digest (`ubuntu:24.04@sha256:562111b8...`), so the image CI builds is the one that was reviewed and not whatever the tag serves that day.
- `.github/workflows/ci.yml`, `.github/workflows/proofs.yml`: the CLIs the conformance and proof cells run are installed from a committed lockfile (`test/cli-pins/package-lock.json`: every tarball by its sha512, checked against the registry's own bytes) with `npm ci --ignore-scripts`, as the runner's user and not as root. The workflows used to name versions and trust whatever the registry served that day, as root, running whatever the packages called a postinstall. What those postinstalls do (stand the linux-x64 binary at the wrapper's bin) is done by link instead. `scripts/verify-ci-pins.py` refuses a tree where an npm command installs any other way, a lockfile entry has no hash or no registry URL, a dependency is not at an exact version, or a `FROM` has no digest.

## `v0.1.0` — 2026-11-26

Initial public release of OPERATOR under the Apache License 2.0.

- Linux `bubblewrap` confinement (`bin/lib/jail.py`, `bin/spawn.py`), host-side API credential brokering (`bin/broker.py`), and allowlisted egress proxy (`bin/egress-proxy.py`).
- Tamper-sealed contract verification (`bin/contract.py`) with pinned read-only test overlays, root runner-config restoration, `expect_base_fail` differential checks, twin `control` rows, and `pytest-guard` receipts.
- Signed SSH closure rulings (`bin/ruling.py`), cross-family review gate (`bin/review.py`), bounded unattended operator loop (`[seat.op]` in `bin/run.py`), and read-only loopback panel (`bin/panel.py`).
- Commercial CLI adapters for `claude-code`, `codex`, `opencode`, `zcode` (experimental), and offline `stub`.
- Cleanroom selftest battery, 461-row guard-mutation sensitivity ratchet, hollow-suite sabotage suite, CI CLI conformance cells, CodeQL, OpenSSF Scorecard, and offline Sigstore Rekor verification for `CLAIMS.md`.
- *Tag note:* `v0.1.0` was initially tagged at `5bcfcec` and re-pointed to `9c3353b` on 2026-11-26 (CI workflow and Dependabot config only; engine code identical).
