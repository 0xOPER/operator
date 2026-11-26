# Changelog

All notable changes to OPERATOR are documented in this file.

## Unreleased (`main`)

### Fixes
- `bin/review.py`: both selftest suites now report a failure (exit 1) when an arm crashes with VOID after an earlier arm already recorded a failure. A break that lets a forged verdict deliver moves the fixture out from under the arms after it; the suite used to exit 2 and forget the failure it had printed, which is why the ratchet reported four review rows as VOID.
- `test/neuter.py`: a row that does not die prints the last lines of the mutated test's output, so a VOID or a survivor can be told apart from an environment that broke the test.

### Documentation & Branding
- Added `docs/charter.md`: the charter design in progress — the schema, signed environments, reach profiles, the manager's verbs, the reserved questions with every escalation kind mapped to a stop class, the default charters, the control audit and the adopted decisions. Design only; nothing in it changes a `v0.1.0` claim.
- Rebuilt `assets/logo.svg` from exact measured geometry and `assets/banner.svg` at 880 px width with outlined Chakra Petch Bold (OFL) wordmark paths.
- Added an architectural comparison of common coding-agent orchestrator patterns and a clickable narrated overview video preview (`assets/video-preview.svg`) to `README.md`.
- Repaired `README.md` and `docs/quickstart.md` command sequences (passing the program directory positionally instead of `cd`ing into a directory without `bin/`), added the real-CLI and `[seat.op]` setup step, and aligned `ssh-keygen` passphrase usage.
- Aligned documentation wording with code and `LIMITATIONS` (`tamper-sealed`, bounded `[seat.op]` effect, call-log tail truncation boundary, `max_parallel = 1`, demo vs. first-level suite scope, and experimental `zcode` status).
- Completed `docs/authoring.md` (including `[seat.op]`, waivers, `budget.minutes`/`budget.context`, contract keys, and a valid `contract.toml` example), refreshed `INTERFACES.md`, and updated `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md`, and `docs/architecture.md`.
- Added Ubuntu 24.04 AppArmor `bwrap` profile instructions, macOS `--mount` Docker workflow, Real CLIs configuration guide (`spawn preflight`, `OPERATOR_ZAI_*`, `OPERATOR_TURN_*`, `OPERATOR_PAGER_COMMAND`), and `LICENSE` appendix notice.

## `v0.1.0` — 2026-11-26

Initial public release of OPERATOR under the Apache License 2.0.

- Linux `bubblewrap` confinement (`bin/lib/jail.py`, `bin/spawn.py`), host-side API credential brokering (`bin/broker.py`), and allowlisted egress proxy (`bin/egress-proxy.py`).
- Tamper-sealed contract verification (`bin/contract.py`) with pinned read-only test overlays, root runner-config restoration, `expect_base_fail` differential checks, twin `control` rows, and `pytest-guard` receipts.
- Signed SSH closure rulings (`bin/ruling.py`), cross-family review gate (`bin/review.py`), bounded unattended operator loop (`[seat.op]` in `bin/run.py`), and read-only loopback panel (`bin/panel.py`).
- Commercial CLI adapters for `claude-code`, `codex`, `opencode`, `zcode` (experimental), and offline `stub`.
- Cleanroom selftest battery, 461-row guard-mutation sensitivity ratchet, hollow-suite sabotage suite, CI CLI conformance cells, CodeQL, OpenSSF Scorecard, and offline Sigstore Rekor verification for `CLAIMS.md`.
- *Tag note:* `v0.1.0` was initially tagged at `5bcfcec` and re-pointed to `9c3353b` on 2026-11-26 (CI workflow and Dependabot config only; engine code identical).
