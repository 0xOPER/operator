# Working in this repo

Each rule names what enforces it, or says it is by convention.

- **Run anything that executes a check through `test/cleanroom.sh`.** Check rows run as you with no sandbox of their own. By convention. `test/cleanroom.sh` is the only thing that hides your home and the network.
- **A tracked file is on `keep-list`, or it doesn't exist.** Enforced by CI's 'No unlisted file, no link' step.
- **No credential shapes or personal home paths.** Checked by `scripts/release-lint.py` against `test/lint/tier-a.tsv`, which CI runs on every push and pull request.
- **A new check gets a row in `test/neuters.py`.** By convention. `test/neuter.py` enforces one kill per tool, no new survivor and a pinned row count, so it can't see a check with no row.
- **A contract row must be able to fail.** Enforced by `contract.py lint` and `test/hollow-battery-check.sh`.
- **`advance` re-evaluates before it moves, and a broken contract is VOID, never a verdict.** Enforced by the selftest arms the neuters `CT-adv-reeval` and `CT-void-adv` break.
- **Commits carry no tool attribution lines.** Enforced by a CI step.

## Tools

`ls bin` shows them, and `bin/operator.sh help <tool>` prints a tool's header. Each has `--selftest`. `scripts/run-all-selftests.sh` runs all of them.

## Exit codes

0 ok, 1 refused or missing, 2 usage or VOID, 3 a lock is held (advance/run lock busy, or call-log's lock busy). VOID means the instrument couldn't speak, so it must never read as a verdict.
