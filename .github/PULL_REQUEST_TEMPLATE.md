## Summary

<!-- Describe what this pull request changes and why. -->

## Verification

- [ ] Added or removed files are reflected in `keep-list` (`LC_ALL=C sort`).
- [ ] `scripts/release-lint.py` passes with `hits=0` (no binary files, host paths, or credentials).
- [ ] `test/ratchet.sh` passes (zero new `shellcheck` or `ruff` issues; `test/ratchet.tsv` lowered if existing issues were fixed).
- [ ] `test/cleanroom.sh scripts/run-all-selftests.sh` passes.
- [ ] Security or gate changes include a corresponding selftest and mutation row in `test/neuters.py`.
- [ ] `CLAIMS.md` was left untouched (or re-anchored intentionally via the release ceremony).
