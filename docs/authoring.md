# Authoring teams and contracts

A program is a directory: `team.toml` (who works), `contract.toml` (what done
means), `roles/*.md` (the persona each seat reads). The engine refuses what
these files don't name -- unknown keys are findings, not style warnings -- so
this page is the complete vocabulary. `bin/operator.sh team validate <dir>` checks
the team; `bin/operator.sh contract validate <dir>` checks the whole table.

## team.toml

```toml
schema = 1
name = "my-team"
max_parallel = 1

[seat.writer]                       # the seat name is [a-z0-9][a-z0-9._-]{0,63}
role = "roles/writer.md"            # the persona: signed ruled text, composed unfenced
adapter = "claude-code"             # stub | claude-code | codex | opencode | zcode
model = "claude-sonnet-4-6"         # optional BYO model id overriding manifest default_model
repo_context = "hide"               # "hide" (default: 0 bytes injected) | "load" (fenced repo instructions)
write = ["src/**"]                  # delivery grants: repo-relative globs
see = [".github/**"]                # visibility: present in the sparse checkout, grants no writes
gpu = true                          # the nvidia devices ride this seat's jails
ro = ["/data/models"]               # read-only host paths (the model tree): mounted
                                    # at their own paths; never on a jail-owned
                                    # mount, never the engine's own tree or state

[seat.writer.budget]
usd = 6.0                           # reservations settle against this, ALWAYS

[seat.reviewer]
role = "roles/reviewer.md"
adapter = "codex"
write = ["docs/**"]

[seat.op]                           # optional; required for `--autonomy unattended`
role = "roles/op.md"
adapter = "claude-code"             # must be an adapter with report_mount (claude-code, opencode, zcode)
[seat.op.budget]
usd = 2.0
```

### The operator seat (`[seat.op]`)

Shipped templates default to `adapter = "stub"` and omit `[seat.op]`. Starting a run with `--autonomy unattended` refuses unless `[seat.op]` is defined with an `adapter` (in `bin/run.py`, `cmd_operate` refuses with `no op seat on this team`).

- **Empty repo grants:** `[seat.op]` carries no `write` grants; its attempts are never sealed, imported, or promoted into the repository.
- **Adapter requirement:** `[seat.op]` delivers its directive JSON via `/w/repo/report-out.json`, so choose an adapter whose manifest defines `report_mount` (`claude-code`, `opencode`, or `zcode`; `codex` and `stub` do not mount it).
- **Bounded effect:** The engine consumes only `report.json` from an operator turn and accepts at most 8 whitelisted directives per turn from 5 verbs: `retry`, `reply`, `resolve`, `cancel`, `stop`. Host guards block `resolve` (and autonomous `retry` on `review_red`) for protected escalations (`halt`, `stop`, `security`, `ruling`, `gate_refused`, `retry_cap`, `review_red`) and enforce `MAX_TASK_RETRIES = 3`.

Every seat key: `role`, `adapter`, `human`, `write`, `read`, `see`, `network`,
`shell`, `mcp`, `memory`, `skills`, `budget`, `model`, `repo_context`. The
team file also takes top-level `contract`, `autonomy`, `budget` and `mcp`
rows; the shipped templates are the working examples.

The `stub` adapter is the fixture worker: its steps come from
`plans/<task>.json` in the program dir (engine-side authoring -- the plan is
compiled input, never brief text, so a fixture worker can't be a confused
deputy for its own persona). A reviewer seat may use its own adapter class:
its turn reads the review pack read-only and returns the verdict JSON -- any
adapter works, including a real CLI. A `human = true` reviewer seat never
dispatches; its verdict comes from `review.py verdict --key` and the run
waits on the approvals screen until it does.

- **role** -- a program-relative markdown file covered by the signed closure
  ruling. Its text rides the seat's brief as engine-trusted persona text (not
  fenced; untrusted repo files and mail ride `<uf-...>` fences separately).
- **repo_context** -- `"hide"` (default: hidden repo instruction files such as
  `CLAUDE.md` and `AGENTS.md` are excluded completely) or `"load"` (injected
  inside `<uf-...>` untrusted fences).
- **adapter** -- the CLI class. Real CLIs speak through the engine's broker:
  the jail never names a host and never holds a usable key.
- **write** -- the only paths whose delivery the gate accepts. Everything else
  a worker changes stays in its attempt as evidence.
- **see** -- what the sparse checkout leaves visible: a seen path is ordinary
  repo text to the worker, and grants no writes (the gate gates on `write`).
- **budget** -- spawn reserves min(seat, team, usd/(max_rework+1)); brokered
  turns settle at ground-truth `broker.jsonl` USD spend (`max(broker_usd, worker_cost)`).

Rows with the same seat, stage and deps form ONE task: one attempt, one
delivery, one review.

## contract.toml

```toml
schema = 2

[setup]                             # runs jailed via `bin/operator.sh contract setup <dir>`
cmd = "..."                         # bridged through egress-proxy.py into <prog>/env (/env)
inputs = ["requirements.lock"]
network = ["pypi.org", "files.pythonhosted.org"]

[[row]]
id = "impl"                         # [a-z0-9][a-z0-9._-]{0,63}, unique
stage = "build"                     # stages run in DECLARATION order, not name order
desc = "what done means, in words"
kind = "run"                        # run | ruling | tsv | git
seat = "writer"                     # who works it
reviewer = "reviewer"               # REQUIRED on every row: whose verdict gates delivery
deps = ["design.review"]            # rows that must be green first; cycles refuse
cmd = "python3 -I tests/run.py"     # THE CHECK. It decides green, never the report
timeout = 300                       # at least 60
oracle = ["tests"]                  # paths restored from the pinned commit, bound ro
oracle_from = "lender.row"          # borrow a lender's oracle; cycles refuse at load
ro = ["tools"]                      # extra read-only binds from the program tree
control = "impl.control"            # the twin: a dead control fails its row
driver = "external"                 # route the row through the verdict gate
evidence = "sealed"                 # sealed | author-reachable | human
gpu = true                          # the host's nvidia devices ride the check
                                    # jail; a host with none Voids naming its fix
```

### The evidence label

The default derives from the shape, and an explicit label that lies refuses:

- **sealed** -- an oracle-pinned row (`oracle` accepts top-level or nested
  directories, single files, and globs such as `pkg/**/tests`). At check time,
  `CONTRACT_PIN` is exported first, grant-scoped candidate edits outside
  `oracle` are applied, pinned `oracle` paths and runner configs (`pytest.ini`,
  `pyproject.toml`, `setup.cfg`, `tox.ini`, `**/conftest.py`, `**/*.pth`,
  `package.json`, `Cargo.toml`, etc.; overridable via `mutable_configs`) are
  mounted read-only, and `pytest` checks are wrapped automatically by
  `pytest-guard.py` (`min_tests`, CPython audit hooks, and HMAC session
  receipts). (To hide secret test vectors from worker reads during authoring,
  store them in `$PROG` and mount via `ro = [...]`.) Sealed NEEDS an oracle: a
  sealed row with nothing pinned is a labeling lie.
- **author-reachable** -- the checks ship in the tree the author works. Must be
  paired with a live `control` twin (itself anchored by `oracle` or
  `expect_base_fail`) or `expect_base_fail = true` (optionally with
  `test_paths = ["tests"]` to transplant newly authored candidate tests onto
  `CONTRACT_PIN` and verify they fail on the unpatched base) to pass
  `bin/operator.sh contract lint`.
- **human** -- a person signs. `ruling.py sign --kind row --row <id>`.

### The twin law (`control`) and differential falsifiability (`expect_base_fail`)

A `control` row runs the CHECKER'S own inputs through the same check. A control
that can't fail proves nothing, so a row whose control is red or hollow fails
its own row -- the twin must be alive, not present. Alternatively, setting
`expect_base_fail = true` on a `run` row enforces a two-point differential
gate: the engine runs `cmd` on `CONTRACT_PIN` first and refuses as vacuous if
it exits 0 on the unmodified base commit before requiring exit 0 on the
candidate.

### Kinds

- **run** -- `cmd` runs in the check jail; exit 0 is green. `contract lint`
  refuses exact trivial commands (`true`, `:`, `pass`...) as well as `|| true`
  / `true ||` shell short-circuits, and requires every `run` row to carry an
  `oracle`, `control`, or `expect_base_fail = true`.
- **ruling** -- a signed ruling of the named kind IS the row's green.
- **tsv** -- the ENGINE generates the check: `file` must exist, parse, hold
  `columns` columns and at least `rows_min` rows (an EMPTY tsv is never
  green). A tsv row takes no `cmd` and no `require`/`forbid` -- those are
  git-row keys.
- **git** -- delivery globs engine-evaluated with reasons: every `require`
  glob must match at least one path CHANGED between the pin and the
  candidate (existing-but-unchanged does not deliver), and no `forbid` glob
  may match anything changed.

### Review

A row that names a `reviewer` delivers nothing until that reviewer passes it:
`review.py verdict` green + signed (a human, `--key`) or provenanced (an
adapter's own review turn, verified from the run dir: right task, right seat,
the turn exited 0, the collected report matches). A stale verdict -- one
naming an earlier candidate -- certifies nothing and refuses by name. Red
refuses with the attempt standing as evidence; `--changes` re-dispatches with
the prior round riding the next pack.

### Templates

`bin/operator.sh init <dir> --template <name>` ships three:

- **feature** -- one writer, one reviewer, the smallest honest team.
- **plan** -- goals with lint (short-circuits, trivial heads, bare literals
  refuse) and a forge test that catches its own planted hollow.
- **research** -- the citation law: sources fetched once through the engine,
  bodies sealed by a content-hash manifest, quotes verbatim from sealed
  bodies only, `[n]` mapped from the numbered closing list only. A fabricated
  URL or quote stays red.

## Rules of thumb

1. The check is the truth; the report is a claim. Write checks you would run
   yourself.
2. Pin what you can (`oracle`), twin what you can't (`control`), label the
   rest `human` and read it.
3. Every refusal names its fix. If a refusal's second line tells you to do
   something, that something is the next command -- this page is the map.
