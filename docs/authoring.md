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
env = ["tests"]                     # environments this seat may call in its jail (charter.toml)

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
- **Bounded effect:** The engine consumes only `report.json` from an operator turn and accepts at most 8 whitelisted directives per turn from 6 verbs: `retry`, `reply`, `resolve`, `cancel`, `stop`, and `net.allow` (`{"seat": "<seat>", "host": "<host>"}`: one host on 443 for a seat that already holds a network grant, inside the charter's `declared_max` and `declared_ttl`, never a denied host; `docs/charter.md`). Host guards block `resolve` (and autonomous `retry` on `review_red`) for protected escalations (`halt`, `stop`, `security`, `ruling`, `gate_refused`, `retry_cap`, `review_red`) and enforce `MAX_TASK_RETRIES = 3`.

Every seat key: `role`, `adapter`, `human`, `write`, `read`, `see`, `network`,
`shell`, `mcp`, `memory`, `skills`, `budget`, `model`, `repo_context`, `gpu`,
`ro`, `env`. The team file also takes top-level `schema`, `name`, `contract`,
`autonomy`, `max_parallel`, `budget`, and `mcp`; the shipped templates are the
working examples (copy them via `bin/operator.sh init` rather than editing
`profiles/templates/` in place, which dirties the engine repo and causes
`ruling sign` to refuse).

> **Enforceability & inert keys:** `claude-code`, `codex` and `opencode` declare
> `tested_classes = ["write", "network", "shell"]`, each with green
> `net-allowed` and `shell-allowed` conformance cells; the others declare
> `write` only. A grant outside its adapter's tested range is **refused** by
> `bin/team.py`. `read` and seat `mcp` grants are **refused** for every adapter. `memory`, `skills`, and
> `mcp` declarations are currently **inert** (accepted with a note, not yet
> wired to enforcement).

### The seat's network (`network`)

A seat asks for a network with `network = ["pypi.org"]`, or `["*"]` for the
charter's whole reach. The charter bounds it (`docs/charter.md`): every host
must be inside `[reach]` (its profile's categories or its `allow` list), a
`[reach].deny` host beats every allow, and `bin/operator.sh team validate`
refuses a grant outside it by name. In the seat's jail the egress proxy is then
the only door: the standard proxy variables are set for every CLI and tool,
each connection is one log row under the attempt's `egress/`, and a host
outside the policy is refused. The broker is never proxied. Port 443 is
served; another port is a `[reach].pins` entry. `bin/reach.py policy <dir>
--seat <seat>` prints the policy a seat's jail runs.

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
- **budget** -- accepts `usd` (team or seat ceiling; reservations settle against
  it, priced from `broker.py`'s built-in rate table), `minutes` (wall-clock
  ceiling), `context` (input-token budget that gates the next reservation), and
  `env_minutes` (what a seat may spend inside its environments).
  Spawn reserves `min(seat, team, usd/(max_rework+1))`.
- **env** -- the environments this seat may call in its jail, each one declared
  in `charter.toml` (see the door below).

### The environment door (`env`)

A seat with `env = ["tests"]` may run commands inside the environments the
program's `charter.toml` signs (`docs/charter.md`). Its jail gets a socket
served by the engine, and the brief says how to use it:

```sh
python3 -I /engine/op-env.py --env tests -- <cmd...>
```

Stage what the command needs under `/w/envwork`; it is `/work` inside the
environment. The engine launches the run through the only container door,
verifies the arm ruling first and files a hash-chained receipt; the command's
output comes back and its exit code is the client's. Everything else is the
signed spec's. One request runs at a time. The door opens with the seat's turn
and closes with it: a run in flight is killed.

### Waivers & ruling bindings

`bin/team.py` recognizes four named waivers (`--waive <name>` on `ruling sign`):

- `budget=advisory` -- emitted whenever a team or seat sets `budget.usd` (the
  cap gates the next reservation; an in-flight attempt may overshoot up to its
  reservation/turn cap, and USD is estimated from `broker.py`'s model price
  table).
- `rule-of-two` -- waives overlapping write/external-input combinations when
  flagged by `team validate`.
- `unreviewed-rows` -- waives rows without an independent reviewer.
- `same-family-review` -- required if a worker and its reviewer share the same
  model family.

When signing an arm ruling (`bin/operator.sh ruling sign <dir> --kind arm`),
you can also bind it to a single run (`--run <name>`) and/or an expiry time
(`--not-after <UTC ISO-8601>`).

Rows with the same seat, stage and deps form ONE task: one attempt, one
delivery, one review.

## contract.toml

```toml
schema = 2

[setup]                             # runs jailed via `bin/operator.sh contract setup <dir>`
cmd = "python3 -m venv /env && /env/bin/pip install -r requirements.lock"
inputs = ["requirements.lock"]      # hashed into setup stamp
network = ["pypi.org", "files.pythonhosted.org"]
timeout = 300                       # optional setup timeout in seconds

[[row]]
id = "tests.control"                # [a-z0-9][a-z0-9._-]{0,63}, unique
stage = "verify"                    # stages run in DECLARATION order, not name order
desc = "Verify the sealed test suite fails on broken fixture"
kind = "run"                        # run | ruling | tsv | git
seat = "writer"
reviewer = "reviewer"
cmd = "pytest -q tests/test_control.py"
timeout = 120                       # at least 60
oracle = ["tests"]                  # paths restored from the pinned commit, bound ro
runner = "pytest"                   # optional: "pytest" (force guard) | "raw"
min_tests = 1                       # optional: minimum collected tests for pytest-guard

[[row]]
id = "impl"
stage = "build"
desc = "Implement feature and pass pinned test suite"
kind = "run"
seat = "writer"
reviewer = "reviewer"               # REQUIRED on every row: whose verdict gates delivery
deps = ["tests.control"]            # rows that must be green first; cycles refuse
cmd = "pytest -q tests/"            # THE CHECK. It decides green, never the report
timeout = 300
oracle_from = "tests.control"       # borrow a lender's oracle; cycles refuse at load
ro = ["tools"]                      # extra read-only binds from the program tree
control = "tests.control"           # the twin: a dead control fails its row
evidence = "sealed"                 # sealed | author-reachable | human
mutable_configs = []                # optional: allowlisted runner configs left writable
# gpu = true                        # optional: mount host nvidia devices (Voids if absent)
# env = "tests"                     # optional: run the check in a signed environment (below)

[[row]]
id = "scope.changed"
stage = "build"
desc = "Ensure source files changed without touching tests"
kind = "git"
seat = "writer"
reviewer = "reviewer"
deps = ["impl"]
require = ["src/**"]
forbid = ["tests/**"]
diff_base = "step"                  # git rows only: "step" (commit^1, default) | "pin"
```

*(Note: `driver = "external"` routes a `run` row through an external verdict
gate and cannot be combined with `cmd` on the same row; `bin/contract.py`
refuses both together.)*

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

- **run** -- `cmd` runs in the check jail; exit 0 is green. With `env = "<name>"`
  it runs instead in that signed environment (`docs/charter.md`): a container the
  engine launches from the program's `charter.toml`, with the same export, the
  same pinned oracle and runner configs mounted read-only at their paths and the
  same `pytest-guard` files. The row's timeout may not exceed the environment's
  wall, and its receipt names the environment, the image and a fingerprint of
  what the check left in `/w/out`. `contract lint`
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

### A derived baseline

`bin/operator.sh derive rows <work-repo> --seat <seat> --reviewer <seat>` reads
the tree at a commit (no checkout) and writes contract rows for the runners it
knows: pytest and unittest, the `test`, `check` and `lint` targets of a
Makefile, the `test`, `lint` and `typecheck` scripts of a `package.json`,
cargo and go. Each row's oracle pins what the runner reads (the test
directory, the config, the lockfile), so a worker cannot weaken the check it
is held to. `--at <commit>` reads that commit. Paste the rows into
`contract.toml` and sign.

`derive pin <program-dir> <run-parent> --at <commit>` runs every derived row
once at the commit, through the check jail, and says which are red there: that
is the known-red baseline, and done then means no new red. The pin reports and
files nothing.

A derived row is a starting point. One that needs what the jail does not have
(an installed tree, a toolchain) is red at the pin and says so.

### The seat's shell (`shell`)

`shell = ["*"]` lets a seat run shell commands. On every shipped adapter the
law is the jail, not a per-command rule: `codex` and `opencode` have no
permission layer at their pins, and `claude-code` runs the commands its own
analysis deems safe with no rule and asks before the rest (measured at the
pin: a write into an existing directory runs; creating the directory asks).
So a command's in-tree effect lands, and its out-of-tree effect (a write
outside the repository, a host path, the network) is refused: by the jail and
the proxy on `codex` and `opencode`, and on `claude-code` by the CLI's own
check first, with the jail behind it. No shipped adapter enforces command
prefixes; the grammar accepts them, for an adapter that can.

### Templates and state

`bin/operator.sh init <dir> --template <name>` ships three starter templates
(copy them with `init`; never edit files under `profiles/` in place):

- **feature** -- one writer, one reviewer, the smallest honest team.
- **plan** -- goals with lint (short-circuits, trivial heads, bare literals
  refuse) and a forge test that catches its own planted hollow.
- **research** -- the citation law: sources fetched once through the engine,
  bodies sealed by a content-hash manifest, quotes verbatim from sealed
  bodies only, `[n]` mapped from the numbered closing list only. A fabricated
  URL or quote stays red.

The repository also includes `profiles/migration/contract.toml` as a reference
contract example for migration-style tasks.

Run state lives under `$OPERATOR_HOME` (default `$XDG_STATE_HOME/operator`,
otherwise `~/.local/state/operator`). Each run keeps a full clone of the work
repository under `runs/<run>/parent/`; reclaim disk space from finished runs
with `bin/operator.sh run gc <run>`.

## Rules of thumb

1. The check is the truth; the report is a claim. Write checks you would run
   yourself.
2. Pin what you can (`oracle`), twin what you can't (`control`), label the
   rest `human` and read it.
3. Every refusal names its fix. If a refusal's second line tells you to do
   something, that something is the next command -- this page is the map.
