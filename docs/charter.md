# The charter

Status: design in progress (started 2026-11-27). The charter is built
milestone by milestone, and the **Status** column of each section says what the
engine enforces today and what is only specified here. Nothing on this page
changes a claim of `v0.1.0`: `README.md`, `CLAIMS.md` and `LIMITATIONS` change
when the manager milestone exits, not before.

A program without a `charter.toml` behaves exactly as it does today. That is
the degenerate charter: no reach, no environments, a fixed signed plan.

## 1. Why

OPERATOR is a good referee with no players. It keeps every "done" honest, and
then it parks, because the work that would make "done" true needs things the
engine refuses: network, a container, a GPU, a re-plan, a bigger budget.

Two programs made the point. One whose truth was a test suite in the repository
closed with no hand verb. One that needed a container and a GPU parked after
five attempts, and three of its four rows were waiting on a person. Where truth
is a command on the repository, the loop closes on its own. Where it is not,
honesty becomes a park.

The fix is not fewer guardrails. It is a different split of power:

> The owner signs the law once. A manager holds every power to act inside it.
> The engine alone certifies.

All power to act, no power to certify, no power to legislate. The README's
"God-Mode Manager Trap" is a manager that can lower the bar: edit a test, widen
its own grant, rubber-stamp. This design gives the manager everything except
that.

### Principles

1. All power to act; none to certify; none to legislate.
2. Refusals are for lies. Weakness gets a label, not a refusal.
3. A parked run is a bug. Every stop has an automatic next move unless the
   question is reserved to the owner (section 7).
4. The owner signs law, not plans.
5. OPERATOR has no opinions about how the work gets done. That intelligence
   lives in the enclosed orchestrators.
6. Default-allow inside the charter. Default-deny only outside it.
7. Every new guard earns a killing neuter row before it ships.
8. The product claim is parity: the same capability as an unconfined agent,
   without the lies.

## 2. The split

| Branch | Today | Charter model | Status |
|---|---|---|---|
| Legislature | signs `team.toml` and `contract.toml` per program | signs a **charter**: powers, purse, rules of evidence, reserved questions. Once, standing | `[[environment.<name>]]` blocks are signed and enforced; the rest is specified here |
| Executive | `[seat.op]`: five triage verbs, no plan | the **manager**: every power to act inside the charter, through one door | M4 |
| Judiciary | engine, zero LLM | unchanged, plus the environment runner, reach policy and plan audit | environment runner built; reach policy M2 |

The signed object moves up one level: from the plan to the rules for making
plans. A signed `team.toml` plus `contract.toml` remains valid as the
degenerate charter, so nothing that works today breaks.

## 3. The schema

`charter.toml` sits in the program directory beside `team.toml` and
`contract.toml`. It is inside the signed closure like every other program file:
`bin/ruling.py` hashes it with the rest, so an unsigned edit to a ceiling, a
host or an environment refuses before an attempt starts. The charter's
identity is computed, never authored.

| Section | Holds | Status |
|---|---|---|
| `schema` | `1` | built |
| `name` | the charter's name, `[a-z0-9][a-z0-9._-]{0,63}` | built |
| `[standing]` | `not_after`. A charter is standing: one signature covers many runs until it expires | today's arm ruling (`--not-after`) |
| `[purse]` | ceilings: `usd`, `minutes`, `context`, `concurrency`. Ceilings only; allocation is the manager's | M4; until then `team.toml` budgets are the ceilings |
| `[reach]` | the network policy (section 5) | M2 |
| `[evidence]` | mutation floor, review law (section 8) | M3 |
| `[reserved]` | questions the owner adds to the reserved list | M4 |
| `[[environment.<name>]]` | signed environment specs (section 4) | built |

Write scopes do not move: they stay on seats, as `[seat.<name>].write`.

An empty purse is not an unlimited purse. The purse is shape-checked now and
enforced with the manager milestone; from then on a charter without a `[purse]`
table refuses at validate and names the missing ceiling. OPERATOR ships no
default number: the ceiling is the owner's.

## 4. Environments

Where programs run. A signed block per environment:

```toml
[[environment.tests]]
image = "registry.example.org/example/tests@sha256:<64 hex digits>"
runtime = "docker"                 # docker | podman | none (a jail plus devices)
devices = ["gpu"]                  # "gpu" or a /dev path
mounts = ["/opt/datasets/oracle:ro"]
network = "none"                   # none, or a reach profile
rootfs = "ro"
writable = ["/tmp:256m"]           # size-capped tmpfs mounts inside the image
user = "1000:1000"                 # never root

  [environment.tests.limits]
  memory = "4g"
  cpus = 2
  pids = 256
  wall = 600                       # the ceiling for one run, in seconds
```

| Field | Meaning |
|---|---|
| `image` | pinned by digest: `name@sha256:<64 hex>` or a local image id `sha256:<64 hex>`. A tag is refused, and the engine never pulls: the image must be present locally under that digest |
| `runtime` | `docker` is built. `podman` and `none` are specified and refuse until they are proven |
| `devices` | `gpu` binds the host's compute devices; a `/dev` path binds that device |
| `mounts` | host paths the environment may see, each `ro` or `rw`, at the same path inside |
| `network` | `none`, or a reach profile (section 5) |
| `limits` | memory, CPUs, processes and wall clock. A runaway is killed by its memory limit |
| `user` | `uid:gid`, both above zero, and the engine's own uid, so the files a run writes stay the engine's |
| `rootfs` | read-only unless a path is declared writable |
| `writable` | tmpfs mounts with a size, for scratch space |

Rules (`bin/environment.py`, built):

- The engine is the only container client. A worker or the manager never sees
  a container socket.
- The caller supplies only an environment name, an argv and a work directory.
  Everything else comes from the signed spec, and the arm ruling is verified
  before every run: an edited environment is an unsigned program.
- No network, a read-only rootfs, every capability dropped, no new privileges,
  a size-capped log, and memory, CPU, process and wall limits. A runaway is
  killed by its memory limit.
- A spec that mounts the host root, a container socket, a system directory or
  anything outside its own list refuses at validate.
- Every run writes a receipt into the hash-chained call log: environment, image
  digest, argv hash, exit code, duration, runtime, and a fingerprint of what
  the run left in its work directory: every regular file's path and bytes,
  within a budget of 20,000 files and 1 GiB. Past the budget the rest is
  fingerprinted by name and size only, and the receipt says `workcap=1`. A
  link is named, never read. Artifact globs chosen by the caller are not
  built: the whole work directory is hashed.
- Signing a new environment spec is reserved to the owner. Once per environment.
- `operator environment validate <dir>` checks the charter;
  `operator environment run <dir> --env NAME -- <cmd...>` is the door.

Rows gain `env = "<name>"`. A `run` row with an environment executes its check
there, with the candidate export and the pinned oracle mounted.

One door serves three callers: a row's check (built), the worker itself (built:
a seat with `env = ["tests"]` gets an environment socket in its jail, served by
the engine, so a worker can iterate against the real environment mid-task
without ever holding the daemon), and the manager's `env.run` verb (M4). Every call is validated the same way, logged the same
way and capped by the seat's purse. A seat names the environments it may call
with `env = ["tests"]`; the container sees only what the worker stages into its
work directory, never the worker's repository.

## 5. Reach

The egress proxy already has the rule language: hosts and subdomains, deny
beats allow, expiry, pinning, non-global addresses refused, one log row per
connection, and a full log refuses everything. It re-reads its policy on every
connection. What is missing is a policy source and the grant classes.

| Category | Default rule | Used by |
|---|---|---|
| `registries` | the package registries | every profile |
| `docs` | documentation hosts | `dev`, `research` |
| `vcs` | forge hosts, fetch only | `dev`, `research` |
| `api` | hosts named in the charter | any |
| `declared` | the manager may allow up to N hosts, port 443, with a TTL, each logged | `dev`, `research` |
| `web` | any global address on 80 and 443, rate and size capped | `research` only |

Always denied: private, local and link-local ranges; cloud metadata endpoints;
the charter's signed deny list of credential, payment and mail endpoints.

"Fetch only" holds by construction: no worker or manager holds a credential,
and the broker stays the only door that has one.

- `network`, `shell` and `read` join an adapter's `tested_classes` only when a
  conformance cell exists for that adapter and class. The grant is earned per
  adapter, not declared.
- `net.allow` is a manager verb, bounded by the `declared` rule. Built as the operator
  seat's verb (below); the manager inherits it.
- A credential shape riding what the egress proxy can read (the CONNECT line
  and its headers, a plain-HTTP request) is refused and logged, naming the
  host and never the bytes. Inside an HTTPS tunnel the proxy reads nothing:
  that limit is stated, not hidden. Built.
- A `closed` profile keeps today's behaviour for repositories that need it.

Built so far (M2, first slice): the policy comes from the charter and the proxy
re-reads it on every connection; a seat's `network` grant is bounded by the
charter and refused outside it; the jail gets the proxy as its only door, with
one log row per connection; `network` is in the `tested_classes` of
`claude-code`, `codex` and `opencode`, each with a `net-allowed` conformance
cell; a credential shape riding a request head is refused and logged (the
`net-allowed` cell proves it in a real jail). `shell` is in the same three
adapters' `tested_classes`: commands run inside the jail and the jail is the
law, because no shipped adapter keeps a per-command law (`claude-code` runs
the commands its own analysis deems safe with no rule and asks before the
rest; the other two have no permission layer at their pins), so the prefix
scoping the plan imagined waits for an
adapter that can. The `declared` rule is built: `operator reach allow <dir>
--seat <seat> --host <host>`, and the operator seat's `net.allow` directive,
open one host on 443 for a seat that already holds a network grant, for
`declared_ttl` seconds while fewer than `declared_max` are live, never a
denied host; every one is a row in the call log, and it rides the seat's next
turn. Open: `read` (neither the plan nor this charter says yet what it
reaches), and the writable clone. Not buildable as the
plan first wrote it: "egress bodies" —
an HTTPS tunnel's body is encrypted, and the broker's request bodies are the
worker's own prompts, where key-shaped strings are often honest fixtures.

A worker's `.git` is bound read-only today, which rules out worktree fan-out. A
seat that needs fan-out gets a real writable clone only when a conformance
cell proves that a hook planted there never runs host-side.
`test/planted-hook-walk.sh` is that proof's standing leg: it plants what a
writable clone could plant, runs the real delivery chain, and checks that
nothing fired on the host. A control shows the plants are live, and a sabotage
mode shows the walk can fail.

## 6. The manager

The manager is any orchestrator: OPERATOR's own seat, or an external tool. It
reaches the engine through exactly one door, `operator ctl`, a small CLI on its
PATH, also exposed as an MCP server.

| Verb | What it does | Bound | Never |
|---|---|---|---|
| `plan.set` | replaces the run's task graph | every row passes lint; each version hash-chained | remove a check from a task that already has a green review without the owner's signature |
| `task.add` | adds a task | same | |
| `task.skip`, `task.defer` | closes or postpones a task with a reason | not on a task the charter marks `must` | erase a red verdict or a non-goal |
| `spawn`, `reassign` | dispatches, or moves a task to another worker, adapter or model | concurrency ceiling | choose the reviewer |
| `reply` | advisory guidance to a worker | as today | instruct as an authority |
| `rebudget` | moves allocation between seats and tasks | charter ceilings | raise a ceiling |
| `env.run` | runs a command in a signed environment | signed specs only | see a container socket |
| `net.allow` | allows a host for a while | the `declared` rule | touch the deny classes |
| `review.request` | asks for a verdict | review law | pick a friendlier reviewer |
| `evidence.attach` | attaches operator-supplied evidence | labelled as such | label it sealed |
| `escalate.owner` | asks a reserved question with the exact ask | reserved classes only | resolve it |
| `retry`, `resolve`, `cancel`, `stop` | as today | as today | resolve a protected escalation, resume after a stop |

The manager may also hold a worker seat if it wants to write code. That seat
passes the same gates as any worker.

Its own cell: a jail with a rendered view of run state and evidence, `operator
ctl`, program memory (fenced, labelled, kept across runs), and the charter's
reach. Its model family should differ from the workers' by default. Every verb
returns JSON, every refusal names its fix, and `ctl why` explains any refusal.

## 7. Reserved questions and the stop law

Reserved to the owner, and to nobody else:

1. Widening the charter: more reach, more purse, more power.
2. Irreversible acts outside the workspace: rewriting shared history, deleting
   a shared branch or release, publishing.
3. External acts: sending, paying, submitting, registering.
4. Signing a new environment spec. Once per environment.
5. Perceptual acceptance, where a task needs a person to look.
6. Resuming after a stop; clearing a security escalation.

Everything else is the manager's.

| Event | Today | Charter model | Status |
|---|---|---|---|
| worker asks a question | listed; in attended mode nobody is paged | manager answers inside the charter's ambiguity rule | M4 |
| machine row red | `contract_red`, retry | rework with the diagnostics; re-plan if it repeats | M4 |
| reviewer says "changes" | retry | same | today |
| reviewer says "red" | human-only | retry, reassign, or skip with a reason; the owner only for a `must` task at its cap | M4 |
| retry cap | 3, then human | higher and per charter; alternatives tried first; the owner only for a `must` task | M4 |
| write outside grants | `gate_refused`, human | reject, retry with the refusal as diagnostic; the owner only if the worker insists and the ask is to widen | M4 |
| no progress | halt, human | manager first: reassign, re-plan, skip | M4 |
| a seat's budget is spent | ticks refuse until a re-arm | manager re-budgets inside the ceiling | M4 |
| out-of-policy host | not expressible | manager allows it if the rule permits, else asks | M2 |
| charter ceiling hit | human | one clean pause and one exact ask, drafted by the manager | M4 |
| stop placed | human resumes | human resumes | today |
| task cannot be done | dead end | `task.skip` with a reason; the run finishes and reports it | M4 |

### Every escalation kind, mapped

Three classes. **Auto**: the loop's own next move. **Manager**: decided inside
the charter. **Owner**: a reserved question, asked with the exact ask.

Escalations are files under `<run>/escalations/`, named by kind.

| Kind | Raised when | Today | Class |
|---|---|---|---|
| `contract_red` | machine rows are red | task escalates; the operator seat may retry | Manager |
| `needs_input` | a worker asks; a turn leaves no report; a verdict says "changes" | the task blocks or escalates; a `reply` readies it again | Manager |
| `needs_input` | a row waits for a human reviewer's verdict | the run idles at `reviewing` | Manager, except a perceptual row: Owner |
| `conflict` | candidacy fails (merge, grant, embedded repository) | task escalates; operator retry | Manager |
| `gate_refused` | the import gate refuses the delivery | protected; the operator seat may still retry | Manager |
| `review_red` | the reviewer's verdict is red | protected: no resolve, no operator retry | Manager (owner for a `must` task at its cap) |
| `retry_cap` | the operator's retries for a task reach 3 | protected; paged | Manager (owner for a `must` task) |
| `episode` | a turn fails, seals abnormally, or a drive step raises (a spent budget, the concurrency ceiling) | usually stays `ready` and repeats next tick | Manager for a budget, Auto for the concurrency ceiling |
| `episode` | three non-clean ticks in a row | paged once | Auto |
| `halt` | no progress: two attempts with no diff and no report | run pauses; paged | Manager first; Owner when nothing is left |
| `stop` | the STOP sentinel | run pauses; a human resumes | Owner |
| `security`, `ruling` | reserved names | protected | Owner |

Refusals map the same way. A `Refused`, `Finding` or `Void` inside a task's
ladder becomes an `episode` file and takes that row's class. The exit codes do
not change: 0 ok, 1 refused, 2 usage or VOID, 3 a lock is held.

### Known gaps in today's stop law

Found while mapping; each is work for the manager milestone.

- A protected escalation file is never retired. No verb resolves one, so after
  any `gate_refused`, `review_red`, `halt`, `retry_cap` or `stop` file the run
  cannot resume on its own.
- A spent budget has no kind of its own. It rides `episode`, and its fix text
  names a retry that refuses a `ready` task.
- `needs_input` covers five different situations with one name.
- A green verdict on a candidate that moved underneath it is only logged.
- A killed or timed-out turn returns to `ready` with no retry count, and the
  named fix after the resulting halt does not work.
- A blocked or reviewing task never pauses, pages or trips the breaker.

## 8. Evidence without a pre-written contract

More power to act needs stronger evidence law, not weaker.

- **Derived baseline.** `operator derive <repo>` finds the runners, linters,
  type checks and build, and writes sealed rows over them. Rows already red at
  the pin become the known-red baseline, shown in the digest; done means no
  new red. Built (first slice): pytest, unittest, Makefile targets,
  package.json scripts, cargo and go are found and their rows sealed; the pin
  reports the red ones and files nothing. Open: linters and type checks as
  their own rows, and the baseline in the run's digest.
- **Labels, not refusals, for weakness.** Every row the manager adds runs once
  against a hollow twin of the candidate (same paths, emptied bodies). A row
  that stays green is labelled `reviewed-only`.
- **Refusals for lies.** An existence-class command cannot claim
  `expect_base_fail`: it fails on base only because the file is new. It may
  anchor a row with a twin control, or carry the `reviewed-only` label. Today
  lint accepts `test -f src/new.py` with `expect_base_fail`.
- **Mutation floor.** A row with `test_paths` may set `min_mutation_kill`: the
  engine mutates the candidate's changed source and the row's own tests must
  kill a share of the mutants.
- **A receipt beats a note.** Evidence from an environment run is an
  engine-written receipt. Anything attached by hand is shown to the reviewer as
  an unverified claim, never as a result.
- **The run reports its evidence mix.** "Done: 3 sealed, 1 reviewed-only,
  1 human."
- **Templates ship checks that can fail.** The starter's `docs` row goes green
  on a four-byte file; it is replaced.

The rest of this section is M3, not built.

## 9. Default charters

Four profiles share one schema. The purse is never defaulted: each example
shows a number that is its owner's.

### `dev`

```toml
schema = 1
name = "dev"

[purse]                  # ceilings; the example numbers are not a default
usd = 40.0
minutes = 480
concurrency = 2

[reach]
profile = "dev"          # registries, documentation hosts and fetch-only forges
declared_max = 10        # the manager may allow ten more hosts on 443, each logged
declared_ttl = 3600

[evidence]
min_mutation_kill = 0.3

[[environment.tests]]
image = "registry.example.org/example/tests@sha256:<64 hex digits>"
runtime = "docker"
network = "none"
user = "1000:1000"
writable = ["/tmp:256m"]

  [environment.tests.limits]
  memory = "4g"
  cpus = 2
  pids = 256
  wall = 600
```

### `research`

The `dev` charter with a wider reach and no environments: `[reach].profile`
is `research`, which adds the `web` category, rate and size capped.

### `closed`

Today's behaviour, kept for repositories that need it: no network for any seat
other than the broker, no environments, human-only protected escalations. A
program without a `charter.toml` is `closed`.

### Standing

A charter used across many runs: the same file, a `[standing].not_after`, and
a wider purse. Reach is the signed scope; `[reserved].extra` names anything
the owner wants to be asked about beyond the six. The rules the owner writes
into the goal and the row descriptions are engine-trusted text and ride every
brief and every review pack.

## 10. The control audit

A control is real when it names a threat and a test that breaks when the
control is removed.

### Real. These do not move.

| Control | Threat | The test that breaks without it |
|---|---|---|
| credential broker | a prompt-injected worker exfiltrates the key | the canary walk, the topology drill, the broker selftest |
| jail and git-object write gate | host damage, out-of-grant writes, symlink and hook smuggling | the conformance cells, the import gate arms |
| sealed oracle, runner-config seal, `pytest-guard` | test tampering, fake green | the hollow battery, the sealed probes |
| dual gate with provenanced verdicts | forged or stale review | the review suite's forgery arms |
| ledger that always settles | budget evasion | the settle arms |
| signed rulings and closure | a model editing the law | the ruling suite, the closure arms |
| one-way STOP | an agent un-stopping itself | the stop sweep arms |
| hash-chained call log and events | tampering, lost evidence | the call log selftest |
| the neuter ratchet | silent regression of all of the above | itself: one killing row per guard |

### Theatre. Each costs the owner time and stops no one.

| What | Why it is theatre | Re-homed in | Status |
|---|---|---|---|
| signing a plan whose rows cannot fail on wrong work | the signature certifies nothing about truth | M3 | open |
| refusing all network to a worker that holds no secret and delivers through the write gate | blocks work, not the threat | M2 | open |
| human-only `review_red` after three tries | a person rubber-stamping an LLM's opinion at 2 AM | M4 | open |
| re-arming to raise a budget | the owner as a budget clerk | M4 | open |
| owner ruling rows for anything a pinned image could run | the engine refuses to know about containers | M1 | open |
| "zero-AI gates" beside an AI review gate | overclaim | M6 | open |

## 11. Decisions and milestones

The owner set the direction on 2026-11-27 and adopted the recommendation on
each row by delegation.

| # | Question | Adopted |
|---|---|---|
| D1 | What is reserved to the owner by default? | the six items of section 7, nothing else |
| D2 | What does the `dev` profile allow on the network? | registries, documentation hosts, fetch-only forges, and up to ten manager-declared hosts on 443, each logged |
| D3 | May the manager retry, reassign or skip past a red review? | yes; the owner sees it only for a `must` task at its cap |
| D4 | Who is the manager first? | OPERATOR's built-in seat (M4); an external orchestrator through `ctl` after (M5) |
| D5 | Is a charter standing, or per run? | standing, with `not_after` |
| D6 | When does the public wording change? | after M4's exit, not before |
| D7 | Containers on the same host, or in a VM? | same host first, with signed specs; a VM when there is more than one tenant |
| D8 | Default purse for the `dev` profile | none: the purse is a required ceiling and the number is the owner's |

| # | Milestone | Un-rails | Status |
|---|---|---|---|
| M0 | Charter law | the signed plan | this document |
| M1 | Environments | container and GPU work | built: the charter, the door, `env` rows, the worker socket, a fingerprint of the work directory in every receipt. The exit is the parked program's two rows closing as machine rows |
| M2 | Reach | network, shell, read | built: a seat's network from the charter, through the egress proxy; a credential shape refused on the wire; `shell` on the three adapters, the jail the law. Open: the `declared` rule, `net.allow` (with the manager), and `read` |
| M3 | Evidence | contract authoring as a precondition | first slice built: `operator derive`. Open: the hollow twin and the `reviewed-only` label, the lint against existence-class anchors, `min_mutation_kill`, the evidence mix, the templates |
| M4 | The manager | triage seat becomes executive | open |
| M5 | Enclose | external orchestrators as workers or managers | open, gated on probes |
| M6 | Scale and prove | serial dispatch; the claim | open |

Order: M0, then M1 and M2, then M3, M4, M5, M6. M3 comes before M4 because
more power to act needs the evidence law first.

The owner's goal is the one `must` task, and no model writes it. It closes on
two things together: the sealed baseline is green, and a cross-family reviewer
verdicts green against the goal's own text. Everything under it is the
manager's to decompose, and to skip with a reason.

A run ends in exactly three ways: the goal is green; stopped; or a reserved
question is waiting. Every other ending is a bug.

## 12. What never moves

1. Zero LLM in the TCB. Every model is untrusted, the manager included.
2. No worker or manager holds a usable credential. Spend settles on the
   broker's numbers.
3. Delivery only through the git-object gate.
4. Evidence labels are structural. No model chooses one.
5. Sealed means sealed: pin-first export, candidate diff outside the oracle,
   runner configs pinned, `pytest-guard` receipts.
6. Promotion only through the dual gate.
7. Cross-family review, enforced; waivers signed by the owner.
8. No editable guardrails, no sandbox-off switch, no judge-as-truth.
9. Reserved questions stay with the owner.
10. STOP is one-way for every model.

This is not one principal that acts and certifies. Certification is
unreachable, the blast radius is the charter, and the reserved questions are
the owner's.
