# Architecture

OPERATOR is a **verifiable AI control plane** for autonomous multi-agent execution. It separates policy authoring, autonomous execution, and deterministic enforcement into three distinct branches so agents can run end-to-end without a human in the inner loop while remaining cryptographically and kernel-bounded.

---

## The Three-Branch Constitutional Model

```
┌────────────────────────────────────────────────────────────────────────────┐
│  1. LEGISLATURE (Human at the Boundary)                                    │
│     team.toml · contract.toml · roles/ · skills/ · tools/                  │
│     Signed once via SSH canonical envelopes (bin/ruling.py)                │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ verified arm ruling (closure SHA)
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  2. AUTONOMOUS EXECUTIVE (Jailed AI Seats inside bwrap)                    │
│     • Worker seats  [seat.<w>]  — write-scoped clones, budget-aware briefs │
│     • Reviewer seat [seat.<r>]  — independent adapter verdict over pack    │
│     • Operator seat [seat.op]   — autonomous escalation triage (whitelisted│
│                                   verbs only; no shell, no rule edits)     │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ sealed bundles, reports, directives
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  3. DETERMINISTIC JUDICIARY (Host Control Plane — zero LLM in the TCB)     │
│     • bin/spawn.py         jail builder, seal, import gate, CAS promote    │
│     • bin/contract.py      contract-first check jails, sealed oracles      │
│     • bin/review.py        adapter provenance & signature gate             │
│     • bin/run.py           state machine, op capability guards, loop daemon│
│     • bin/broker.py        API credential isolation, usage & turn caps     │
│     • bin/egress-proxy.py  allowlisted TLS/SNI & header-only HTTP egress   │
│     • bin/compose-fence.py per-turn nonce fences & format-char stripping   │
└────────────────────────────────────────────────────────────────────────────┘
```

### 1. Legislature — Signed Constitution at the Boundary

Humans do not babysit the execution loop. Instead, the owner defines the program's constitution once and signs it with an SSH key restricted to `namespaces="operator-ruling,operator-review"` (`bin/init.py`, `bin/ruling.py`):

- **`team.toml`** (`bin/team.py`) — declares seats, adapters, write grants (`src/**`, `docs/**`), read-only data paths, GPU access, `max_parallel`, per-seat/team USD and context-token budgets, and optional autonomous `[seat.op]`. Roles carry no authority; grants do.
- **`contract.toml`** (`bin/contract.py`) — declares stages, dependencies, reviewers, and typed check rows:
  - `kind = "run"`: shell check inside a fresh `bwrap` jail; rows with `oracle = [...]` or `oracle_from` are **sealed** (the engine overlays pinned base-commit directories read-only and seals root test-runner configs `pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini`, `conftest.py`).
  - `kind = "tsv"`: engine-side UTF-8 shape check (`O_NOFOLLOW`, size-capped, `rows_min >= 1`).
  - `kind = "git"`: engine-side diff check against `require` and `forbid` path globs.
  - `kind = "ruling"`: human-signed gate for boundary signoff (never dispatched to an adapter).
  - `control = "<row>"`: twin control row that must pass alongside the primary check.
- **Canonical envelope signing** (`bin/ruling.py`) — signs the full canonical JSON envelope (`schema`, `kind`, `row`, `run`, `not_after`, `signed_at`, `waivers`, `closure_sha`, and full length-prefixed `tree_sha` closure of the program + engine commit). Any unsigned mutation to files, skills, roles, or ruling metadata invalidates the closure before an attempt starts.

### 2. Autonomous Executive — Jailed Seats & Unattended Loop

`bin/run.py loop <program-dir> --run R --interval S` (or `operator run loop ...`) drives the run autonomously until all tasks reach `done`, a terminal circuit breaker trips (`halt`, `STOP`, retry ceiling), or `SIGINT`/`SIGTERM` arrives cleanly between ticks:

1. **Worker turns (`[seat.<w>]`)**: Each attempt gets a fresh 1-commit rootless git checkout (zero commit history, hidden instruction blobs absent unless `repo_context = "load"`), an engine-composed brief with BATS budget awareness and per-turn random `<uf-xxxxxx>` fences, and an adapter jail (`bin/spawn.py`).
2. **Independent reviewer (`[seat.<r>]`)**: After machine checks pass, the reviewer receives a read-only checkout of `candidate/<task>` plus a nonce-fenced pack containing the engine-trusted task specification (`contract.toml` row descriptions outside untrusted spans), candidate diff (`-M90%` rename-aware, verified lockfiles summarised above `PACK_CAP`), untrusted worker self-report, operator-supplied evidence, and contract receipts (`bin/review.py`). Adapter verdicts must prove `doc.seat == reviewer`, `am.seat == doc.seat`, `am.review_turn is True`, `am.candidate == cand_sha`, and `supervisor.rc == 0`.
3. **Autonomous operator (`[seat.op]`)**: In `--autonomy unattended` runs, live escalations (`contract_red`, `needs_input`, `conflict`, `episode`, `gate_refused`, `review_red`) are dispatched to `[seat.op]` outside the tick lock. `[seat.op]` receives a `compose-fence`-protected brief and can emit only whitelisted JSON directives (`retry`, `reply`, `resolve`, `cancel`, `stop`); `review_red` escalations are protected against both `resolve` and autonomous `retry` (and `"red"` reviewer notes are withheld from worker retry briefs).

### 3. Deterministic Judiciary — Enforcement & Capability Guards

Every agent output crosses a deterministic host gate before affecting state or another seat:

```
reserve -> build_attempt -> compose_brief (nonce fence + budget)
  -> bwrap adapter turn (clearenv, unshared net/pid/user, no creds, broker socket)
  -> seal (bwrap git bundle)
  -> import_gate (path grants, modes, size, sensitive paths, 1-commit law)
  -> collect (O_NOFOLLOW, depth/size/UTF-8 caps)
  -> candidate (merge-tree against integration/R, embedded-repo check)
  -> CONTRACT-FIRST GATE (bin/contract.py evaluate_task_machine_rows in bwrap)
       ├── RED   -> write contract.json, emit contract_red escalation,
       │            skip reviewer ($0 review spend), hand to [seat.op]
       └── GREEN -> record hash-chained receipt in <run>/call-log.tsv
                    -> reviewer pack (nonce-fenced + contract receipts)
                    -> reviewer adapter turn -> settle
                    -> DUAL-GATE CAS PROMOTE (review_mod.gate_run AND
                       contract_mod.gate_task_green -> integration/R)
```

- **Contract-First Execution**: Machine-checkable contract rows (`run`, `tsv`, `git`, and twin `control` rows; excluding `ruling` and `driver = "external"`) run immediately after candidacy and **before** `review.dispatch()`. Broken candidates fast-fail without burning reviewer spend, and `spawn._promote()` refuses promotion unless both the review gate and verified call-log receipts for the exact candidate SHA, pin commit, and arm hash are green.
- **Capability Guards on `[seat.op]`**:
  - `resolve` refuses protected terminal/security/ruling escalations (`halt`, `stop`, `security`, `ruling`, `gate_refused`, `retry_cap`), symlinks, and path traversal.
  - `retry` enforces a deterministic per-task retry ceiling (`MAX_TASK_RETRIES`), emitting a protected `retry_cap` escalation and paging when reached.
  - `reply` stamps every op note with an explicit advisory provenance tag (`[op-reply (advisory; ...)]`) and logs `source="op"`.
  - `stop` invokes `cmd_stop()` to terminate live jailed pid namespaces before sealing `STOP`.
  - Executed op turns settle honestly against the ledger (never erased to `$0.0000` on failure or malformed reports) and apply exponential backoff on failing, malformed, or sterile turns.
- **Process, Filesystem & Network Isolation**:
  - `bin/lib/jail.py`: `--clearenv`, unshared mount/pid/net/ipc/uts/cgroup/user namespaces (`--unshare-user --disable-userns`), `--hostname engine-jail`, read-only `/`, `/dev`, and bounded read-only `/usr/local` tmpfs, generated `/etc/{passwd,hosts,machine-id,hostname}`, and `--die-with-parent` (with `spawn.py` and `contract.py` prepending `prlimit` for `FSIZE`, `NPROC`, `core=0`, and configured `AS`).
  - `bin/spawn.py`: engine-owned `<attempt>/report/report.json` backing file copied back with `O_NOFOLLOW` (blocking resumed symlink escapes), symlink-checked `skills`/`home_files`/`must_create`/`repo_config`, and `PostToolUse` data-fence hook (`bin/tool-fence-hook.py`) on hooked CLIs.
  - `bin/broker.py`: Unix-socket LLM proxy injecting credentials outside the jail, stripping client `Authorization`/`x-api-key`/`Accept-Encoding`, enforcing exact routes (`/v1/messages`, `/v1/responses`), streaming usage metering past 64 KiB + non-streaming JSON metering/cap, mid-stream `turn_cap` abort, pre-header concurrency slots (`MAX_CONNS`), and `CLIENT_TIMEOUT`.
  - `bin/egress-proxy.py`: allowlisted HTTPS CONNECT (port 443, SNI verified) and setup-only plain HTTP `GET`/`HEAD` (request bodies refused, unidirectional upstream read), pinned-IP audit logging, and log size cap.
- **Observability & Auditability**:
  - Append-only hash-chained `call-log.tsv` (`bin/call-log.sh`), structured `events.jsonl`, per-attempt `supervisor.json`, `collected.json`, `contract.json`, `out/hook.jsonl`, and a token-guarded loopback panel (`bin/panel.py`) backed by engine CLIs (`status`, `approvals`, `census`) and read-only engine module views (`O_NOFOLLOW` + capped tails).

---

## Security Boundaries & Stated Limits

Every guarantee above is bounded by the explicit threat model in `LIMITATIONS`:

- **Single-UID host trust**: A process running unsandboxed as the same host user as the engine can rewrite engine files. The hash chain detects tampering after the fact; host isolation is the OS boundary.
- **Sealed evidence vs. leakage**: Sealed oracles prevent a worker from modifying or faking test suites, not from solving tests whose contents were already disclosed to it.
- **Prompt injection**: Nonce fences (`bin/compose-fence.py`) and tool hooks (`bin/tool-fence-hook.py`) separate data from instructions at the prompt layer, while deterministic host gates (grants, broker, import gate, contract jails, op capability guards) enforce containment even when a model follows hostile text.
- **Platform**: Linux with working `bubblewrap` and unprivileged user namespaces.

---

## Verification Gates & Ratchets

| Gate | What it proves |
|---|---|
| `test/cleanroom.sh scripts/run-all-selftests.sh` | Every tool's room-safe selftest passes with home hidden, network unshared, and tree read-only. |
| `scripts/run-first-level-selftests.sh` | Live `bwrap` jail arms across `cleanroom`, `contract`, `review`, `run`, `spawn`, `demo`, `fixtures`. |
| `test/cleanroom.sh test/neuter.py` | Mutation-testing ratchet (`test/neuters.py`): breaking any single security or logic guard must kill its suite (`0` survivors). |
| `test/hollow-battery-check.sh` | Real-`pytest` hollow-suite sabotage recipes (runner configs, conftest, skip, delete, symlink-swap) fail under the sealed overlay + `pytest-guard` and pass when unpinned. |
| `test/sealed-probe-check.sh` & `test/forge/sealed.py` | All 5 sealed probes: PID-1 environment cleanliness, hostile bind cleanup, oracle-pin void checks, and process isolation. |
| `scripts/ast-mutants.py` | Deterministic AST mutation generation and strict kill-rate scoring across all 11 TCB control-plane modules listed in `CLAIMS.md`. |
| `test/conformance.sh`, `test/canary-walk.sh`, `test/topology-drill.sh`, `test/fence-placement.sh` | Adapter confinement cells, login-canary isolation, network-topology egress refusal, and hook placement proofs. |
| `scripts/release-lint.py` & `test/ratchet.sh` | Tier-A export hygiene (no host paths, secrets, internal names), `keep-list` sync, and static analysis ratchets. |
