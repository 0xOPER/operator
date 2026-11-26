# Quickstart

From a clone to a green run. Every command here is real; run them in order. If
something refuses, the refusal names its fix -- read the second line.

## 0. Requirements

- **Linux (native, recommended):** Python 3.11+, `python3-venv`, `git`,
  `openssh-client` (`ssh-keygen`), `pytest`, and `bubblewrap` (`bwrap --version`).
  On Ubuntu 24.04+, unprivileged user namespaces are restricted by AppArmor by
  default. Install a targeted profile for `bwrap` (recommended, survives reboots):

  ```bash
  sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'
  abi <abi/4.0>,
  include <tunables/global>

  profile bwrap /usr/bin/bwrap flags=(unconfined) {
    userns,
    include if exists <local/bwrap>
  }
  EOF
  sudo apparmor_parser -r /etc/apparmor.d/bwrap
  ```

  *(For quick testing only, `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
  also works, but it relaxes the setting system-wide and resets on reboot.)*
- **macOS (Docker Desktop / Colima / OrbStack VM):** run commands through the
  included Linux + `bubblewrap` container wrapper (`scripts/docker-operator.sh`).
  Persists state in `0700` `~/.local/state/operator-docker` by default. Because
  nested `bubblewrap` inside a container needs `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`,
  and unconfined seccomp/AppArmor/systempaths, the wrapper refuses native Linux
  unless `--allow-linux-unconfined` is passed (on macOS, the Linux hypervisor VM
  is the outer boundary):
  ```bash
  scripts/docker-operator.sh               # builds once and runs `demo run`
  scripts/docker-operator.sh doctor        # check environment inside container
  scripts/docker-operator.sh --publish-panel --mount "$PWD" status
  ```
  To run your own program directory and work repo from macOS, mount both
  paths into the container and pass the mounted paths positionally (only
  `/operator-state` persists inside the container image):
  ```bash
  scripts/docker-operator.sh --mount "$PWD/myteam:/work/myteam" \
    --mount "/path/to/work-repo:/work/repo" \
    init /work/myteam --template feature
  scripts/docker-operator.sh --mount "$PWD/myteam:/work/myteam" \
    team validate /work/myteam
  ```
- An agent CLI if you want real workers (`claude`, `codex`, `opencode`, or
  `zcode` on `PATH` or under `OPERATOR_CLI_DIR/bin`). Without one, the `stub`
  adapter still walks the engine using `plans/<task>.json`.

## 1. The demo (under a minute)

```bash
bin/operator.sh demo run
```

Two stub seats promote candidate work through sealed checks, an outside write fails to land while an allowed write lands, and the egress fence proves itself against a local listener. It prints a one-line summary and cleans up its temporary directory (no credentials, no risk). For the full live-jail tick, reservation, and review ladder, run `scripts/run-first-level-selftests.sh`.

## 2. The front door

```bash
bin/operator.sh doctor      # what's installed, what's missing, the next step
bin/operator.sh status      # the run ledger once runs exist
bin/operator.sh help        # every tool behind the one entry point
```

## 3. A program of your own

A *program* is a directory holding a team, a contract and role files.

```bash
bin/operator.sh init myteam --template feature
```

Stay in the repository root and pass `myteam` positionally to every verb (`init` writes only `team.toml`, `contract.toml`, and `roles/`—no `bin/`). You get a one-writer, one-reviewer team to edit, not a blank file. The authoring guide ([authoring.md](authoring.md)) walks every field; the minimum:

- `team.toml`: each seat's role file, adapter, optional `model` (BYO model ID
  overriding the adapter manifest's `default_model`), what it may `write`, and a
  budget. Point `adapter` at a real CLI (`claude-code`, `codex`, `opencode`,
  `zcode`) when you have the CLI; `stub` is fine to learn.
- `contract.toml`: rows naming `cmd` checks. **A check that cannot fail is a
  lie**; `bin/operator.sh contract lint` refuses trivial commands, `|| true` / `true ||`
  short-circuits, dummy `test -f` stats on unsealed paths, and unanchored
  `control` twins. Rows with the same seat, stage and deps form one task.

```bash
bin/operator.sh team validate myteam
bin/operator.sh contract validate myteam
```

## 4. Arm it

Nothing runs until a signed ruling says so -- the engine refuses an unarmed
program by name. Make a passphrase-protected signing key once, register its
public half, then sign the closure:

```bash
ssh-keygen -t ed25519 -N 'a passphrase you keep' -f ~/myteam-key
bin/operator.sh init myteam --key ~/myteam-key     # the private half's path;
                                                   # the .pub must sit beside it
CONTRACT_REPO=/path/to/work-repo bin/operator.sh ruling closure myteam
CONTRACT_REPO=/path/to/work-repo bin/operator.sh ruling sign myteam --kind arm --key ~/myteam-key
```

Pass `CONTRACT_REPO` when signing so the closure pins the work repository's base
commit. If your team defines a `budget.usd` cap (all shipped templates do),
pass `--waive budget=advisory` (the cap gates the next reservation; an in-flight
attempt may overshoot up to its reservation/turn cap, and USD is estimated from
`broker.py`'s model price table). Pass `--waive same-family-review` only if your
worker and reviewer intentionally share the same model family. The key refuses
to be plain (`-N ''`) -- a signing key without a passphrase protects nothing
that outlives a session. Signing prompts for the passphrase; `ssh-agent` or
`$SSH_ASKPASS` carries it if you'd rather not type it each time.

## 5. Run it

```bash
# With stub adapters (no API key needed; requires plans/<task>.json in myteam/):
bin/operator.sh run start myteam --run r1 --autonomy attended --from /path/to/work-repo
bin/operator.sh run tick myteam --run r1     # dispatch, collect, review, settle

# With real CLIs (single-origin or multi-provider; real keys stay host-side in broker.py):
OPERATOR_CLI_DIR=/usr/local \
OPERATOR_ANTHROPIC_ORIGIN=https://api.example.com \
OPERATOR_ANTHROPIC_CREDENTIAL="$YOUR_ANTHROPIC_KEY" \
OPERATOR_OPENAI_ORIGIN=https://api.example.com \
OPERATOR_OPENAI_CREDENTIAL="$YOUR_OPENAI_KEY" \
  bin/operator.sh run loop myteam --run r1   # unattended ticks until done/halt

bin/operator.sh status r1 --json
bin/operator.sh run next myteam --run r1     # what the engine wants next, and why
```

Each tick drives the ladder for every ready task -- reserve (the reservation
settles ALWAYS; a worker's claimed cost is a hint), the seat's adapter turn
in its jail (no network, no credentials, the repo sparse to what the seat may
see), seal, the import gate, the reviewer's verdict (an adapter reviewer
verdicts in its own turn; a HUMAN reviewer waits on the approvals screen),
and promote. Repeat `tick` until `next` says done. Stub seats take their
steps from `plans/<task>.json` in the program dir (engine-side authoring,
never worker input); real CLI seats take the composed brief.

## 5a. Real CLIs, turn caps, and the pager

Before spending API credits on a real CLI run:

1. **Preflight each adapter binary:**
   ```bash
   bin/operator.sh spawn preflight claude-code   # probes binary + version floor (--strict for exact pin)
   bin/operator.sh spawn preflight codex
   ```
   Tested CLI versions in `config/adapters/*.toml`: `claude-code` (`2.1.318`,
   `tool_fencing = "hooked"`), `codex` (`0.166.0`, `"unfenced"`), `opencode`
   (`1.19.5`, `"unfenced"`), and `zcode` (`0.17.1`, `"hooked"`, experimental /
   not run in CI). Inside the jail, wrapped CLIs run with their own internal
   guardrails relaxed because the `bubblewrap` jail, host API broker, and Git
   import gate enforce confinement externally.
2. **Provider credentials (host-side only):** Set the provider origin and key
   on the host when launching `run tick` or `run loop`; `run.py` auto-supervises
   `broker.py` on `/tmp/opb-*/b.sock` so real keys never enter the jail:
   - Anthropic: `OPERATOR_ANTHROPIC_ORIGIN`, `OPERATOR_ANTHROPIC_CREDENTIAL`
   - OpenAI: `OPERATOR_OPENAI_ORIGIN`, `OPERATOR_OPENAI_CREDENTIAL`
   - ZCode (`zcode`): `OPERATOR_ZAI_ORIGIN`, `OPERATOR_ZAI_CREDENTIAL`
   - Single-origin fallback: `OPERATOR_BROKER_ORIGIN`, `OPERATOR_BROKER_CREDENTIAL`
3. **Per-attempt turn ceilings:** Override the default host-side per-attempt
   broker limits if needed:
   - `OPERATOR_TURN_USD_CAP` (default `10.00`, estimated from `broker.py`'s model price table)
   - `OPERATOR_TURN_INPUT_CAP` (default `500000` input tokens)
4. **Unattended `[seat.op]` & pager notifications:** Add a `[seat.op]` block to
   `team.toml` using an adapter that sets `report_mount` (`claude-code`,
   `opencode`, or `zcode`; see [authoring.md](authoring.md)). On a halt or
   all-escalated pause, the engine writes a row to `<run>/pages.tsv` by default;
   set `OPERATOR_PAGER_COMMAND` to pipe the alert message to an external notifier
   on stdin.
5. **Disk space & cleanup:** Runs live under `$OPERATOR_HOME` (default
   `~/.local/state/operator`), and each run holds a full clone of the work
   repository. Reclaim finished runs with `bin/operator.sh run gc <run>`.

## 6. The loop in under a minute (the demo)

```bash
bin/operator.sh demo run --keep demo-keep
OPERATOR_HOME=demo-keep/home bin/operator.sh panel render --run demo-run
```

The demo exercises stub seats, sealed contract checks, and the network fence, and `--keep` preserves its run directory so `status --json`, `approvals`, and `panel render` can read it back (`demo run` itself deletes its temp directory unless `--keep` is passed).

Watch your own run live:

```bash
bin/operator.sh panel serve --run r1         # http://127.0.0.1:8765
```

The panel is a VIEW: it renders `run.py status --json` and `approvals --json`
exactly, and its buttons run exactly four engine verbs (`stop`, `resume`,
`cancel`, `reply`). Verdicts and signatures stay in the CLI.

## 7. When a human is needed

```bash
bin/operator.sh run approvals            # everything waiting on you, each with its fix
bin/operator.sh run reply r1 impl --note answer.md
bin/operator.sh review pack <attempt>    # the reviewer's capped, fenced diff
bin/operator.sh review verdict r1 impl --by reviewer --green --key ~/myteam-key
```

A reviewed row delivers NOTHING until its reviewer passes it: green, signed,
and current -- a verdict naming yesterday's candidate is stale and certifies
nothing. Red refuses with the attempt standing as evidence; `--changes` sends
it back with the prior round riding the next pack.

## 8. Done

When every stage of your own run is green -- the demo's kept run shows the
shape on its panel: promoted chips and a settled budget dock:

```bash
bin/operator.sh run status r1 --json     # state: done
bin/operator.sh run report myteam --run r1    # the claims summary, on the record
```

What 0.1 does not claim -- told vectors, under-test detection, the rest -- is
stated plainly in [../LIMITATIONS](../LIMITATIONS). Read it before you trust a
green.
