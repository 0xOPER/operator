# Quickstart

From a clone to a green run. Every command here is real; run them in order. If
something refuses, the refusal names its fix -- read the second line.

## 0. Requirements

- **Linux (native, recommended):** `bubblewrap` (`bwrap --version`). On Ubuntu
  24.04+, either install a targeted `/etc/apparmor.d/bwrap` `userns` profile or
  enable unprivileged userns (`sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`).
- **macOS (Docker Desktop / Colima / OrbStack VM):** run commands through the
  included Linux + `bubblewrap` container wrapper (persists state in `0700`
  `~/.local/state/operator-docker` by default; refused on native Linux unless
  `--allow-linux-unconfined` is passed because nested `bwrap` requires
  unconfined container flags inside the Linux guest VM):
  ```bash
  scripts/docker-operator.sh               # builds once and runs `demo run`
  scripts/docker-operator.sh doctor        # check environment inside container
  scripts/docker-operator.sh --publish-panel --mount "$PWD" status
  ```
- An agent CLI if you want real workers (`claude`, `codex`, `opencode`, or
  `zcode` on `PATH` or under `OPERATOR_CLI_DIR/bin`). Without one, the `stub`
  adapter still walks the whole engine.

## 1. The demo (under a minute)

```bash
bin/operator.sh demo run
```

Two stub seats go from reserve to promoted, a forged claim refuses, an outside
write refuses, and the network fence proves itself. This is the whole loop
with no credentials and no risk.

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
cd myteam
```

You get `team.toml`, `contract.toml` and `roles/` -- a one-writer, one-reviewer
team to edit, not a blank file. The authoring guide
([authoring.md](authoring.md)) walks every field; the minimum:

- `team.toml`: each seat's role file, adapter, optional `model` (BYO model ID
  overriding the adapter manifest's `default_model`), what it may `write`, and a
  budget. Point `adapter` at a real CLI (`claude-code`, `codex`, `opencode`,
  `zcode`) when you have the CLI; `stub` is fine to learn.
- `contract.toml`: rows naming `cmd` checks. **A check that cannot fail is a
  lie**; `operator contract lint` refuses trivial commands, `|| true` / `true ||`
  short-circuits, dummy `test -f` stats on unsealed paths, and unanchored
  `control` twins. Rows with the same seat, stage and deps form one task.

```bash
bin/operator.sh team validate .
bin/operator.sh contract validate .
```

## 4. Arm it

Nothing runs until a signed ruling says so -- the engine refuses an unarmed
program by name. Make a passphrase-protected signing key once, register its
public half, then sign the closure:

```bash
ssh-keygen -t ed25519 -N 'a passphrase you keep' -f ~/myteam-key
bin/operator.sh init . --key ~/myteam-key     # the private half's path;
                                                   # the .pub must sit beside it
CONTRACT_REPO=/path/to/work-repo bin/operator.sh ruling closure .
CONTRACT_REPO=/path/to/work-repo bin/operator.sh ruling sign . --kind arm --key ~/myteam-key
```

Pass `CONTRACT_REPO` when signing so the closure pins the work repository's base
commit (and pass `--waive same-family-review` only if your worker and reviewer
intentionally share the same model family). The key refuses to be plain
(`-N ''`) -- a signing key without a passphrase protects nothing that outlives a
session. Signing prompts for the passphrase; `ssh-agent` or `$SSH_ASKPASS`
carries it if you'd rather not type it each time.

## 5. Run it

```bash
# With stub adapters (no API key needed):
bin/operator.sh run start . --run r1 --autonomy attended --from /path/to/work-repo
bin/operator.sh run tick . --run r1          # dispatch, collect, review, settle

# With real CLIs (single-origin or multi-provider; real keys stay host-side in broker.py):
OPERATOR_CLI_DIR=/usr/local \
OPERATOR_ANTHROPIC_ORIGIN=https://api.example.com \
OPERATOR_ANTHROPIC_CREDENTIAL="$YOUR_ANTHROPIC_KEY" \
OPERATOR_OPENAI_ORIGIN=https://api.example.com \
OPERATOR_OPENAI_CREDENTIAL="$YOUR_OPENAI_KEY" \
  bin/operator.sh run loop . --run r1        # unattended ticks until done/halt

bin/operator.sh status r1 --json
bin/operator.sh run next . --run r1          # what the engine wants next, and why
```

Each tick drives the ladder for every ready task -- reserve (the reservation
settles ALWAYS; a worker's claimed cost is a hint), the seat's adapter turn
in its jail (no network, no credentials, the repo sparse to what the seat may
see), seal, the import gate, the reviewer's verdict (an adapter reviewer
verdicts in its own turn; a HUMAN reviewer waits on the approvals screen),
and promote. Repeat `tick` until `next` says done. Stub seats take their
steps from `plans/<task>.json` in the program dir (engine-side authoring,
never worker input); real CLI seats take the composed brief.

## 6. The loop in under a minute (the demo)

```bash
bin/operator.sh demo run --keep demo-keep
OPERATOR_HOME=demo-keep/home bin/operator.sh panel render --run demo-run
```

The demo walks the whole engine on stub seats -- two go from reserve to
promoted, a forged claim refuses, an outside write refuses -- and `--keep`
preserves its run dir so everything you just learned (`status --json`,
`approvals`, the panel) reads it back. Each attempt was budgeted, jailed,
sealed, gated and reviewed before anything promoted.

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
bin/operator.sh run report . --run r1    # the claims summary, on the record
```

What 0.1 does not claim -- told vectors, under-test detection, the rest -- is
stated plainly in [../LIMITATIONS](../LIMITATIONS). Read it before you trust a
green.
