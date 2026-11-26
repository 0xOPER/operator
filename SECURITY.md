# Security Policy

## Supported Versions

Security fixes are maintained for the current `0.1.x` release line on `main`.

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security reports.

Use GitHub's [Private Vulnerability Reporting](https://github.com/0xOPER/operator/security/advisories/new) on `0xOPER/operator` to send a confidential report directly to the maintainers. Include:

- A description of the boundary violation (for example: sandbox escape, ungranted file write, credential leak, test-seal bypass, or reviewer/operator privilege escalation).
- Minimal reproduction steps or a failing test fixture.
- Environment details (Linux distribution, kernel version, `bwrap --version`, Python version, and adapter CLI if relevant).

We aim to acknowledge reports within 48 hours and coordinate a fix and disclosure timeline with you before publishing an advisory.

## Security Scope

OPERATOR enforces deterministic host-side boundaries around untrusted coding-agent turns. The following boundaries are **in scope**:

- **Sandbox confinement (`bin/lib/jail.py`, `bin/spawn.py`)**: Network isolation, read-only host filesystem, hidden home directory, PID/mount/user namespace isolation, and bounded write grants.
- **Credential & egress isolation (`bin/broker.py`, `bin/egress-proxy.py`)**: Keeping real API keys outside the worker jail, enforcing API routes and usage/budget caps, and blocking unauthorized outbound traffic.
- **Sealed test verification (`bin/contract.py`, `bin/lib/pytest-guard.py`)**: Preventing workers from modifying pinned test suites, runner configs, or forging passing check receipts.
- **Independent review & `[seat.op]` capability guards (`bin/review.py`, `bin/run.py`, `bin/ruling.py`)**: Enforcing signed closure rulings, cross-family review requirements, and hard host-side blocks on protected escalations (`review_red`, `gate_refused`, `retry_cap`, `halt`, `security`, `ruling`).
- **Prompt boundary fencing (`bin/compose-fence.py`, `bin/untrusted-span-fence.py`, `bin/tool-fence-hook.py`)**: Isolating untrusted worker output and tool results from trusted contract specifications.

## Stated Out-of-Scope Boundaries

As documented plainly in [LIMITATIONS](LIMITATIONS):

- **Same-UID host processes**: OPERATOR trusts the host OS account running the engine. An unsandboxed process running as the same local user can modify local state or logs (the hash-chained `call-log.tsv` detects corruption or truncation rather than preventing same-user host writes).
- **Disclosed hidden test vectors**: Sealed test suites prevent tampering, not solving tests whose expected vectors were already provided to the worker.
- **Linux kernel / `bubblewrap` bugs**: Shared-kernel isolation relies on Linux namespaces and `bubblewrap`; on macOS, isolation runs inside the Linux guest VM via `scripts/docker-operator.sh`.
- **Under-test detection**: A worker can observe jail mount shapes or timing; enforcement lives host-side rather than relying on stealth.
