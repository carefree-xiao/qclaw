# qclaw

**Prevent AI agents from deleting the wrong thing.**

Cursor, Claude Code, OpenHands, and other AI coding agents can execute destructive shell commands. QClaw intercepts dangerous commands before they run.

## Problem

AI coding agents sometimes execute commands they shouldn't:
- `rm -rf` on the wrong directory
- `DROP TABLE` on production databases
- `docker system prune -a` wiping all containers
- `git push --force` overwriting team history
- `terraform destroy` deleting cloud infrastructure

These happen because agents have no risk awareness. QClaw adds it.

## Quick Start

```bash
pip install -e .
qclaw shell
```

## Commands

### Evaluate risk (no execution)
```bash
qclaw eval "rm -rf /var/data"
# X BLOCKED
#   Risk: destructive (score: 1.00)
#   Reasons:
#     - recursive deletion detected
#     - file removal with force flag
#     - deleted files cannot be recovered
#   Use --force to bypass (logged)
```

### Execute with guardrails
```bash
qclaw run "ls -la"
# >> ACCEPT
#   Risk: safe (score: 0.00)
#   Reasons:
#     - matched trusted dev command allowlist
#   Success (0.01s)

qclaw run "pip install requests"
# >> ACCEPT — trusted developer command
```

### Emergency bypass
```bash
qclaw run --force "rm -rf test_dir"
# !! BYPASS - Protection overridden
#   WARNING: All protection bypassed. This action is logged.
```

In shell mode, prefix with `!`:
```
qclaw> !rm -rf test_dir
```

### Replay decision trace
```bash
qclaw trace qc_7a89d0f9_1777735522
# Trace: qc_7a89d0f9_1777735522
#   Command:  rm -rf /var/data
#   Risk:     destructive (score: 1.00)
#   Decision: REJECT
#   Details:
#     - recursive deletion detected
#     - file removal with force flag
#     - deleted files cannot be recovered
```

### Interactive protected shell
```bash
qclaw shell
# All commands are evaluated before execution.
# Prefix ! to bypass protection (logged).
```

## How It Works

```
AI agent command
  1. Trusted dev command? → ACCEPT (pip install, pytest, git status, etc.)
  2. Destructive pattern?  → BLOCK with reasons (rm -rf, DROP TABLE, etc.)
  3. Risky pattern?        → UPGRADE to COMPLEX (git push, docker run, etc.)
  4. Rule-based classifier + risk scorer → ACCEPT / RETRY / BLOCK
  5. Every decision is traced and replayable
```

## Trusted Developer Commands

These always pass — zero evaluation needed:

| Command | Why safe |
|---------|----------|
| `pip install`, `npm install`, `yarn install` | Adds dependencies, read-only to the world |
| `pytest`, `jest`, `ruff`, `eslint`, `mypy` | Test/lint, no side effects |
| `git status`, `git log`, `git pull`, `git diff` | Read-only git operations |
| `docker ps`, `docker logs`, `kubectl get` | Read-only container/k8s queries |
| `ls`, `cat`, `grep`, `find`, `echo` | Filesystem reads and prints |

## What Gets Blocked

| Pattern | Reasons |
|---------|---------|
| `rm -rf` | Recursive deletion, force flag, irreversible |
| `DROP TABLE` | SQL destructive, permanent data loss |
| `docker system prune` | Removes all unused containers/images/volumes |
| `git push --force` | Overwrites remote history, others' commits may be lost |
| `kubectl delete` | Deletes k8s resources, may affect production |
| `terraform destroy` | Destroys all managed cloud infrastructure |
| `shutdown`, `reboot` | System power off/restart |
| `kill -9`, `pkill -9` | Forceful termination without cleanup |

Full list: `qclaw_core/policies/command_patterns.py`

## Architecture

QClaw reuses proven components from the Emora decision system:

- **policies/command_patterns.py** — Single source of truth: trusted allowlist + destructive patterns + risky patterns
- **risk_types.py** — Rule-based risk classifier (bilingual: English + Chinese)
- **risk_scorer.py** — Numerical risk scoring with confidence + failure history
- **snapshot_manager.py** — Pre-execution filesystem snapshots for rollback
- **cli.py** — Thin CLI layer, all policy logic in qclaw_core

No hooks needed. Works with any AI agent that runs shell commands.

## Demo

```bash
python demo/demo.py
```

Creates a fake production database, then shows QClaw blocking its deletion. Deterministic output — same result every run.

## License

MIT
