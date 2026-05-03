# QClaw

**Execution firewall for AI coding agents.**

Stop AI agents from deleting the wrong thing.

---

## Demo

```bash
$ qclaw eval "rm -rf fake_prod_db"

  REJECTED
  Risk: destructive (score: 1.00)
  Reasons:
    - recursive deletion detected
    - file removal with force flag
    - deleted files cannot be recovered
```

```bash
$ qclaw run "rmdir /s /q fake_prod_db" --force

  BYPASS - Protection overridden
  Snapshot created: snap_qc_a3f2_1777808344
  Command executed (0.02s)
  WARNING: All protection bypassed. This action is logged.
  Trace: qc_a3f2e255_1777808344
```

```bash
$ qclaw rollback qc_a3f2e255_1777808344

  Restored successfully
  3 files recovered
  Checksum verified
```

```bash
$ qclaw eval "pip install requests"

  ACCEPT
  Risk: safe (score: 0.00)
  Reason: matched trusted dev command allowlist
```

## Install

```bash
pip install qclaw
```

## Why

Cursor, Claude Code, OpenHands, and other AI coding agents can run any shell command. Sometimes they run the wrong one.

Real examples from the field:
- AI deleted the production database
- `docker system prune -a` wiped all containers
- `git push --force` overwrote team history
- `terraform destroy` deleted cloud infrastructure

QClaw intercepts dangerous commands before they run.

## What it does

| Feature | What it means |
|---------|---------------|
| Risk evaluation | Classifies every command: safe / complex / destructive |
| Execution blocking | Destructive commands are rejected with reasons |
| Trusted allowlist | `pip install`, `pytest`, `git status` pass automatically |
| Emergency bypass | `--force` flag overrides protection (logged) |
| Snapshot + rollback | Pre-execution filesystem snapshots, one-command restore |
| Decision trace | Every evaluation is logged and replayable |

## Commands

```bash
qclaw eval "rm -rf /var/data"     # Evaluate risk (no execution)
qclaw run "ls -la"                 # Evaluate + execute
qclaw run --force "rm -rf test"   # Emergency bypass (logged)
qclaw rollback qc_xxx             # Restore from snapshot
qclaw trace qc_xxx                # Replay decision chain
qclaw shell                        # Interactive protected shell
```

## Current limitations

- Filesystem only. No SQL/cloud/k8s rollback.
- Rule-based classifier. No ML (yet).
- No IDE integration. CLI only.

These are intentional scope boundaries, not bugs. If you need more, [open an issue](https://github.com/carefree-xiao/qclaw/issues).

## License

MIT
