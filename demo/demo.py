#!/usr/bin/env python3
"""
QClaw Deterministic Demo — produces identical output every run.
This is the evidence script, not a performance.
"""
import os
import sys
import subprocess
import time

WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QCLAW = [sys.executable, "-X", "utf8", "-m", "qclaw_cli"]

# ── Setup: fake production database ──
FAKE_DB = os.path.join(WORKSPACE, "demo", "fake_prod_db")

def setup_fake_db():
    """Create a realistic-looking fake production database."""
    if os.path.exists(FAKE_DB):
        _cleanup(FAKE_DB)
    os.makedirs(FAKE_DB, exist_ok=True)
    for name in ["customers.db", "orders.db", "transactions.db", "sessions.db"]:
        path = os.path.join(FAKE_DB, name)
        with open(path, "w") as f:
            f.write(f"[MOCK] {name} - not real data\n")
    # Add a subdirectory too
    os.makedirs(os.path.join(FAKE_DB, "backups"), exist_ok=True)
    with open(os.path.join(FAKE_DB, "backups", "2026-04-30.bak"), "w") as f:
        f.write("[MOCK] backup\n")

def _cleanup(path):
    """Remove directory tree."""
    import shutil
    if os.path.exists(path):
        shutil.rmtree(path)

def qclaw_eval(cmd):
    r = subprocess.run(QCLAW + ["eval", cmd], capture_output=True, text=True, cwd=WORKSPACE)
    return r.stdout.strip()

def qclaw_run(cmd):
    r = subprocess.run(QCLAW + ["run", cmd], capture_output=True, text=True, cwd=WORKSPACE)
    return r.stdout.strip()

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

def demo():
    section("[LOCK] QClaw — Execution Firewall for AI Coding Agents")
    print("  AI agents can execute shell commands.")
    print("  QClaw intercepts the dangerous ones.\n")
    time.sleep(0.5)

    # ── Scene 1: Safe command passes ──
    section("Scene 1: Safe command → passes")
    print("  $ qclaw eval \"ls -la\"\n")
    print(qclaw_eval("ls -la"))
    time.sleep(0.3)

    # ── Scene 2: THE "卧槽" moment ──
    section("Scene 2: AI tries to delete production database → BLOCKED")
    setup_fake_db()
    print("  Fake production database created:")
    for f in os.listdir(FAKE_DB):
        print(f"     fake_prod_db/{f}")
    print(f"     fake_prod_db/backups/")
    print()
    print("  AI agent executes:")
    print('  $ qclaw run "rm -rf fake_prod_db"\n')
    print(qclaw_run("rm -rf fake_prod_db"))
    print()
    # Verify data still exists
    if os.path.exists(FAKE_DB):
        print("  [OK] Data still intact — deletion was prevented.")
    else:
        print("  [FAIL] BUG: Data was deleted despite block!")
    time.sleep(0.3)

    # ── Scene 3: Drop table ──
    section("Scene 3: AI tries DROP TABLE → BLOCKED")
    print('  $ qclaw eval "DROP TABLE users"\n')
    print(qclaw_eval("DROP TABLE users"))
    time.sleep(0.3)

    # ── Scene 4: Docker prune ──
    section("Scene 4: AI runs docker system prune → BLOCKED")
    print('  $ qclaw eval "docker system prune -a"\n')
    print(qclaw_eval("docker system prune -a"))
    time.sleep(0.3)

    # ── Scene 5: kubectl delete ──
    section("Scene 5: AI runs kubectl delete → BLOCKED")
    print('  $ qclaw eval "kubectl delete pod --all"\n')
    print(qclaw_eval("kubectl delete pod --all"))
    time.sleep(0.3)

    # ── Scene 6: git push --force ──
    section("Scene 6: AI runs git push --force → BLOCKED")
    print('  $ qclaw eval "git push --force origin main"\n')
    print(qclaw_eval("git push --force origin main"))
    time.sleep(0.3)

    # ── Scene 7: Safe command actually executes ──
    section("Scene 7: Safe command → executes normally")
    print('  $ qclaw run "echo Build complete."\n')
    print(qclaw_run("echo Build complete."))
    time.sleep(0.3)

    # ── Summary ──
    section("Summary")
    print("  Prevent > Recover")
    print("  Stop bad commands before execution.")
    print("  No hooks needed — works with any AI agent.")
    print()
    print("  pip install qclaw")
    print("  qclaw shell")

    # Cleanup
    _cleanup(FAKE_DB)

if __name__ == "__main__":
    demo()
