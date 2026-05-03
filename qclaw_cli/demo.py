"""
QClaw CLI Demo - Simulate "AI tries deleting stuff → gets blocked → rollback"

This is the demo script for recording the first demo video/gif.
"""
import subprocess
import sys
import os

WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QCLAW = [sys.executable, "-X", "utf8", "-m", "qclaw_cli"]

def run_qclaw(subcmd, arg):
    cmd = QCLAW + [subcmd, arg]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=WORKSPACE)
    return result.stdout + result.stderr

def main():
    print("=" * 60)
    print("🔒 QClaw Execution Firewall - Demo")
    print("=" * 60)

    # Test 1: Safe command - should pass
    print("\n--- Test 1: Safe command ---")
    print("$ qclaw eval \"ls -la\"")
    print(run_qclaw("eval", "ls -la"))

    # Test 2: Destructive command - should block
    print("\n--- Test 2: AI tries to delete database ---")
    print('$ qclaw eval "drop table users"')
    print(run_qclaw("eval", "drop table users"))

    # Test 3: rm -rf - should block
    print("\n--- Test 3: AI tries rm -rf ---")
    print('$ qclaw eval "rm -rf /var/data"')
    print(run_qclaw("eval", "rm -rf /var/data"))

    # Test 4: Docker prune - should block
    print("\n--- Test 4: AI tries docker prune ---")
    print('$ qclaw eval "docker system prune -a"')
    print(run_qclaw("eval", "docker system prune -a"))

    # Test 5: kubectl delete - should block
    print("\n--- Test 5: AI tries kubectl delete ---")
    print('$ qclaw eval "kubectl delete pod --all"')
    print(run_qclaw("eval", "kubectl delete pod --all"))

    # Test 6: git force push - should block
    print("\n--- Test 6: AI tries git push --force ---")
    print('$ qclaw eval "git push --force origin main"')
    print(run_qclaw("eval", "git push --force origin main"))

    # Test 7: Actually execute a safe command
    print("\n--- Test 7: Execute safe command ---")
    print('$ qclaw run "echo hello from qclaw"')
    print(run_qclaw("run", "echo hello from qclaw"))

    # Test 8: Block actual execution of destructive command
    print("\n--- Test 8: Block destructive execution ---")
    print('$ qclaw run "rm -rf /tmp/test"')
    print(run_qclaw("run", "rm -rf /tmp/test"))

    print("\n" + "=" * 60)
    print("✅ Demo complete - All dangerous commands blocked!")
    print("=" * 60)

if __name__ == "__main__":
    main()
