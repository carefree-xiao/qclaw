#!/usr/bin/env python3
"""
qclaw - Execution Firewall for AI Coding Agents

Prevent AI agents from making destructive changes.

Usage:
    qclaw run "rm -rf /tmp/test"       # Evaluate and execute a command
    qclaw eval "drop table users"       # Evaluate risk only (no execution)
    qclaw trace <trace_id>              # Replay decision chain
    qclaw shell                         # Interactive protected shell
"""
import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime

from qclaw_core.risk_types import classify_risk, risk_to_decision, get_risk_explanation, RiskType
from qclaw_core.risk_scorer import compute_risk_score, risk_to_action
from qclaw_core.snapshot import SnapshotManager
from qclaw_core.policies import check_trusted, check_destructive, check_risky


# ── ANSI colors ──
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# ── Trace storage ──
WORKSPACE = os.getcwd()
TRACE_DIR = os.path.join(WORKSPACE, "data", "qclaw_traces")
os.makedirs(TRACE_DIR, exist_ok=True)

_snapshot_mgr = SnapshotManager()


def _save_trace(trace: dict) -> str:
    """Save trace to JSONL file."""
    date_str = datetime.now().strftime("%Y-%m-%d")
    trace_file = os.path.join(TRACE_DIR, f"traces_{date_str}.jsonl")
    with open(trace_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(trace, ensure_ascii=False) + "\n")
    return trace["trace_id"]


def _load_trace(trace_id: str) -> dict | None:
    """Load a trace by ID."""
    for fname in os.listdir(TRACE_DIR):
        if not fname.endswith(".jsonl"):
            continue
        fpath = os.path.join(TRACE_DIR, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    t = json.loads(line.strip())
                    if t.get("trace_id") == trace_id:
                        return t
                except json.JSONDecodeError:
                    continue
    return None


def _extract_affected_paths(command: str) -> list[str]:
    """Best-effort extraction of file paths from a command."""
    paths = []
    tokens = command.split()
    for token in tokens:
        if token.startswith(("-", "/", "~", ".", "\\")):
            if not token.startswith("--"):
                continue
        if os.path.exists(token):
            paths.append(os.path.abspath(token))
    return paths


# ── Risk explanation (English, for output) ───────────────────────────────────

_RISK_EXPLANATIONS_EN = {
    RiskType.DESTRUCTIVE: "Destructive action - data loss or system damage risk",
    RiskType.IRREVERSIBLE: "Irreversible action - cannot be rolled back",
    RiskType.UNCERTAIN: "Insufficient information - cannot make reliable judgment",
    RiskType.COMPLEX: "Complex operation - requires step-by-step verification",
    RiskType.SAFE: "Low risk - safe to execute",
}


def evaluate_command(command: str) -> dict:
    """
    Core evaluation: command -> risk assessment.

    Policy evaluation order:
      1. Trusted dev commands -> force SAFE
      2. Destructive patterns -> force BLOCK (with specific reasons)
      3. Risky patterns -> upgrade to COMPLEX
      4. Fall through to rule-based classifier + risk scorer

    Returns:
        dict with risk_type, risk_score, decision, explanation, reasons, trace_id
    """
    trace_id = f"qc_{uuid.uuid4().hex[:8]}_{int(time.time())}"
    reasons = []

    # ── Policy Layer 1: Trusted developer commands ──
    if check_trusted(command):
        trace = {
            "trace_id": trace_id,
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "risk_type": "safe",
            "risk_score": 0.0,
            "decision": "ACCEPT",
            "explanation": "Trusted developer command",
            "reasons": ["matched trusted dev command allowlist"],
        }
        _save_trace(trace)
        return {
            "trace_id": trace_id,
            "command": command,
            "risk_type": "safe",
            "risk_score": 0.0,
            "decision": "ACCEPT",
            "explanation": "Trusted developer command",
            "reasons": ["matched trusted dev command allowlist"],
        }

    # ── Policy Layer 2: Destructive patterns (always BLOCK) ──
    destructive_reasons = check_destructive(command)
    if destructive_reasons:
        trace = {
            "trace_id": trace_id,
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "risk_type": "destructive",
            "risk_score": 1.0,
            "decision": "REJECT",
            "explanation": "Destructive action - data loss or system damage risk",
            "reasons": destructive_reasons,
        }
        _save_trace(trace)
        return {
            "trace_id": trace_id,
            "command": command,
            "risk_type": "destructive",
            "risk_score": 1.0,
            "decision": "REJECT",
            "explanation": "Destructive action - data loss or system damage risk",
            "reasons": destructive_reasons,
        }

    # ── Policy Layer 3: Risky patterns → upgrade to COMPLEX ──
    base_risk = classify_risk(command, "shell_command")
    if check_risky(command):
        if base_risk == RiskType.SAFE:
            base_risk = RiskType.COMPLEX
            reasons.append("matched risky command pattern")

    # ── Policy Layer 4: Rule-based classifier + risk scorer ──
    risk_score = compute_risk_score(
        risk_type=base_risk.value,
        goal=command,
    )

    action = risk_to_action(risk_score)

    # Override: IRREVERSIBLE always blocked
    if base_risk == RiskType.IRREVERSIBLE:
        action = "REJECT"

    explanation = _RISK_EXPLANATIONS_EN.get(base_risk, get_risk_explanation(base_risk))

    trace = {
        "trace_id": trace_id,
        "timestamp": datetime.now().isoformat(),
        "command": command,
        "risk_type": base_risk.value,
        "risk_score": round(risk_score, 4),
        "decision": action,
        "explanation": explanation,
        "reasons": reasons,
    }
    _save_trace(trace)

    return {
        "trace_id": trace_id,
        "command": command,
        "risk_type": base_risk.value,
        "risk_score": round(risk_score, 4),
        "decision": action,
        "explanation": explanation,
        "reasons": reasons,
    }


def _print_reasons(reasons: list[str]) -> None:
    """Print human-readable reasons for a decision."""
    if not reasons:
        return
    for r in reasons:
        print(f"    - {r}")


def execute_command(command: str, auto_approve_safe: bool = True, force: bool = False) -> dict:
    """
    Evaluate + execute a command with safety guardrails.

    Flow:
        classify -> score -> decide -> (snapshot if risky) -> execute -> trace

    Args:
        command: Shell command to evaluate and potentially execute.
        auto_approve_safe: If True, auto-approve ACCEPT decisions without prompt.
        force: If True, bypass all protection (emergency override). Logged.
    """
    # ── Emergency bypass ──
    if force:
        trace_id = f"qc_{uuid.uuid4().hex[:8]}_{int(time.time())}"
        print(f"\n{C.YELLOW}{C.BOLD}!! BYPASS - Protection overridden{C.RESET}")
        print(f"  Command: {C.YELLOW}{command}{C.RESET}")
        print(f"  {C.RED}WARNING: All protection bypassed. This action is logged.{C.RESET}")

        # ── Create snapshot before execution (filesystem only) ──
        snapshot_id = None
        affected = _extract_affected_paths(command)
        if affected:
            snap = _snapshot_mgr.create(trace_id, affected, mock=False)
            if snap:
                snapshot_id = snap.snapshot_id
                print(f"  {C.BLUE}Snapshot: {snapshot_id}{C.RESET} ({snap.file_count} files)")
            else:
                print(f"  {C.YELLOW}Snapshot failed - no rollback available{C.RESET}")
        else:
            print(f"  {C.DIM}No target paths detected - rollback unavailable{C.RESET}")

        # Execute directly
        start = time.time()
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30, cwd=WORKSPACE,
            )
            elapsed = time.time() - start

            result = {
                "trace_id": trace_id,
                "command": command,
                "risk_type": "bypass",
                "risk_score": -1,
                "decision": "BYPASS",
                "explanation": "Emergency bypass - protection overridden by user",
                "reasons": ["--force flag used"],
                "executed": True,
                "execution_output": proc.stdout[:2000] if proc.stdout else None,
                "execution_error": proc.stderr[:2000] if proc.stderr else None,
                "exit_code": proc.returncode,
                "elapsed_sec": round(elapsed, 2),
                "snapshot_id": snapshot_id,
                "rollback_available": snapshot_id is not None,
            }

            if proc.returncode == 0:
                print(f"  {C.GREEN}Success{C.RESET} ({elapsed:.2f}s)")
                if proc.stdout and proc.stdout.strip():
                    for line in proc.stdout.strip().split("\n")[:5]:
                        print(f"    {C.DIM}{line[:100]}{C.RESET}")
            else:
                print(f"  {C.RED}Failed{C.RESET} (exit {proc.returncode}, {elapsed:.2f}s)")
                if proc.stderr and proc.stderr.strip():
                    for line in proc.stderr.strip().split("\n")[:3]:
                        print(f"    {C.RED}{line[:100]}{C.RESET}")

        except subprocess.TimeoutExpired:
            result = {
                "trace_id": trace_id, "command": command, "risk_type": "bypass",
                "risk_score": -1, "decision": "BYPASS",
                "explanation": "Emergency bypass - protection overridden by user",
                "reasons": ["--force flag used"],
                "executed": False, "execution_error": "timeout (30s)",
            }
            print(f"  {C.RED}Timeout (30s){C.RESET}")

        print(f"  Trace:   {C.DIM}{trace_id}{C.RESET}")
        _save_trace(result)
        return result

    # ── Normal evaluation ──
    eval_result = evaluate_command(command)
    trace_id = eval_result["trace_id"]
    decision = eval_result["decision"]
    reasons = eval_result.get("reasons", [])

    result = {
        **eval_result,
        "executed": False,
        "execution_output": None,
        "execution_error": None,
        "snapshot_id": None,
        "rollback_available": False,
    }

    # BLOCKED
    if decision == "REJECT":
        print(f"\n{C.RED}{C.BOLD}X BLOCKED{C.RESET}")
        print(f"  Command: {C.YELLOW}{command}{C.RESET}")
        print(f"  Risk:    {C.RED}{eval_result['risk_type']}{C.RESET} (score: {eval_result['risk_score']:.2f})")
        if reasons:
            print(f"  Reasons:")
            _print_reasons(reasons)
        else:
            print(f"  Reason:  {eval_result['explanation']}")
        print(f"  Trace:   {C.DIM}{trace_id}{C.RESET}")
        print(f"  {C.DIM}Use --force to bypass (logged){C.RESET}")
        return result

    # RETRY → dry-run mode (execute with snapshot for rollback)
    if decision == "RETRY":
        print(f"\n{C.YELLOW}{C.BOLD}! RETRY (dry-run with snapshot){C.RESET}")
        print(f"  Command: {C.YELLOW}{command}{C.RESET}")
        print(f"  Risk:    {C.YELLOW}{eval_result['risk_type']}{C.RESET} (score: {eval_result['risk_score']:.2f})")
        if reasons:
            print(f"  Reasons:")
            _print_reasons(reasons)
        else:
            print(f"  Reason:  {eval_result['explanation']}")

        # Create snapshot
        affected = _extract_affected_paths(command)
        if affected:
            snap = _snapshot_mgr.create(trace_id, affected, mock=False)
            if snap:
                result["snapshot_id"] = snap.snapshot_id
                result["rollback_available"] = True
                print(f"  Snapshot: {C.BLUE}{snap.snapshot_id}{C.RESET} ({snap.file_count} files)")

        if not auto_approve_safe:
            confirm = input(f"\n  {C.BOLD}Execute anyway? [y/N]{C.RESET} ").strip().lower()
            if confirm != "y":
                print(f"  {C.DIM}Cancelled.{C.RESET}")
                return result

    # ACCEPT → execute directly
    if decision == "ACCEPT":
        print(f"\n{C.GREEN}{C.BOLD}>> ACCEPT{C.RESET}")
        print(f"  Command: {C.GREEN}{command}{C.RESET}")
        print(f"  Risk:    {C.GREEN}{eval_result['risk_type']}{C.RESET} (score: {eval_result['risk_score']:.2f})")
        if reasons:
            print(f"  Note:")
            _print_reasons(reasons)

    # Execute the command
    if decision in ("ACCEPT", "RETRY"):
        start = time.time()
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30, cwd=WORKSPACE,
            )
            elapsed = time.time() - start

            result["executed"] = True
            result["execution_output"] = proc.stdout[:2000] if proc.stdout else None
            result["execution_error"] = proc.stderr[:2000] if proc.stderr else None
            result["exit_code"] = proc.returncode
            result["elapsed_sec"] = round(elapsed, 2)

            if proc.returncode == 0:
                print(f"  {C.GREEN}Success{C.RESET} ({elapsed:.2f}s)")
                if proc.stdout and proc.stdout.strip():
                    for line in proc.stdout.strip().split("\n")[:5]:
                        print(f"    {C.DIM}{line[:100]}{C.RESET}")
            else:
                print(f"  {C.RED}Failed{C.RESET} (exit {proc.returncode}, {elapsed:.2f}s)")
                if proc.stderr and proc.stderr.strip():
                    for line in proc.stderr.strip().split("\n")[:3]:
                        print(f"    {C.RED}{line[:100]}{C.RESET}")

                # Auto-rollback if snapshot exists
                if result["snapshot_id"]:
                    print(f"\n  {C.YELLOW}Auto-rollback...{C.RESET}")
                    if _snapshot_mgr.restore(result["snapshot_id"]):
                        print(f"  {C.GREEN}Rollback successful{C.RESET}")
                    else:
                        print(f"  {C.RED}Rollback FAILED{C.RESET}")

        except subprocess.TimeoutExpired:
            result["execution_error"] = "timeout (30s)"
            print(f"  {C.RED}Timeout (30s){C.RESET}")
        except Exception as e:
            result["execution_error"] = str(e)[:200]
            print(f"  {C.RED}Error: {e}{C.RESET}")

    print(f"  Trace:   {C.DIM}{trace_id}{C.RESET}")

    # Update trace with execution results
    trace_update = {k: v for k, v in result.items() if k not in eval_result}
    full_trace = {**eval_result, **trace_update}
    _save_trace(full_trace)

    return result


def show_trace(trace_id: str) -> None:
    """Display a trace's decision chain."""
    trace = _load_trace(trace_id)
    if not trace:
        print(f"{C.RED}Trace not found: {trace_id}{C.RESET}")
        return

    print(f"\n{C.BOLD}Trace: {trace_id}{C.RESET}")
    print(f"  Time:     {trace.get('timestamp', '?')}")
    print(f"  Command:  {trace.get('command', '?')}")
    print(f"  Risk:     {trace.get('risk_type', '?')} (score: {trace.get('risk_score', '?')})")
    print(f"  Decision: {trace.get('decision', '?')}")
    print(f"  Reason:   {trace.get('explanation', '?')}")
    if trace.get("reasons"):
        print(f"  Details:")
        for r in trace["reasons"]:
            print(f"    - {r}")
    if trace.get("executed"):
        print(f"  Executed: >> (exit {trace.get('exit_code', '?')}, {trace.get('elapsed_sec', '?')}s)")
        if trace.get("snapshot_id"):
            print(f"  Snapshot: {trace['snapshot_id']}")
            print(f"  Rollback: {'available' if trace.get('rollback_available') else 'used'}")
    else:
        print(f"  Executed: (blocked or cancelled)")


def interactive_shell() -> None:
    """Interactive protected shell."""
    print(f"\n{C.BOLD}{C.BLUE}QClaw Protected Shell{C.RESET}")
    print(f"  All commands are evaluated before execution.")
    print(f"  Type {C.YELLOW}exit{C.RESET} to quit, {C.YELLOW}trace <id>{C.RESET} to replay.")
    print(f"  Prefix {C.YELLOW}!{C.RESET} to bypass protection (logged).{C.RESET}\n")

    history = []
    while True:
        try:
            cmd = input(f"{C.GREEN}qclaw>{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.DIM}Bye.{C.RESET}")
            break

        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit"):
            print(f"{C.DIM}Bye.{C.RESET}")
            break
        if cmd.lower().startswith("trace "):
            show_trace(cmd.split(" ", 1)[1].strip())
            continue
        if cmd.lower() == "history":
            for h in history[-10:]:
                print(f"  {C.DIM}{h}{C.RESET}")
            continue

        # Emergency bypass: prefix with !
        if cmd.startswith("!"):
            actual_cmd = cmd[1:].strip()
            if actual_cmd:
                result = execute_command(actual_cmd, auto_approve_safe=False, force=True)
                history.append(f"[BYPASS] {actual_cmd}")
            continue

        result = execute_command(cmd, auto_approve_safe=False)
        history.append(f"[{result['decision']}] {cmd}")


def main():
    parser = argparse.ArgumentParser(
        prog="qclaw",
        description="QClaw - Execution Firewall for AI Coding Agents",
    )
    sub = parser.add_subparsers(dest="command")

    # qclaw run <cmd>
    run_p = sub.add_parser("run", help="Evaluate and execute a command")
    run_p.add_argument("cmd", help="Command to evaluate and execute")
    run_p.add_argument("--yes", "-y", action="store_true", help="Auto-approve non-blocked commands")
    run_p.add_argument("--force", "-f", action="store_true", help="Emergency bypass - skip all protection (logged)")

    # qclaw eval <cmd>
    eval_p = sub.add_parser("eval", help="Evaluate risk only (no execution)")
    eval_p.add_argument("cmd", help="Command to evaluate")

    # qclaw trace <id>
    trace_p = sub.add_parser("trace", help="Replay decision chain")
    trace_p.add_argument("trace_id", help="Trace ID to replay")

    # qclaw shell
    sub.add_parser("shell", help="Interactive protected shell")

    # qclaw rollback <trace_id>
    rollback_p = sub.add_parser("rollback", help="Restore system from snapshot by trace_id")
    rollback_p.add_argument("trace_id", help="Trace ID with snapshot to restore")

    args = parser.parse_args()

    if args.command == "run":
        execute_command(args.cmd, auto_approve_safe=args.yes, force=getattr(args, 'force', False))
    elif args.command == "eval":
        result = evaluate_command(args.cmd)
        print(f"\n  Command:  {result['command']}")
        print(f"  Risk:     {result['risk_type']} (score: {result['risk_score']:.2f})")
        print(f"  Decision: {result['decision']}")
        if result.get("reasons"):
            print(f"  Reasons:")
            for r in result["reasons"]:
                print(f"    - {r}")
        else:
            print(f"  Reason:   {result['explanation']}")
        print(f"  Trace:    {result['trace_id']}")
    elif args.command == "trace":
        show_trace(args.trace_id)
    elif args.command == "shell":
        interactive_shell()
    elif args.command == "rollback":
        trace = _load_trace(args.trace_id)
        if not trace:
            print(f"Trace not found: {args.trace_id}")
        elif not trace.get("snapshot_id"):
            print(f"No snapshot in trace: {args.trace_id}")
        else:
            restored = _snapshot_mgr.restore(trace["snapshot_id"])
            if restored:
                print(f"{C.GREEN}Restored:{C.RESET} {trace['snapshot_id']}")
            else:
                print(f"{C.RED}Restore failed:{C.RESET} {trace['snapshot_id']}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
