"""
qclaw_core.policies — Single source of truth for command risk policies.

Three lists, evaluated in order:
  1. TRUSTED_DEV_COMMANDS  → force SAFE (no evaluation needed)
  2. DESTRUCTIVE_PATTERNS  → force BLOCK (with human-readable reasons)
  3. RISKY_PATTERNS        → upgrade to COMPLEX (at minimum)

Everything else falls through to the rule-based classifier + risk scorer.
"""

import re


# ── Trusted developer commands ───────────────────────────────────────────────
# These are always SAFE. Period. No scoring, no evaluation.
# NEVER add: git push --force, docker system prune, rm, etc.

TRUSTED_DEV_COMMANDS = [
    # Package install (adds dependencies, read-only to the world)
    r"\bpip\s+install\b",
    r"\bnpm\s+install\b",
    r"\byarn\s+(install|add)\b",
    r"\bpnpm\s+install\b",
    r"\bpoetry\s+install\b",
    r"\bbrew\s+install\b",
    # Test / lint / build (read-only side effects)
    r"\bpytest\b",
    r"\bjest\b",
    r"\bmocha\b",
    r"\bruff\b",
    r"\bpylint\b",
    r"\bmypy\b",
    r"\beslint\b",
    r"\bblack\b",
    r"\bisort\b",
    # Git read-only
    r"\bgit\s+(status|log|diff|branch|show|blame|remote|tag)\b",
    r"\bgit\s+pull\b",
    r"\bgit\s+fetch\b",
    r"\bgit\s+stash\b",
    # Docker read-only
    r"\bdocker\s+(ps|images|logs|inspect|version|info)\b",
    r"\bdocker\s+compose\s+(ps|logs|config)\b",
    # Kubernetes read-only
    r"\bkubectl\s+(get|describe|logs|top|explain|version)\b",
    # Filesystem read-only
    r"\bls\b",
    r"\bcat\b",
    r"\bhead\b",
    r"\btail\b",
    r"\bfind\b",
    r"\bgrep\b",
    r"\bwc\b",
    r"\bwhich\b",
    r"\btype\b",
    r"\bfile\b",
    r"\bdu\b",
    r"\bdf\b",
    # Echo / print
    r"\becho\b",
    r"\bprintf\b",
    r"\bprintenv\b",
    # Python read-only
    r"\bpython\s+(-[cm]\b|--version\b)",
    r"\bpip\s+(list|show|freeze|check)\b",
]


# ── Destructive patterns → always BLOCK ──────────────────────────────────────
# Each entry: (regex, [human-readable reasons])
# Reasons explain WHY the command is blocked, not just "it's dangerous".

DESTRUCTIVE_PATTERNS = [
    # rm variants
    (r"\brm\s+(-[rfRfd]+\s+)*", [
        "recursive deletion detected",
        "file removal with force flag",
        "deleted files cannot be recovered",
    ]),
    (r"\brmdir\b", [
        "directory removal detected",
        "irreversible operation",
    ]),
    # Docker destructive
    (r"\bdocker\s+system\s+prune\b", [
        "removes all unused containers, images, networks",
        "data in stopped containers will be lost",
    ]),
    (r"\bdocker\s+volume\s+prune\b", [
        "removes all unused volumes",
        "named volume data will be permanently deleted",
    ]),
    (r"\bdocker\s+(rm|rmi)\b", [
        "container/image removal",
        "running state will be lost",
    ]),
    # kubectl destructive
    (r"\bkubectl\s+delete\b", [
        "kubernetes resource deletion",
        "may affect production workloads",
    ]),
    (r"\bkubectl\s+destroy\b", [
        "kubernetes resource destruction",
        "irreversible cluster state change",
    ]),
    # Database destructive
    (r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA|INDEX)\b", [
        "SQL destructive operation",
        "database object will be permanently removed",
        "data loss - no undo",
    ]),
    # Filesystem destructive
    (r"\bmkfs\b", [
        "filesystem format detected",
        "all data on target device will be destroyed",
    ]),
    (r"\bdd\s+.*of=\b", [
        "raw disk write (dd)",
        "target device will be overwritten",
    ]),
    (r"\bformat\s+[A-Z]:\\", [
        "Windows drive format",
        "all data on drive will be destroyed",
    ]),
    # Git destructive
    (r"\bgit\s+push\s+.*(--force|-f)\b", [
        "force push detected",
        "remote history will be overwritten",
        "other developers' commits may be lost",
    ]),
    (r"\bgit\s+reset\s+--hard\b", [
        "hard reset detected",
        "uncommitted changes permanently lost",
    ]),
    (r"\bgit\s+clean\s+-fd\b", [
        "git clean with force",
        "untracked files permanently deleted",
    ]),
    # Package removal
    (r"\bapt(-get)?\s+(remove|purge)\b", [
        "system package removal",
        "dependencies may break",
    ]),
    (r"\byum\s+(remove|erase)\b", [
        "system package removal",
        "dependencies may break",
    ]),
    # System control
    (r"\bshutdown\b", [
        "system shutdown",
        "machine will power off",
    ]),
    (r"\breboot\b", [
        "system reboot",
        "machine will restart",
    ]),
    (r"\bkill\s+-9\b", [
        "SIGKILL (kill -9)",
        "process terminated without cleanup",
    ]),
    (r"\bpkill\s+-9\b", [
        "SIGKILL (pkill -9)",
        "matching processes forcefully terminated",
    ]),
    # Terraform destructive
    (r"\bterraform\s+destroy\b", [
        "terraform destroy",
        "all managed infrastructure will be destroyed",
        "cloud resources will be deleted",
    ]),
    # Permission dangerous
    (r"\bchmod\s+(-R\s+)?000\b", [
        "permission removal (chmod 000)",
        "lockout risk - no access to target",
    ]),
    (r"\bchmod\s+(-R\s+)?777\b", [
        "permission escalation (chmod 777)",
        "security risk - world-readable/writable",
    ]),
]


# ── Risky patterns → upgrade to COMPLEX ──────────────────────────────────────
# Not immediately destructive, but require caution.

RISKY_PATTERNS = [
    r"\bgit\s+(push|merge|rebase|reset|checkout)\b",
    r"\bdocker\s+(run|exec|build|push)\b",
    r"\bkubectl\s+(apply|rollout|scale)\b",
    r"\bsystemctl\s+(restart|stop|disable)\b",
    r"\bservice\s+\w+\s+(restart|stop)\b",
    r"\bnpm\s+publish\b",
    r"\bmv\s+.*\s+/",
    r"\bcp\s+-r\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bsed\s+-i\b",
]


def check_trusted(command: str) -> bool:
    """Check if command matches a trusted developer pattern."""
    for pattern in TRUSTED_DEV_COMMANDS:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False


def check_destructive(command: str) -> list[str] | None:
    """
    Check if command matches a destructive pattern.
    Returns list of human-readable reasons, or None if not destructive.
    """
    for pattern, reasons in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return reasons
    return None


def check_risky(command: str) -> bool:
    """Check if command matches a risky (but not destructive) pattern."""
    for pattern in RISKY_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False
