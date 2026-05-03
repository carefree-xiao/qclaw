"""
qclaw_core.risk_scorer - Signal-aware risk scoring.

score = 0.60 * base_fail_rate(RiskType)
      + 0.25 * (1 - confidence)
      + 0.15 * history_fail_rate
"""
from collections import defaultdict

# ── Calibration table ──
_CALIBRATION = {
    "safe":         {"fail_rate": 0.015},
    "complex":      {"fail_rate": 0.081},
    "destructive":  {"fail_rate": 0.609},
    "irreversible": {"fail_rate": 0.609},
    "uncertain":    {"fail_rate": 0.125},
    "unknown":      {"fail_rate": 0.125},
}

# ── Goal-level history tracker ──
_history = defaultdict(lambda: {"fail": 0, "total": 0})


def update_history(goal: str, label: str) -> None:
    if not goal:
        return
    h = _history[goal]
    h["total"] += 1
    if label == "FAIL":
        h["fail"] += 1


def get_history_fail_rate(goal: str) -> float:
    if not goal:
        return 0.0
    h = _history[goal]
    if h["total"] < 5:
        return 0.0
    return h["fail"] / h["total"]


def reset_history() -> None:
    _history.clear()


WEIGHTS = {
    "base":    0.60,
    "conf":    0.25,
    "history": 0.15,
}


def compute_confidence(goal: str) -> float:
    if not goal:
        return 0.5
    g = goal.lower()
    if any(k in g for k in ["delete", "drop", "remove all", "truncate", "purge"]):
        return 0.95
    if any(k in g for k in ["deploy", "rebuild", "switch", "migrate", "replace"]):
        return 0.80
    if any(k in g for k in ["restart", "reboot", "stop", "disable", "kill"]):
        return 0.75
    if any(k in g for k in ["create", "update", "set", "enable", "grant"]):
        return 0.60
    if any(k in g for k in ["refactor", "optimize", "tune", "merge", "archive"]):
        return 0.30
    if any(k in g for k in ["export", "import", "backup", "restore", "snapshot"]):
        return 0.35
    return 0.5


def _clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def compute_risk_score(
    risk_type: str,
    confidence: float = None,
    history_fail_rate: float = None,
    goal: str = "",
) -> float:
    base = _CALIBRATION.get(risk_type, _CALIBRATION["unknown"])["fail_rate"]

    eff_conf = confidence if confidence is not None else compute_confidence(goal)

    eff_hist = history_fail_rate
    if eff_hist is None and goal:
        eff_hist = get_history_fail_rate(goal)
    if eff_hist is None:
        eff_hist = 0.0

    score = (
        WEIGHTS["base"] * base
        + WEIGHTS["conf"] * (1.0 - eff_conf)
        + WEIGHTS["history"] * eff_hist
    )

    if risk_type == "unknown":
        score = max(score, 0.25)

    return _clamp(score)


THRESHOLDS = {
    "reject": 0.6,
    "retry": 0.2,
}


def risk_to_action(score: float) -> str:
    if score >= THRESHOLDS["reject"]:
        return "REJECT"
    elif score >= THRESHOLDS["retry"]:
        return "RETRY"
    else:
        return "ACCEPT"
