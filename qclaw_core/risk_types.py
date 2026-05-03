"""
qclaw_core.risk_types - Risk type classification for shell commands.

Core principle:
- DESTRUCTIVE/IRREVERSIBLE → always REJECT
- UNCERTAIN/COMPLEX → RETRY (need more info)
- SAFE → ACCEPT
"""
import re
from enum import Enum, auto


class RiskType(Enum):
    DESTRUCTIVE = "destructive"
    IRREVERSIBLE = "irreversible"
    UNCERTAIN = "uncertain"
    COMPLEX = "complex"
    SAFE = "safe"


def classify_risk(goal: str, task_type: str = "") -> RiskType:
    """
    Rule-based risk classifier (bilingual: English + Chinese).

    Priority: DESTRUCTIVE > IRREVERSIBLE > UNCERTAIN > COMPLEX > SAFE
    """
    goal_lower = goal.lower()

    # ── Whitelist: avoid false positives ──
    safe_patterns = [
        "format string", "format code", "format output",
        "format json", "format xml", "format html",
        "format date", "format time", "format csv",
        "format number", "format text", "format table",
        "reformat output", "reformat data",
        "code formatting", "auto-format",
    ]
    if any(p in goal_lower for p in safe_patterns):
        return RiskType.SAFE

    # ── 1. DESTRUCTIVE ──
    destructive_en = [
        "delete", "drop", "wipe", "remove all", "truncate",
        "destroy", "purge", "clean all", "erase",
        "format", "mkfs", "reinitialize", "repartition",
        "overwrite disk", "zero out", "wipe disk", "secure erase",
    ]
    for kw in destructive_en:
        if kw in goal_lower:
            return RiskType.DESTRUCTIVE

    destructive_cn = [
        "删除", "删掉", "删去", "删除所有", "删除全部",
        "格式化", "格式化磁盘", "清空", "清空数据", "清空所有",
        "销毁", "抹掉", "擦除", "清除", "清除所有", "清除全部",
        "禁用", "禁用防火墙", "关闭防火墙",
        "关闭所有", "停止服务", "终止进程",
        "drop table", "drop database", "truncate", "rm -rf",
        "发送垃圾邮件", "发送垃圾", "群发垃圾",
    ]
    for kw in destructive_cn:
        if kw in goal_lower:
            return RiskType.DESTRUCTIVE

    # ── 2. IRREVERSIBLE ──
    irreversible_en = [
        "irreversible", "cannot undo", "no rollback",
        "permanent", "one-way", "destructive deploy",
    ]
    for kw in irreversible_en:
        if kw in goal_lower:
            return RiskType.IRREVERSIBLE

    irreversible_cn = [
        "不可逆", "无法回滚", "不可回滚", "永久删除",
        "一次性", "单向操作",
    ]
    for kw in irreversible_cn:
        if kw in goal_lower:
            return RiskType.IRREVERSIBLE

    # ── 3. UNCERTAIN ──
    uncertain_en = [
        "unknown", "unclear", "not sure", "ambiguous",
        "missing info", "incomplete", "vague",
    ]
    for kw in uncertain_en:
        if kw in goal_lower:
            return RiskType.UNCERTAIN

    uncertain_cn = [
        "未知", "不确定", "不清楚", "信息不足",
        "缺少信息", "不完整", "模糊",
    ]
    for kw in uncertain_cn:
        if kw in goal_lower:
            return RiskType.UNCERTAIN

    # ── 4. COMPLEX ──
    complex_en = [
        "migrate", "deploy", "rewrite", "upgrade", "refactor",
        "redesign", "restructure", "rebuild", "architect",
        "distributed", "concurrent", "async", "parallel",
        "optimize", "performance", "scale",
    ]
    for kw in complex_en:
        if kw in goal_lower:
            return RiskType.COMPLEX

    complex_cn = [
        "迁移", "部署", "重构", "重写", "升级", "降级",
        "优化", "性能优化", "大规模",
        "机器学习", "深度学习", "神经网络",
        "微服务", "分布式", "并发", "异步",
        "架构调整", "架构设计", "系统重构",
        "生产环境", "线上环境",
    ]
    for kw in complex_cn:
        if kw in goal_lower:
            return RiskType.COMPLEX

    # ── 5. Default: SAFE ──
    return RiskType.SAFE


def risk_to_decision(risk: RiskType, confidence_delta: float = None) -> str:
    mapping = {
        RiskType.DESTRUCTIVE: "REJECT",
        RiskType.IRREVERSIBLE: "REJECT",
        RiskType.UNCERTAIN: "RETRY",
        RiskType.COMPLEX: "RETRY",
        RiskType.SAFE: "ACCEPT",
    }
    return mapping.get(risk, "REJECT")


def get_risk_explanation(risk: RiskType) -> str:
    explanations = {
        RiskType.DESTRUCTIVE: "Operation may cause data loss or system damage",
        RiskType.IRREVERSIBLE: "Operation cannot be rolled back",
        RiskType.UNCERTAIN: "Insufficient information for reliable judgment",
        RiskType.COMPLEX: "Complex operation requiring step-by-step verification",
        RiskType.SAFE: "Low risk operation",
    }
    return explanations.get(risk, "Unknown risk type")
