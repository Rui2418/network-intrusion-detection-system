from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from src.detector.models import Alert, Incident


STAGE_MAP = {
    "端口扫描": "reconnaissance",
    "可疑路径访问": "reconnaissance",
    "异常状态码": "reconnaissance",
    "多端口异常访问": "reconnaissance",
    "SQL注入尝试": "initial_access",
    "XSS尝试": "initial_access",
    "目录遍历尝试": "initial_access",
    "恶意命令访问": "execution_or_control",
    "疑似控制信道": "execution_or_control",
    "暴力登录": "credential_attack",
    "登录失败异常": "credential_attack",
    "疑似密码喷洒": "credential_attack",
    "疑似横向移动": "lateral_movement",
    "外部来源访问内网": "initial_access",
    "TLS指纹异常": "execution_or_control",
}


def correlate_alerts(alerts: list[Alert]) -> list[Incident]:
    grouped: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.source_ip:
            grouped[alert.source_ip].append(alert)

    incidents: list[Incident] = []
    for source_ip, group in grouped.items():
        stages = []
        for alert in group:
            stage = STAGE_MAP.get(alert.alert_type)
            if stage and stage not in stages:
                stages.append(stage)
        if len(stages) < 2:
            continue

        sorted_group = sorted(group, key=lambda item: item.first_seen or item.last_seen or datetime.min)
        score = min(100, max(alert.score for alert in group) + len(stages) * 5)
        if score >= 80:
            level = "高危"
        elif score >= 50:
            level = "中危"
        else:
            level = "低危"
        incidents.append(Incident(
            source_ip=source_ip,
            stages=tuple(stages),
            level=level,
            score=score,
            confidence=round(sum(alert.confidence for alert in group) / len(group), 2),
            alert_types=tuple(dict.fromkeys(alert.alert_type for alert in group)),
            first_seen=sorted_group[0].first_seen or sorted_group[0].last_seen,
            last_seen=sorted_group[-1].last_seen or sorted_group[-1].first_seen,
            evidence=f"同一来源依次触发 {len(stages)} 个攻击阶段",
            recommended_actions=_recommend_actions(group),
        ))
    return incidents


def _recommend_actions(alerts: list[Alert]) -> tuple[str, ...]:
    actions: list[str] = []
    alert_types = {alert.alert_type for alert in alerts}
    if {"端口扫描", "多端口异常访问", "可疑路径访问"} & alert_types:
        actions.append("限制来源IP访问频率")
    if {"暴力登录", "登录失败异常", "疑似密码喷洒"} & alert_types:
        actions.append("临时锁定目标账号或开启验证码")
    if {"SQL注入尝试", "XSS尝试", "目录遍历尝试", "恶意命令访问"} & alert_types:
        actions.append("阻断高风险请求并记录审计")
    if {"疑似控制信道", "TLS指纹异常", "疑似横向移动"} & alert_types:
        actions.append("加入隔离或封禁观察名单")
    return tuple(actions)
