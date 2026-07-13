from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from src.detector.models import Alert
from src.parser.log_parser import LogEvent
from src.scoring.risk import score_alert


SUSPICIOUS_PATH_KEYWORDS = (
    "/admin",
    "/login",
    ".env",
    "/phpmyadmin",
    "/wp-admin",
    "../",
    "select%20",
    "union%20",
)


def detect_attacks(events: list[LogEvent]) -> list[Alert]:
    return [
        *detect_port_scan(events),
        *detect_brute_force(events),
        *detect_high_frequency_access(events),
        *detect_suspicious_paths(events),
        *detect_abnormal_status_codes(events),
    ]


def detect_port_scan(events: list[LogEvent], window_seconds: int = 60, min_ports: int = 5) -> list[Alert]:
    grouped: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in events:
        grouped[(event.source_ip, event.target_ip)].append(event)

    alerts: list[Alert] = []
    for (source_ip, target_ip), group in grouped.items():
        sorted_events = sorted(group, key=lambda item: item.timestamp)
        for index, start_event in enumerate(sorted_events):
            window_end = start_event.timestamp + timedelta(seconds=window_seconds)
            ports = {event.port for event in sorted_events[index:] if event.timestamp <= window_end}
            if len(ports) >= min_ports:
                score, level = score_alert("port_scan", len(ports))
                alerts.append(Alert(
                    alert_type="端口扫描",
                    category="规则检测",
                    source_ip=source_ip,
                    target=target_ip,
                    level=level,
                    score=score,
                    confidence=0.88,
                    evidence=f"{window_seconds} 秒内访问 {len(ports)} 个不同端口",
                    rule_id="port_scan",
                    count=len(ports),
                    first_seen=start_event.timestamp,
                    last_seen=max(event.timestamp for event in sorted_events[index:] if event.timestamp <= window_end),
                    matched_fields=("source_ip", "target_ip", "port"),
                ))
                break
    return alerts


def detect_brute_force(events: list[LogEvent], window_seconds: int = 120, max_failures: int = 5) -> list[Alert]:
    failures = [event for event in events if event.login_success is False]
    grouped: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in failures:
        grouped[(event.source_ip, event.username or "unknown")].append(event)

    alerts: list[Alert] = []
    for (source_ip, username), group in grouped.items():
        sorted_events = sorted(group, key=lambda item: item.timestamp)
        for index, start_event in enumerate(sorted_events):
            window_end = start_event.timestamp + timedelta(seconds=window_seconds)
            count = sum(1 for event in sorted_events[index:] if event.timestamp <= window_end)
            if count >= max_failures:
                score, level = score_alert("brute_force", count)
                alerts.append(Alert(
                    alert_type="暴力登录",
                    category="规则检测",
                    source_ip=source_ip,
                    target=username,
                    level=level,
                    score=score,
                    confidence=0.9,
                    evidence=f"{window_seconds} 秒内账号 {username} 登录失败 {count} 次",
                    rule_id="brute_force",
                    count=count,
                    first_seen=start_event.timestamp,
                    last_seen=max(event.timestamp for event in sorted_events[index:] if event.timestamp <= window_end),
                    matched_fields=("source_ip", "username", "login_success"),
                ))
                break
    return alerts


def detect_high_frequency_access(events: list[LogEvent], window_seconds: int = 60, max_requests: int = 20) -> list[Alert]:
    grouped: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        grouped[event.source_ip].append(event)

    alerts: list[Alert] = []
    for source_ip, group in grouped.items():
        sorted_events = sorted(group, key=lambda item: item.timestamp)
        for index, start_event in enumerate(sorted_events):
            window_end = start_event.timestamp + timedelta(seconds=window_seconds)
            count = sum(1 for event in sorted_events[index:] if event.timestamp <= window_end)
            if count >= max_requests:
                score, level = score_alert("high_frequency", count)
                alerts.append(Alert(
                    alert_type="异常访问频率",
                    category="规则检测",
                    source_ip=source_ip,
                    target="multiple targets",
                    level=level,
                    score=score,
                    confidence=0.82,
                    evidence=f"{window_seconds} 秒内产生 {count} 次请求",
                    rule_id="high_frequency",
                    count=count,
                    first_seen=start_event.timestamp,
                    last_seen=max(event.timestamp for event in sorted_events[index:] if event.timestamp <= window_end),
                    matched_fields=("source_ip",),
                ))
                break
    return alerts


def detect_suspicious_paths(events: list[LogEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        normalized_path = event.path.lower()
        matched = next((keyword for keyword in SUSPICIOUS_PATH_KEYWORDS if keyword in normalized_path), None)
        if matched:
            score, level = score_alert("suspicious_path", 1)
            alerts.append(Alert(
                alert_type="可疑路径访问",
                category="规则检测",
                source_ip=event.source_ip,
                target=event.path,
                level=level,
                score=score,
                confidence=0.78,
                evidence=f"请求路径命中可疑特征 {matched}",
                rule_id="suspicious_path",
                count=1,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                matched_fields=("path",),
            ))
    return alerts


def detect_abnormal_status_codes(events: list[LogEvent], threshold: int = 8) -> list[Alert]:
    abnormal_events = [event for event in events if event.status_code in {401, 403, 404, 500}]
    grouped: dict[tuple[str, int], list[LogEvent]] = defaultdict(list)
    for event in abnormal_events:
        grouped[(event.source_ip, event.status_code)].append(event)

    alerts: list[Alert] = []
    for (source_ip, status_code), group in grouped.items():
        if len(group) >= threshold:
            score, level = score_alert("abnormal_status", len(group))
            alerts.append(Alert(
                alert_type="异常状态码",
                category="规则检测",
                source_ip=source_ip,
                target=str(status_code),
                level=level,
                score=score,
                confidence=0.8,
                evidence=f"出现 {len(group)} 次 HTTP {status_code} 响应",
                rule_id="abnormal_status",
                count=len(group),
                first_seen=min(event.timestamp for event in group),
                last_seen=max(event.timestamp for event in group),
                matched_fields=("status_code",),
            ))
    return alerts
