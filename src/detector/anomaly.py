from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address

from src.detector.models import Alert, BaselineMetric
from src.parser.log_parser import LogEvent
from src.scoring.risk import score_alert


MANAGEMENT_PORTS = {22, 3389, 445, 5985}


def detect_anomalies(events: list[LogEvent]) -> tuple[list[Alert], dict[str, object]]:
    alerts: list[Alert] = []
    request_rate_per_ip: list[BaselineMetric] = []
    unique_ports_per_ip: list[BaselineMetric] = []
    login_failures_per_ip: list[BaselineMetric] = []

    grouped_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    grouped_by_user: dict[str, set[str]] = defaultdict(set)
    grouped_by_internal_source: dict[str, set[str]] = defaultdict(set)

    coverage = {
        "bytes_sent": any(event.bytes_sent is not None for event in events),
        "duration_ms": any(event.duration_ms is not None for event in events),
        "tls_fingerprint": any(bool(event.tls_fingerprint) for event in events),
    }

    for event in events:
        grouped_by_ip[event.source_ip].append(event)
        if event.username:
            grouped_by_user[event.username].add(event.source_ip)
        if _is_private_ip(event.source_ip) and _is_private_ip(event.target_ip) and event.port in MANAGEMENT_PORTS:
            grouped_by_internal_source[event.source_ip].add(event.target_ip)

    for source_ip, group in grouped_by_ip.items():
        request_count = len(group)
        unique_ports = len({event.port for event in group})
        login_failures = sum(1 for event in group if event.login_success is False)

        request_rate_per_ip.append(BaselineMetric(source_ip, "request_rate", float(request_count), 20.0, f"共 {request_count} 次请求"))
        unique_ports_per_ip.append(BaselineMetric(source_ip, "unique_ports", float(unique_ports), 5.0, f"访问 {unique_ports} 个端口"))
        login_failures_per_ip.append(BaselineMetric(source_ip, "login_failures", float(login_failures), 5.0, f"登录失败 {login_failures} 次"))

        if request_count >= 25:
            score, level = score_alert("anomaly_request_rate", request_count)
            alerts.append(Alert(
                alert_type="异常高频访问",
                category="异常检测",
                source_ip=source_ip,
                target="multiple targets",
                level=level,
                score=score,
                confidence=0.82,
                evidence=f"单个来源共产生 {request_count} 次请求，超过基线 20",
                rule_id="anomaly_request_rate",
                count=request_count,
                first_seen=min(event.timestamp for event in group),
                last_seen=max(event.timestamp for event in group),
                matched_fields=("source_ip",),
            ))

        if unique_ports >= 5:
            score, level = score_alert("anomaly_multi_port", unique_ports)
            alerts.append(Alert(
                alert_type="多端口异常访问",
                category="异常检测",
                source_ip=source_ip,
                target="multiple ports",
                level=level,
                score=score,
                confidence=0.8,
                evidence=f"单个来源访问 {unique_ports} 个不同端口，超过基线 5",
                rule_id="anomaly_multi_port",
                count=unique_ports,
                first_seen=min(event.timestamp for event in group),
                last_seen=max(event.timestamp for event in group),
                matched_fields=("port",),
            ))

        if login_failures >= 5:
            score, level = score_alert("anomaly_login_failures", login_failures)
            alerts.append(Alert(
                alert_type="登录失败异常",
                category="异常检测",
                source_ip=source_ip,
                target="authentication",
                level=level,
                score=score,
                confidence=0.84,
                evidence=f"登录失败 {login_failures} 次，超过基线 5",
                rule_id="anomaly_login_failures",
                count=login_failures,
                first_seen=min(event.timestamp for event in group),
                last_seen=max(event.timestamp for event in group),
                matched_fields=("username", "login_success"),
            ))

        if any((not _is_private_ip(event.source_ip)) and _is_private_ip(event.target_ip) for event in group):
            suspicious_targets = sorted({event.target_ip for event in group if _is_private_ip(event.target_ip)})
            score, level = score_alert("anomaly_external_internal", len(suspicious_targets))
            alerts.append(Alert(
                alert_type="外部来源访问内网",
                category="异常检测",
                source_ip=source_ip,
                target=", ".join(suspicious_targets[:3]) or "internal targets",
                level=level,
                score=score,
                confidence=0.86,
                evidence=f"外部来源访问 {len(suspicious_targets)} 个内网目标",
                rule_id="anomaly_external_internal",
                count=len(suspicious_targets),
                first_seen=min(event.timestamp for event in group),
                last_seen=max(event.timestamp for event in group),
                matched_fields=("source_ip", "target_ip"),
            ))

        durations = [event.duration_ms for event in group if event.duration_ms is not None]
        if durations and max(durations) >= 5000:
            peak = max(durations)
            score, level = score_alert("anomaly_duration", peak // 1000)
            alerts.append(Alert(
                alert_type="会话时长异常",
                category="异常检测",
                source_ip=source_ip,
                target="session",
                level=level,
                score=score,
                confidence=0.75,
                evidence=f"最大会话时长 {peak} ms，超过基线 5000 ms",
                rule_id="anomaly_duration",
                count=1,
                first_seen=min(event.timestamp for event in group),
                last_seen=max(event.timestamp for event in group),
                matched_fields=("duration_ms",),
            ))

        bytes_sent = [event.bytes_sent for event in group if event.bytes_sent is not None]
        if bytes_sent and max(bytes_sent) >= 500000:
            peak = max(bytes_sent)
            score, level = score_alert("anomaly_bytes", max(1, peak // 100000))
            alerts.append(Alert(
                alert_type="流量体量异常",
                category="异常检测",
                source_ip=source_ip,
                target="traffic",
                level=level,
                score=score,
                confidence=0.76,
                evidence=f"最大传输字节数 {peak}，超过基线 500000",
                rule_id="anomaly_bytes",
                count=1,
                first_seen=min(event.timestamp for event in group),
                last_seen=max(event.timestamp for event in group),
                matched_fields=("bytes_sent",),
            ))

        fingerprints = {event.tls_fingerprint for event in group if event.tls_fingerprint}
        if any(fp and "malware" in fp.lower() for fp in fingerprints):
            score, level = score_alert("anomaly_tls", len(fingerprints))
            alerts.append(Alert(
                alert_type="TLS指纹异常",
                category="异常检测",
                source_ip=source_ip,
                target="tls",
                level=level,
                score=score,
                confidence=0.9,
                evidence="检测到异常 TLS 指纹标识",
                rule_id="anomaly_tls",
                count=len(fingerprints),
                first_seen=min(event.timestamp for event in group),
                last_seen=max(event.timestamp for event in group),
                matched_fields=("tls_fingerprint",),
            ))

    for username, sources in grouped_by_user.items():
        if len(sources) >= 3:
            score, level = score_alert("anomaly_password_spray", len(sources))
            alerts.append(Alert(
                alert_type="疑似密码喷洒",
                category="异常检测",
                source_ip="multiple",
                target=username,
                level=level,
                score=score,
                confidence=0.83,
                evidence=f"账号 {username} 被 {len(sources)} 个来源尝试",
                rule_id="anomaly_password_spray",
                count=len(sources),
                matched_fields=("username", "source_ip"),
            ))

    for source_ip, targets in grouped_by_internal_source.items():
        if len(targets) >= 3:
            score, level = score_alert("anomaly_lateral_movement", len(targets))
            alerts.append(Alert(
                alert_type="疑似横向移动",
                category="异常检测",
                source_ip=source_ip,
                target=", ".join(sorted(targets)[:3]),
                level=level,
                score=score,
                confidence=0.87,
                evidence=f"内网主机访问 {len(targets)} 个管理目标端口",
                rule_id="anomaly_lateral_movement",
                count=len(targets),
                matched_fields=("source_ip", "target_ip", "port"),
            ))

    baseline = {
        "request_rate_per_ip": request_rate_per_ip,
        "unique_ports_per_ip": unique_ports_per_ip,
        "login_failures_per_ip": login_failures_per_ip,
        "data_coverage": coverage,
    }
    return alerts, baseline


def _is_private_ip(value: str) -> bool:
    try:
        return ip_address(value).is_private
    except ValueError:
        return False
