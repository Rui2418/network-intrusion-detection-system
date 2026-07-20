from pathlib import Path

from src.detector.signatures import detect_signature_attacks, load_signatures
from src.parser.log_parser import parse_csv_log, parse_csv_rows


EXTENDED_SAMPLE_LOG = Path(__file__).resolve().parents[1] / "data" / "sample_logs_extended.csv"


def test_signature_detection_finds_expected_attack_types():
    events = parse_csv_log(EXTENDED_SAMPLE_LOG)
    alert_types = {alert.alert_type for alert in detect_signature_attacks(events)}

    assert "SQL注入尝试" in alert_types
    assert "XSS尝试" in alert_types
    assert "目录遍历尝试" in alert_types
    assert "恶意命令访问" in alert_types
    assert "疑似控制信道" in alert_types


def test_signature_alerts_include_aggregation_metadata():
    events = parse_csv_log(EXTENDED_SAMPLE_LOG)
    alerts = detect_signature_attacks(events)

    sql_alert = next(alert for alert in alerts if alert.alert_type == "SQL注入尝试")
    assert sql_alert.category == "特征匹配"
    assert sql_alert.rule_id == "sql_injection_basic"
    assert sql_alert.count >= 1
    assert sql_alert.matched_fields


def test_signature_detection_matches_lab_course_sqli_payload():
    rows = [
        {
            "timestamp": "2026-07-20T10:57:55",
            "source_ip": "127.0.0.1",
            "target_ip": "10.0.0.42",
            "port": "8001",
            "path": "/api/grades?course=信息安全 1=1",
            "status_code": "200",
            "username": "2024001",
            "login_success": "",
            "method": "GET",
            "protocol": "tcp",
            "host": "127.0.0.1",
            "user_agent": "browser",
            "bytes_sent": "1407",
            "duration_ms": "1",
            "tls_fingerprint": "ja3-browser",
        }
    ]

    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))

    assert any(alert.alert_type == "SQL注入尝试" for alert in alerts)
