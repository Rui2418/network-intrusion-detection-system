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


def test_signature_detection_ignores_plain_double_dash_path():
    rows = [
        {
            "timestamp": "2026-07-20T10:00:00",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "port": "80",
            "path": "/assets/course--intro.html",
            "status_code": "200",
            "username": "",
            "login_success": "",
        }
    ]

    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))

    assert not any(alert.alert_type == "SQL注入尝试" for alert in alerts)


def test_signature_detection_matches_command_injection():
    rows = [
        {
            "timestamp": "2026-07-20T10:00:00",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "port": "80",
            "path": "/exec?cmd=%7Ccat%20/etc/passwd",
            "status_code": "200",
            "username": "",
            "login_success": "",
        }
    ]

    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))

    assert any(alert.alert_type == "命令注入尝试" for alert in alerts)
    cmd_alert = next(a for a in alerts if a.alert_type == "命令注入尝试")
    assert cmd_alert.rule_id == "command_injection"
    assert cmd_alert.category == "特征匹配"


def test_signature_detection_matches_file_inclusion():
    rows = [
        {
            "timestamp": "2026-07-20T10:00:00",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "port": "80",
            "path": "/view?page=php://filter/convert.base64-encode/resource=index",
            "status_code": "200",
            "username": "",
            "login_success": "",
        }
    ]

    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))

    assert any(alert.alert_type == "文件包含尝试" for alert in alerts)
    fi_alert = next(a for a in alerts if a.alert_type == "文件包含尝试")
    assert fi_alert.rule_id == "file_inclusion"
    assert fi_alert.category == "特征匹配"


def test_signature_detection_matches_webshell_exec():
    rows = [
        {
            "timestamp": "2026-07-20T10:00:00",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "port": "80",
            "path": "/shell?cmd=eval%28%24_POST%5Bcmd%5D%29",
            "status_code": "200",
            "username": "",
            "login_success": "",
        }
    ]

    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))

    assert any(alert.alert_type == "Webshell执行" for alert in alerts)
    ws_alert = next(a for a in alerts if a.alert_type == "Webshell执行")
    assert ws_alert.rule_id == "webshell_exec"
    assert ws_alert.category == "特征匹配"
