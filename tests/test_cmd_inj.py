"""命令注入签名检测"""
from src.detector.signatures import detect_signature_attacks
from src.parser.log_parser import parse_csv_rows


def test_cmd_inj_pipe():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.1", "target_ip": "10.0.0.42",
             "port": "80", "path": "/run?cmd=|cat /etc/passwd",
             "status_code": "200", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "命令注入尝试" for a in alerts)


def test_cmd_inj_semicolon():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.2", "target_ip": "10.0.0.42",
             "port": "80", "path": "/ping?host=8.8.8.8;whoami",
             "status_code": "200", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "命令注入尝试" for a in alerts)


def test_cmd_inj_dollar():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.3", "target_ip": "10.0.0.42",
             "port": "80", "path": "/exec?cmd=$(whoami)",
             "status_code": "500", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "命令注入尝试" for a in alerts)


def test_cmd_inj_backtick():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.4", "target_ip": "10.0.0.42",
             "port": "80", "path": "/backup?cmd=`whoami`",
             "status_code": "500", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "命令注入尝试" for a in alerts)
