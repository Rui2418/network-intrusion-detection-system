from src.detector.signatures import detect_signature_attacks
from src.parser.log_parser import parse_csv_rows


def test_webshell_system():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.10", "target_ip": "10.0.0.42",
             "port": "80", "path": "/a.php?f=system(cat /etc/passwd)",
             "status_code": "500", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "Webshell执行" for a in alerts)


def test_webshell_gzinflate():
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.11", "target_ip": "10.0.0.42",
             "port": "80", "path": "/e.php?d=gzinflate(base64_decode(AF39))",
             "status_code": "200", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "Webshell执行" for a in alerts)
