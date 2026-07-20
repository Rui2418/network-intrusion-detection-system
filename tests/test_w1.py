from src.detector.signatures import detect_signature_attacks
from src.parser.log_parser import parse_csv_rows


def test_webshell_eval():
    payload = "eval(" + "base64_decode(" + "$_POST[x]))"
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.8", "target_ip": "10.0.0.42",
             "port": "80", "path": "/s.php?cmd=" + payload,
             "status_code": "200", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "Webshell执行" for a in alerts)


def test_webshell_assert():
    payload = "assert(" + "$_GET[c])"
    rows = [{"timestamp": "2026-07-20T10:00:00", "source_ip": "10.0.0.9", "target_ip": "10.0.0.42",
             "port": "80", "path": "/i.php?x=" + payload,
             "status_code": "200", "username": "", "login_success": ""}]
    alerts = detect_signature_attacks(list(parse_csv_rows(rows)))
    assert any(a.alert_type == "Webshell执行" for a in alerts)
