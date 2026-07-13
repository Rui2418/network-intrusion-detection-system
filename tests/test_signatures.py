from pathlib import Path

from src.detector.signatures import detect_signature_attacks
from src.parser.log_parser import parse_csv_log


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
