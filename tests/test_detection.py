from io import BytesIO
from pathlib import Path

from src.app import app
from src.detector.rules import detect_attacks
from src.parser.log_parser import parse_csv_log


SAMPLE_LOG = Path(__file__).resolve().parents[1] / "data" / "sample_logs.csv"


def test_sample_logs_generate_expected_alert_types():
    events = parse_csv_log(SAMPLE_LOG)
    alert_types = {alert.alert_type for alert in detect_attacks(events)}

    assert "端口扫描" in alert_types
    assert "暴力登录" in alert_types
    assert "可疑路径访问" in alert_types
    assert "异常状态码" in alert_types
    assert "异常访问频率" in alert_types


def test_alerts_have_risk_levels():
    events = parse_csv_log(SAMPLE_LOG)
    alerts = detect_attacks(events)

    assert alerts
    assert all(alert.level in {"低危", "中危", "高危"} for alert in alerts)
    assert all(0 <= alert.score <= 100 for alert in alerts)


def test_upload_rejects_invalid_timestamp():
    response = upload_csv(
        "timestamp,source_ip,target_ip,port,path,status_code,username,login_success\n"
        "not-a-date,192.168.1.1,10.0.0.1,80,/index,200,,\n"
    )

    assert response.status_code == 400
    assert "CSV 日志格式错误" in response.get_json()["error"]


def test_upload_rejects_invalid_port():
    response = upload_csv(
        "timestamp,source_ip,target_ip,port,path,status_code,username,login_success\n"
        "2026-07-08T10:00:00,192.168.1.1,10.0.0.1,notaport,/index,200,,\n"
    )

    assert response.status_code == 400
    assert "CSV 日志格式错误" in response.get_json()["error"]


def upload_csv(content: str):
    with app.test_client() as client:
        return client.post(
            "/api/analyze",
            data={"file": (BytesIO(content.encode("utf-8")), "logs.csv")},
            content_type="multipart/form-data",
        )
