import csv
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import src.app as app_module
import src.defense as defense_module
from src.app import app
from src.detector.rules import detect_attacks
from src.parser.log_parser import parse_csv_log


SAMPLE_LOG = Path(__file__).resolve().parents[1] / "data" / "sample_logs.csv"
EXTENDED_SAMPLE_LOG = Path(__file__).resolve().parents[1] / "data" / "sample_logs_extended.csv"


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


def test_extended_sample_api_returns_rich_analysis_result():
    with app.test_client() as client:
        response = client.get("/api/sample")

    assert response.status_code == 200
    data = response.get_json()
    assert data["events"] > 0
    assert "baseline" in data
    assert "incidents" in data
    assert "recommendations" in data
    assert "by_type" in data["summary"]
    assert "by_level" in data["summary"]
    assert data["summary"]["高危"] == data["summary"]["by_level"]["高危"]


def test_alert_export_returns_filtered_csv():
    with app.test_client() as client:
        client.get("/api/sample")
        response = client.get("/api/alerts/export?severity=高危")

    assert response.status_code == 200
    assert response.content_type.startswith("text/csv")
    assert "attachment;" in response.headers["Content-Disposition"]

    decoded = response.data.decode("utf-8-sig")
    rows = list(csv.DictReader(decoded.splitlines()))
    assert rows
    assert all(row["level"] == "高危" for row in rows)
    assert {"alert_type", "source_ip", "evidence", "rule_id"} <= set(rows[0])


def test_live_lab_log_endpoint_analyzes_runtime_website_log():
    lab_log = Path(__file__).resolve().parents[1] / "交大学生成绩管理系统_vuln_lab" / "data" / "access_log.csv"
    lab_log.write_text(
        "timestamp,source_ip,target_ip,port,path,status_code,username,login_success,method,protocol,host,user_agent,bytes_sent,duration_ms,tls_fingerprint\n"
        "2026-07-20T10:00:00,127.0.0.1,10.0.0.42,8001,/api/login,200,2024001,true,POST,tcp,127.0.0.1,grade-lab-demo/1.0,680,30,ja3-browser\n"
        "2026-07-20T10:00:02,127.0.0.1,10.0.0.42,8001,/api/grades?course=信息安全导论' or 1=1--,200,2024001,,GET,tcp,127.0.0.1,grade-lab-demo/1.0,4500,40,ja3-browser\n"
        "2026-07-20T10:00:04,127.0.0.1,10.0.0.42,8001,/api/grades?course=信息安全导论' or 1=1--,200,2024001,,GET,tcp,127.0.0.1,grade-lab-demo/1.0,4500,38,ja3-browser\n"
        "2026-07-20T10:00:06,127.0.0.1,10.0.0.42,8001,/api/grades?course=信息安全导论' or 1=1--,200,2024001,,GET,tcp,127.0.0.1,grade-lab-demo/1.0,4500,36,ja3-browser\n",
        encoding="utf-8",
    )

    with app.test_client() as client:
        response = client.get("/api/analyze/lab-live")
        dashboard_response = client.get("/api/dashboard")

    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "靶场实时访问日志"
    assert data["events"] == 4
    sql_alert = next(alert for alert in data["alerts"] if alert["alert_type"] == "SQL注入尝试")
    assert sql_alert["count"] == 3
    assert sql_alert["timestamp"] == "2026-07-20T10:00:02"

    assert dashboard_response.status_code == 200
    dashboard_ids = dashboard_response.get_json()["ids"]
    assert dashboard_ids["total_hits"] >= 3
    assert dashboard_ids["type_counts"]["SQL注入尝试"] == 3


def test_lab_log_watcher_ignores_existing_log_until_it_changes(monkeypatch, tmp_path):
    lab_log = tmp_path / "access_log.csv"
    lab_log.write_text(
        "timestamp,source_ip,target_ip,port,path,status_code,username,login_success,method,protocol,host,user_agent,bytes_sent,duration_ms,tls_fingerprint\n"
        "2026-07-20T10:00:00,127.0.0.1,10.0.0.42,8001,/api/grades?course=信息安全导论' or 1=1--,200,2024001,,GET,tcp,127.0.0.1,browser,4500,40,ja3-browser\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "LAB_ACCESS_LOG", lab_log)
    previous_signature = app_module._lab_log_signature
    previous_seen_rows = app_module._lab_log_seen_rows
    app_module._lab_log_signature = app_module.lab_log_signature()
    app_module._lab_log_seen_rows = app_module.lab_log_row_count()
    previous_analysis = app_module._last_analysis
    app_module._last_analysis = {
        "events": 0,
        "alerts": [],
        "incidents": [],
        "summary": {},
        "baseline": {},
        "metadata": {},
        "source": "",
        "recommendations": [],
    }

    try:
        app_module.analyze_lab_log_if_changed()
        assert app_module._last_analysis["events"] == 0
        assert app_module._last_analysis["alerts"] == []
    finally:
        app_module._last_analysis = previous_analysis
        app_module._lab_log_signature = previous_signature
        app_module._lab_log_seen_rows = previous_seen_rows


def test_lab_log_watcher_ignores_old_sql_rows_when_benign_row_is_appended(monkeypatch, tmp_path):
    lab_log = tmp_path / "access_log.csv"
    lab_log.write_text(
        "timestamp,source_ip,target_ip,port,path,status_code,username,login_success,method,protocol,host,user_agent,bytes_sent,duration_ms,tls_fingerprint\n"
        "2026-07-20T10:00:00,127.0.0.1,10.0.0.42,8001,/api/grades?course=信息安全导论' or 1=1--,200,2024001,,GET,tcp,127.0.0.1,browser,4500,40,ja3-browser\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "LAB_ACCESS_LOG", lab_log)
    previous_signature = app_module._lab_log_signature
    previous_seen_rows = app_module._lab_log_seen_rows
    previous_analysis = app_module._last_analysis
    app_module._lab_log_signature = app_module.lab_log_signature()
    app_module._lab_log_seen_rows = app_module.lab_log_row_count()
    app_module._last_analysis = {
        "events": 0,
        "alerts": [],
        "incidents": [],
        "summary": {},
        "baseline": {},
        "metadata": {},
        "source": "",
        "recommendations": [],
    }

    try:
        with lab_log.open("a", encoding="utf-8", newline="") as log_file:
            log_file.write(
                "2026-07-28T22:00:00,127.0.0.1,10.0.0.42,8001,/,200,,,GET,tcp,127.0.0.1,browser,680,30,ja3-browser\n"
            )

        app_module.analyze_lab_log_if_changed()

        assert app_module._last_analysis["events"] == 1
        assert not any(alert["alert_type"] == "SQL注入尝试" for alert in app_module._last_analysis["alerts"])
        assert app_module._lab_log_seen_rows == 2
    finally:
        app_module._last_analysis = previous_analysis
        app_module._lab_log_signature = previous_signature
        app_module._lab_log_seen_rows = previous_seen_rows


def test_lab_log_watcher_detects_sql_in_new_appended_rows(monkeypatch, tmp_path):
    lab_log = tmp_path / "access_log.csv"
    lab_log.write_text(
        "timestamp,source_ip,target_ip,port,path,status_code,username,login_success,method,protocol,host,user_agent,bytes_sent,duration_ms,tls_fingerprint\n"
        "2026-07-28T22:00:00,127.0.0.1,10.0.0.42,8001,/,200,,,GET,tcp,127.0.0.1,browser,680,30,ja3-browser\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "LAB_ACCESS_LOG", lab_log)
    previous_signature = app_module._lab_log_signature
    previous_seen_rows = app_module._lab_log_seen_rows
    previous_analysis = app_module._last_analysis
    app_module._lab_log_signature = app_module.lab_log_signature()
    app_module._lab_log_seen_rows = app_module.lab_log_row_count()
    app_module._last_analysis = {
        "events": 0,
        "alerts": [],
        "incidents": [],
        "summary": {},
        "baseline": {},
        "metadata": {},
        "source": "",
        "recommendations": [],
    }

    try:
        with lab_log.open("a", encoding="utf-8", newline="") as log_file:
            log_file.write(
                "2026-07-28T22:00:02,127.0.0.1,10.0.0.42,8001,/api/grades?course=信息安全导论' or 1=1--,200,2024001,,GET,tcp,127.0.0.1,browser,4500,40,ja3-browser\n"
            )

        app_module.analyze_lab_log_if_changed()

        sql_alert = next(alert for alert in app_module._last_analysis["alerts"] if alert["alert_type"] == "SQL注入尝试")
        assert app_module._last_analysis["events"] == 1
        assert sql_alert["count"] == 1
        assert sql_alert["timestamp"] == "2026-07-28T22:00:02"
        assert app_module._lab_log_seen_rows == 2
    finally:
        app_module._last_analysis = previous_analysis
        app_module._lab_log_signature = previous_signature
        app_module._lab_log_seen_rows = previous_seen_rows


def test_lab_log_watcher_keeps_bruteforce_alert_after_successful_login(monkeypatch, tmp_path):
    lab_log = tmp_path / "access_log.csv"
    lab_log.write_text(
        "timestamp,source_ip,target_ip,port,path,status_code,username,login_success,method,protocol,host,user_agent,bytes_sent,duration_ms,tls_fingerprint\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "LAB_ACCESS_LOG", lab_log)
    previous_signature = app_module._lab_log_signature
    previous_seen_rows = app_module._lab_log_seen_rows
    previous_analysis = app_module._last_analysis
    app_module._lab_log_signature = app_module.lab_log_signature()
    app_module._lab_log_seen_rows = app_module.lab_log_row_count()
    app_module._last_analysis = app_module.empty_analysis()

    try:
        with lab_log.open("a", encoding="utf-8", newline="") as log_file:
            for index in range(5):
                log_file.write(
                    f"2026-07-28T22:00:{index:02d},127.0.0.1,10.0.0.42,8001,/api/login,401,admin,false,POST,tcp,127.0.0.1,browser,220,20,ja3-browser\n"
                )

        app_module.analyze_lab_log_if_changed()

        assert any(alert["alert_type"] == "暴力登录" for alert in app_module._last_analysis["alerts"])
        brute_alert_count = len(app_module._last_analysis["alerts"])

        with lab_log.open("a", encoding="utf-8", newline="") as log_file:
            log_file.write(
                "2026-07-28T22:01:00,127.0.0.1,10.0.0.42,8001,/api/login,200,2024001,true,POST,tcp,127.0.0.1,browser,680,30,ja3-browser\n"
            )

        app_module.analyze_lab_log_if_changed()

        assert app_module._last_analysis["events"] == 6
        assert len(app_module._last_analysis["alerts"]) == brute_alert_count
        assert any(alert["alert_type"] == "暴力登录" for alert in app_module._last_analysis["alerts"])
        assert app_module._lab_log_seen_rows == 6
    finally:
        app_module._last_analysis = previous_analysis
        app_module._lab_log_signature = previous_signature
        app_module._lab_log_seen_rows = previous_seen_rows


    lab_log = tmp_path / "access_log.csv"
    monkeypatch.setattr(app_module, "LAB_ACCESS_LOG", lab_log)
    previous_signature = app_module._lab_log_signature
    previous_seen_rows = app_module._lab_log_seen_rows
    previous_analysis = app_module._last_analysis
    app_module._lab_log_signature = None
    app_module._lab_log_seen_rows = None
    app_module._last_analysis = {
        "events": 0,
        "alerts": [],
        "incidents": [],
        "summary": {},
        "baseline": {},
        "metadata": {},
        "source": "",
        "recommendations": [],
    }

    try:
        app_module.analyze_lab_log_if_changed()
        lab_log.write_text(
            "timestamp,source_ip,target_ip,port,path,status_code,username,login_success,method,protocol,host,user_agent,bytes_sent,duration_ms,tls_fingerprint\n"
            "2026-07-20T10:00:00,127.0.0.1,10.0.0.42,8001,/api/grades?course=信息安全导论' or 1=1--,200,2024001,,GET,tcp,127.0.0.1,browser,4500,40,ja3-browser\n",
            encoding="utf-8",
        )
        app_module.analyze_lab_log_if_changed()
        assert app_module._last_analysis["events"] == 0
        assert app_module._last_analysis["alerts"] == []
        assert app_module._lab_log_signature == app_module.lab_log_signature()
        assert app_module._lab_log_seen_rows == 1
    finally:
        app_module._last_analysis = previous_analysis
        app_module._lab_log_signature = previous_signature
        app_module._lab_log_seen_rows = previous_seen_rows


def test_alert_export_cold_start_uses_sample_data():
    previous_analysis = app_module._last_analysis
    app_module._last_analysis = {
        "events": 0,
        "alerts": [],
        "incidents": [],
        "summary": {},
        "baseline": {},
        "metadata": {},
        "source": "",
        "recommendations": [],
    }

    try:
        with app.test_client() as client:
            response = client.get("/api/alerts/export")
    finally:
        app_module._last_analysis = previous_analysis

    assert response.status_code == 200
    rows = list(csv.DictReader(response.data.decode("utf-8-sig").splitlines()))
    assert rows
    assert rows[0]["alert_type"]


def test_old_csv_upload_still_works():
    content = SAMPLE_LOG.read_text(encoding="utf-8")
    response = upload_csv(content)

    assert response.status_code == 200
    data = response.get_json()
    assert data["events"] > 0
    assert data["alerts"]
    assert data["summary"]["by_level"]["中危"] >= 0


def test_sample_analysis_emits_realtime_result(monkeypatch):
    emitted = []
    monkeypatch.setattr(app_module.socketio, "emit", lambda event, data, **kwargs: emitted.append((event, data, kwargs)))

    with app.test_client() as client:
        response = client.get("/api/sample")

    assert response.status_code == 200
    assert emitted
    event, data, kwargs = emitted[-1]
    assert event == "analysis_result"
    assert data["source"] == "示例数据"
    assert data["events"] > 0
    assert kwargs == {}


def test_socket_connect_emits_current_analysis(monkeypatch):
    emitted = []
    monkeypatch.setattr(app_module.socketio, "emit", lambda event, data, **kwargs: emitted.append((event, data, kwargs)))
    monkeypatch.setattr(app_module, "start_lab_log_watcher", lambda: None)
    monkeypatch.setattr(app_module, "request", SimpleNamespace(sid="client-1"))

    app_module.on_connect()

    assert emitted == [("analysis_result", app_module._last_analysis, {"to": "client-1"})]


def test_extended_parser_supports_optional_fields():
    events = parse_csv_log(EXTENDED_SAMPLE_LOG)

    assert any(event.user_agent for event in events)
    assert any(event.bytes_sent is not None for event in events)
    assert any(event.duration_ms is not None for event in events)
    assert any(event.tls_fingerprint for event in events)


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


def test_defense_module_mock_state_persists_rules(monkeypatch):
    monkeypatch.setattr(defense_module, "is_kernel_available", lambda: False)
    defense_module._MOCK_RULES.clear()
    defense_module._MOCK_NEXT_RULE_ID = 1
    defense_module._MOCK_ENABLED = False
    defense_module._MOCK_DEFAULT_POLICY = "accept"

    defense_module.set_enable(True)
    defense_module.set_default_policy("deny")
    defense_module.add_rule({"priority": 20, "protocol": "tcp", "saddr": "192.168.1.10", "dport": 80, "action": "drop", "enabled": True})
    [rule] = defense_module.list_rules()
    rule["priority"] = 999
    defense_module.update_rule({"id": rule["id"], "priority": 5, "protocol": "udp", "daddr": "10.0.0.2", "sport": 53, "action": "accept", "enabled": False})
    [updated] = defense_module.list_rules()

    assert defense_module.get_status() == {"enabled": True, "default_policy": "deny", "rule_count": 1, "uptime_seconds": 0}
    assert updated["priority"] == 5
    assert updated["protocol_num"] == 17
    assert updated["protocol"] == "udp"
    assert updated["daddr"] == "10.0.0.2"
    assert updated["sport"] == 53
    assert updated["action"] == "accept"
    assert updated["enabled"] is False

    defense_module.del_rule(updated["id"])
    assert defense_module.list_rules() == []


def test_defense_mock_mode_persists_rule_crud(monkeypatch):
    monkeypatch.setattr(app_module, "defense_is_mock_mode", lambda: True)
    monkeypatch.setattr(app_module, "defense_set_enable", lambda enabled: None)

    rules = []
    next_id = 1

    def add_rule(rule):
        nonlocal next_id
        saved = dict(rule)
        saved.update({"id": next_id, "protocol_num": 6, "protocol": "tcp", "hit_count": 0})
        next_id += 1
        rules.append(saved)

    def update_rule(rule):
        for index, existing in enumerate(rules):
            if existing["id"] == rule["id"]:
                rules[index] = {**existing, **rule}
                return True
        return False

    def delete_rule(rule_id):
        before = len(rules)
        rules[:] = [rule for rule in rules if rule["id"] != rule_id]
        return len(rules) != before

    monkeypatch.setattr(app_module, "defense_status", lambda: {"enabled": True, "default_policy": "accept", "rule_count": len(rules), "uptime_seconds": 0})
    monkeypatch.setattr(app_module, "defense_list_rules", lambda: [dict(rule) for rule in rules])
    monkeypatch.setattr(app_module, "defense_add_rule", add_rule)
    monkeypatch.setattr(app_module, "defense_update_rule", update_rule)
    monkeypatch.setattr(app_module, "defense_del_rule", delete_rule)

    with app.test_client() as client:
        enable_response = client.post("/api/defense/enable", json={"enabled": True})
        create_response = client.post("/api/defense/rules", json={"priority": 10, "protocol": "tcp", "saddr": "192.168.1.10", "dport": 80, "action": "drop", "enabled": True})
        list_response = client.get("/api/defense/rules")
        rule_id = list_response.get_json()["data"][0]["id"]
        update_response = client.put(f"/api/defense/rules/{rule_id}", json={"priority": 5, "protocol": "tcp", "saddr": "192.168.1.10", "dport": 443, "action": "accept", "enabled": False})
        updated_response = client.get("/api/defense/rules")
        delete_response = client.delete(f"/api/defense/rules/{rule_id}")
        empty_response = client.get("/api/defense/rules")
        missing_update_response = client.put("/api/defense/rules/999", json={"priority": 1, "protocol": "tcp", "dport": 1, "action": "drop", "enabled": True})
        missing_delete_response = client.delete("/api/defense/rules/999")

    assert enable_response.status_code == 200
    assert create_response.status_code == 200
    assert list_response.get_json()["data"][0]["dport"] == 80
    assert update_response.status_code == 200
    updated_rule = updated_response.get_json()["data"][0]
    assert updated_rule["priority"] == 5
    assert updated_rule["dport"] == 443
    assert updated_rule["action"] == "accept"
    assert updated_rule["enabled"] is False
    assert delete_response.status_code == 200
    assert empty_response.get_json()["data"] == []
    assert missing_update_response.status_code == 404
    assert missing_delete_response.status_code == 404


def test_dashboard_reports_mock_ips_availability(monkeypatch):
    monkeypatch.setattr(app_module, "defense_status", lambda: {"enabled": False, "default_policy": "accept", "rule_count": 0, "uptime_seconds": 0})
    monkeypatch.setattr(app_module, "defense_get_stats", lambda: {"total_checked": 0, "total_dropped": 0, "total_accepted": 0, "drop_rate": 0, "protocols": {"icmp": 0, "tcp": 0, "udp": 0}})
    monkeypatch.setattr(app_module, "defense_is_mock_mode", lambda: True)

    with app.test_client() as client:
        response = client.get("/api/dashboard")

    assert response.status_code == 200
    assert response.get_json()["ips"]["availability"] == "mock"


def test_dashboard_still_loads_after_clearing_alerts(monkeypatch, tmp_path):
    lab_log = tmp_path / "access_log.csv"
    lab_log.write_text(
        "timestamp,source_ip,target_ip,port,path,status_code,username,login_success,method,protocol,host,user_agent,bytes_sent,duration_ms,tls_fingerprint\n"
        "2026-07-28T22:00:00,127.0.0.1,10.0.0.42,8001,/api/login,401,admin,false,POST,tcp,127.0.0.1,browser,220,20,ja3-browser\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "LAB_ACCESS_LOG", lab_log)
    emitted = []
    monkeypatch.setattr(app_module.socketio, "emit", lambda event, data, **kwargs: emitted.append((event, data, kwargs)))
    previous_analysis = app_module._last_analysis
    previous_signature = app_module._lab_log_signature
    previous_seen_rows = app_module._lab_log_seen_rows

    try:
        app_module._lab_log_signature = app_module.lab_log_signature()
        app_module._lab_log_seen_rows = app_module.lab_log_row_count()
        with app.test_client() as client:
            client.get("/api/sample")
            clear_response = client.post("/api/alerts/clear")
            dashboard_response = client.get("/api/dashboard")

        assert clear_response.status_code == 200
        assert dashboard_response.status_code == 200
        ids = dashboard_response.get_json()["ids"]
        assert ids["events"] == 0
        assert ids["total_alerts"] == 0
        assert ids["summary"]["by_level"] == {"高危": 0, "中危": 0, "低危": 0}
        assert app_module._lab_log_seen_rows == 0
        assert lab_log.read_text(encoding="utf-8").count("\n") == 1
        assert emitted[-1][0] == "analysis_result"
        assert emitted[-1][1]["alerts"] == []
    finally:
        app_module._last_analysis = previous_analysis
        app_module._lab_log_signature = previous_signature
        app_module._lab_log_seen_rows = previous_seen_rows


def upload_csv(content: str):
    with app.test_client() as client:
        return client.post(
            "/api/analyze",
            data={"file": (BytesIO(content.encode("utf-8")), "logs.csv")},
            content_type="multipart/form-data",
        )
