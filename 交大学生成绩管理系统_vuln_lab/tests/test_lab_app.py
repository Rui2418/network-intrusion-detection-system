from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parents[1]
IDS_DIR = LAB_DIR.parent
sys.path.insert(0, str(LAB_DIR))
sys.path.insert(0, str(IDS_DIR))

from app import app, reset_state  # noqa: E402
from src.parser.log_parser import parse_csv_log  # noqa: E402


def setup_function():
    reset_state(clear_audit=True)


def login(client, username="teacher", password="teacher123"):
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.get_json()["data"]["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_student_can_only_view_own_grades():
    with app.test_client() as client:
        token = login(client, "2024001", "123456")
        response = client.get("/api/grades", headers=auth(token))

    assert response.status_code == 200
    items = response.get_json()["data"]["items"]
    assert items
    assert {item["student_id"] for item in items} == {"2024001"}


def test_teacher_can_update_grade_and_reset_restores_seed():
    with app.test_client() as client:
        token = login(client)
        update = client.put(
            "/api/grades",
            headers=auth(token),
            json={"student_id": "2024001", "course": "信息安全导论", "score": "60"},
        )
        assert update.status_code == 200
        changed = client.get("/api/grades?student_id=2024001", headers=auth(token)).get_json()["data"]["items"]
        assert any(item["course"] == "信息安全导论" and item["score"] == 60 for item in changed)

        reset = client.post("/api/lab/reset")
        assert reset.status_code == 200
        new_token = login(client)
        restored = client.get("/api/grades?student_id=2024001", headers=auth(new_token)).get_json()["data"]["items"]
        assert any(item["course"] == "信息安全导论" and item["score"] == 88 for item in restored)


def test_student_cannot_update_grade():
    with app.test_client() as client:
        token = login(client, "2024001", "123456")
        response = client.put(
            "/api/grades",
            headers=auth(token),
            json={"student_id": "2024001", "course": "信息安全导论", "score": "99"},
        )

    assert response.status_code == 403


def test_homepage_looks_like_normal_grade_system_without_lab_controls():
    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "交大学生成绩管理系统" in html
    assert "训练场景" not in html
    assert "靶场" not in html
    assert "IDS" not in html
    assert "审计日志" not in html
    assert "导出" not in html


def test_student_can_query_other_student_by_direct_parameter():
    with app.test_client() as client:
        token = login(client, "2024001", "123456")
        response = client.get("/api/grades?student_id=2024002", headers=auth(token))

    assert response.status_code == 200
    items = response.get_json()["data"]["items"]
    assert items
    assert {item["student_id"] for item in items} == {"2024002"}


def test_sqli_payload_returns_all_grades_and_audits_it():
    with app.test_client() as client:
        token = login(client, "2024001", "123456")
        response = client.get("/api/grades?student_id=2024001%27%20or%201=1--", headers=auth(token))
        assert response.status_code == 200
        items = response.get_json()["data"]["items"]
        student_ids = {item["student_id"] for item in items}
        assert {"2024001", "2024002", "2024003"}.issubset(student_ids)

        audit = client.get("/api/lab/audit")
        records = audit.get_json()["data"]["items"]
        assert any(
            item["action"] == "vulnerable_grade_query"
            and item["target"] == "2024001' or 1=1--"
            and item["scenario"] == "sqli_probe"
            for item in records
        )

        export = client.get("/api/lab/export-log")
        rows = list(csv.DictReader(io.StringIO(export.get_data(as_text=True))))
        assert any(row["path"] == "/lab/vulnerable_grade_query" for row in rows)
        assert any("or%201=1" in row["path"] for row in rows)


def test_reset_keeps_vulnerable_site_seeded_without_showing_lab_controls():
    with app.test_client() as client:
        reset = client.post("/api/lab/reset")
        assert reset.status_code == 200
        token = login(client, "2024001", "123456")
        vulnerable = client.get("/api/grades?student_id=2024001%27%20or%201=1--", headers=auth(token))
        page = client.get("/")

    assert {"2024001", "2024002", "2024003"}.issubset(
        {item["student_id"] for item in vulnerable.get_json()["data"]["items"]}
    )
    assert "训练场景" not in page.get_data(as_text=True)


def test_scenario_activation_writes_audit_and_exportable_ids_csv():
    with app.test_client() as client:
        response = client.post("/api/lab/scenarios/sqli_probe/activate")
        assert response.status_code == 200

        audit = client.get("/api/lab/audit")
        records = audit.get_json()["data"]["items"]
        assert any(item["action"] == "activate_scenario" and item["scenario"] == "sqli_probe" for item in records)

        export = client.get("/api/lab/export-log")
        assert export.status_code == 200
        text = export.get_data(as_text=True)
        rows = list(csv.DictReader(io.StringIO(text)))
        assert rows
        assert any("union%20select" in row["path"] for row in rows)


def test_exported_log_file_can_be_parsed_by_ids_parser():
    with app.test_client() as client:
        client.post("/api/lab/scenarios/bruteforce_chain/activate")
        client.get("/api/lab/export-log")

    events = parse_csv_log(LAB_DIR / "data" / "exported_logs.csv")
    assert len(events) >= 4
    assert any(event.path == "/shell?cmd=whoami" for event in events)


def test_invalid_score_rejects_float_like_value():
    with app.test_client() as client:
        token = login(client)
        response = client.put(
            "/api/grades",
            headers=auth(token),
            json={"student_id": "2024001", "course": "信息安全导论", "score": "99.5"},
        )

    assert response.status_code == 400
