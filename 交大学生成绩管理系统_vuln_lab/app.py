from __future__ import annotations

import csv
import copy
import io
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
AUDIT_LOG = DATA_DIR / "audit_log.jsonl"
EXPORT_LOG = DATA_DIR / "exported_logs.csv"
CSV_FIELDS = [
    "timestamp",
    "source_ip",
    "target_ip",
    "port",
    "path",
    "status_code",
    "username",
    "login_success",
    "method",
    "protocol",
    "host",
    "user_agent",
    "bytes_sent",
    "duration_ms",
    "tls_fingerprint",
]

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))

USERS: dict[str, dict[str, Any]] = {}
GRADE_RECORDS: list[dict[str, Any]] = []
SESSIONS: dict[str, str] = {}
ACTIVE_SCENARIO: str | None = "sqli_probe"
SCENARIO_EVENTS: list[dict[str, Any]] = []


def load_json(name: str) -> Any:
    with (DATA_DIR / name).open("r", encoding="utf-8") as file:
        return json.load(file)


def write_jsonl(record: dict[str, Any]) -> None:
    with AUDIT_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")


def audit(action: str, *, username: str = "anonymous", target: str = "", result: str = "ok", detail: str = "") -> None:
    write_jsonl({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "username": username,
        "action": action,
        "target": target,
        "result": result,
        "scenario": ACTIVE_SCENARIO or "none",
        "simulated": True,
        "detail": detail,
    })


def reset_state(clear_audit: bool = True) -> None:
    global USERS, GRADE_RECORDS, ACTIVE_SCENARIO, SCENARIO_EVENTS
    USERS = copy.deepcopy(load_json("seed_users.json"))
    GRADE_RECORDS = copy.deepcopy(load_json("seed_grades.json"))
    SESSIONS.clear()
    ACTIVE_SCENARIO = "sqli_probe"
    scenario = get_scenario(ACTIVE_SCENARIO)
    SCENARIO_EVENTS = copy.deepcopy(scenario.get("log_events", [])) if scenario else []
    if clear_audit:
        AUDIT_LOG.write_text("", encoding="utf-8")
    write_export_log(build_export_events())


def public_user(username: str) -> dict[str, object]:
    user = USERS[username]
    result = {"username": username, "role": user["role"], "name": user["name"]}
    if user["role"] == "student":
        result["student_id"] = user["student_id"]
        result["class_name"] = user["class_name"]
    return result


def current_user() -> tuple[str | None, dict[str, object] | None]:
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    username = SESSIONS.get(token)
    if not username:
        return None, None
    return username, USERS[username]


def find_student(student_id: str) -> dict[str, object] | None:
    for user in USERS.values():
        if user.get("role") == "student" and user.get("student_id") == student_id:
            return user
    return None


def validate_score(raw_score: object) -> tuple[int | None, str | None]:
    if isinstance(raw_score, bool):
        return None, "成绩必须是 0 到 100 的整数"
    if isinstance(raw_score, int):
        score = raw_score
    elif isinstance(raw_score, str) and raw_score.strip().isdecimal():
        score = int(raw_score.strip())
    else:
        return None, "成绩必须是 0 到 100 的整数"
    if score < 0 or score > 100:
        return None, "成绩必须是 0 到 100 的整数"
    return score, None


def upsert_grade(student_id: str, course: str, score: int) -> None:
    student = find_student(student_id)
    if not student:
        return
    for item in GRADE_RECORDS:
        if item["student_id"] == student_id and item["course"] == course:
            item["student_name"] = student["name"]
            item["class_name"] = student["class_name"]
            item["score"] = score
            return
    GRADE_RECORDS.append({
        "student_id": student_id,
        "student_name": student["name"],
        "class_name": student["class_name"],
        "course": course,
        "score": score,
    })


def lab_mode_enabled(scenario_id: str) -> bool:
    return ACTIVE_SCENARIO == scenario_id


def looks_like_sqli_probe(value: str) -> bool:
    normalized = value.lower()
    markers = ("'", "--", " or ", "union", "select", "1=1")
    return any(marker in normalized for marker in markers)


def vulnerable_grade_query(student_id: str) -> list[dict[str, Any]] | None:
    if looks_like_sqli_probe(student_id):
        return GRADE_RECORDS
    return None


def scenario_summaries() -> list[dict[str, Any]]:
    scenarios = load_json("scenarios.json")
    return [
        {
            "id": item["id"],
            "name": item["name"],
            "description": item["description"],
            "expected_alerts": item.get("expected_alerts", []),
            "steps": item.get("steps", []),
            "active": item["id"] == ACTIVE_SCENARIO,
        }
        for item in scenarios
    ]


def get_scenario(scenario_id: str) -> dict[str, Any] | None:
    for item in load_json("scenarios.json"):
        if item["id"] == scenario_id:
            return item
    return None


def audit_to_csv_events() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not AUDIT_LOG.exists():
        return rows
    for line in AUDIT_LOG.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        status_code = 200 if record.get("result") == "ok" else 400
        if record.get("action") == "login" and record.get("result") != "ok":
            status_code = 401
        rows.append({
            "timestamp": record.get("timestamp", ""),
            "source_ip": "10.0.0.20",
            "target_ip": "10.0.0.42",
            "port": 8001,
            "path": f"/lab/{record.get('action', '')}",
            "status_code": status_code,
            "username": record.get("username", ""),
            "login_success": "true" if record.get("action") == "login" and record.get("result") == "ok" else "false" if record.get("action") == "login" else "",
            "method": "POST" if record.get("action") in {"login", "logout", "save_grade", "activate_scenario", "reset"} else "GET",
            "protocol": "tcp",
            "host": "grade-lab.local",
            "user_agent": "lab-ui",
            "bytes_sent": 600,
            "duration_ms": 35,
            "tls_fingerprint": "ja3-browser",
        })
    return rows


def write_export_log(events: list[dict[str, Any]]) -> None:
    with EXPORT_LOG.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for event in events:
            writer.writerow({field: event.get(field, "") for field in CSV_FIELDS})


def build_export_events() -> list[dict[str, Any]]:
    return [*audit_to_csv_events(), *SCENARIO_EVENTS]


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    user = USERS.get(username)
    if not user or user["password"] != password:
        audit("login", username=username or "anonymous", result="denied", detail="账号或密码错误")
        return jsonify({"code": 1, "message": "账号或密码错误"}), 401

    token = secrets.token_urlsafe(24)
    SESSIONS[token] = username
    audit("login", username=username, target=user["role"])
    return jsonify({"code": 0, "data": {"token": token, "user": public_user(username)}})


@app.get("/api/me")
def me():
    username, user = current_user()
    if not user or not username:
        return jsonify({"code": 1, "message": "请先登录"}), 401
    return jsonify({"code": 0, "data": public_user(username)})


@app.post("/api/logout")
def logout():
    username, _ = current_user()
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    SESSIONS.pop(token, None)
    audit("logout", username=username or "anonymous")
    return jsonify({"code": 0, "message": "OK"})


@app.get("/api/grades")
def list_grades():
    username, user = current_user()
    if not user:
        audit("list_grades", result="denied", detail="未登录访问")
        return jsonify({"code": 1, "message": "请先登录"}), 401

    student_id = request.args.get("student_id", "").strip()
    vulnerable_records = vulnerable_grade_query(student_id)
    if vulnerable_records is not None:
        audit(
            "vulnerable_grade_query",
            username=username or "anonymous",
            target=student_id,
            detail="lab_sqli_bypass_returned_all_grades",
        )
        return jsonify({"code": 0, "data": {"items": vulnerable_records, "total": len(vulnerable_records)}})

    if user["role"] == "student":
        target = student_id or user["student_id"]
        records = [item for item in GRADE_RECORDS if item["student_id"] == target]
    else:
        records = GRADE_RECORDS
        if student_id:
            records = [item for item in records if item["student_id"] == student_id]
        target = student_id or "all"
    audit("list_grades", username=username or "anonymous", target=target)
    return jsonify({"code": 0, "data": {"items": records, "total": len(records)}})


@app.put("/api/grades")
def save_grade():
    username, user = current_user()
    if not user:
        audit("save_grade", result="denied", detail="未登录访问")
        return jsonify({"code": 1, "message": "请先登录"}), 401
    if user["role"] != "teacher":
        audit("save_grade", username=username or "anonymous", result="denied", detail="学生用户不能登记或修改成绩")
        return jsonify({"code": 1, "message": "学生用户不能登记或修改成绩"}), 403

    data = request.get_json(silent=True) or {}
    student_id = str(data.get("student_id", "")).strip()
    course = str(data.get("course", "")).strip()
    raw_score = data.get("score")
    score, error = validate_score(raw_score)

    student = find_student(student_id)
    if not student:
        audit("save_grade", username=username or "anonymous", target=student_id, result="denied", detail="学生不存在")
        return jsonify({"code": 1, "message": "学生不存在"}), 400
    if not course:
        audit("save_grade", username=username or "anonymous", target=student_id, result="denied", detail="课程名称不能为空")
        return jsonify({"code": 1, "message": "课程名称不能为空"}), 400
    if error or score is None:
        audit("save_grade", username=username or "anonymous", target=student_id, result="denied", detail="成绩格式错误")
        return jsonify({"code": 1, "message": error}), 400

    upsert_grade(student_id, course, score)
    record = next(item for item in GRADE_RECORDS if item["student_id"] == student_id and item["course"] == course)
    audit("save_grade", username=username or "anonymous", target=f"{student_id}:{course}", detail=f"score={score}")
    return jsonify({"code": 0, "data": record, "message": "保存成功"})


@app.post("/api/lab/reset")
def lab_reset():
    reset_state(clear_audit=True)
    audit("reset", username="lab_operator", detail="恢复种子数据")
    return jsonify({"code": 0, "message": "靶场已重置"})


@app.get("/api/lab/scenarios")
def lab_scenarios():
    return jsonify({"code": 0, "data": {"active": ACTIVE_SCENARIO, "items": scenario_summaries()}})


@app.post("/api/lab/scenarios/<scenario_id>/activate")
def lab_activate_scenario(scenario_id: str):
    global ACTIVE_SCENARIO, SCENARIO_EVENTS
    scenario = get_scenario(scenario_id)
    if not scenario:
        audit("activate_scenario", username="lab_operator", target=scenario_id, result="denied", detail="场景不存在")
        return jsonify({"code": 1, "message": "场景不存在"}), 404

    ACTIVE_SCENARIO = scenario_id
    SCENARIO_EVENTS = copy.deepcopy(scenario.get("log_events", []))
    for update in scenario.get("grade_updates", []):
        score, error = validate_score(update.get("score"))
        if score is not None and not error:
            upsert_grade(str(update.get("student_id", "")), str(update.get("course", "")), score)
    audit("activate_scenario", username="lab_operator", target=scenario_id, detail=scenario["name"])
    write_export_log(build_export_events())
    return jsonify({"code": 0, "data": {"active": ACTIVE_SCENARIO, "scenario": scenario_summaries()}})


@app.get("/api/lab/audit")
def lab_audit():
    records: list[dict[str, Any]] = []
    if AUDIT_LOG.exists():
        for line in AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-80:]:
            if line.strip():
                records.append(json.loads(line))
    return jsonify({"code": 0, "data": {"items": records, "total": len(records)}})


@app.get("/api/lab/export-log")
def lab_export_log():
    events = build_export_events()
    write_export_log(events)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for event in events:
        writer.writerow({field: event.get(field, "") for field in CSV_FIELDS})
    audit("export_log", username="lab_operator", target="ids_csv", detail=f"events={len(events)}")
    return Response(
        buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=grade_lab_logs.csv"},
    )


reset_state(clear_audit=False)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8001, debug=True)
