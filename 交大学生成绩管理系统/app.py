from __future__ import annotations

import secrets
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))

USERS = {
    "2024001": {"password": "123456", "role": "student", "name": "张明", "student_id": "2024001", "class_name": "网络安全 2401"},
    "2024002": {"password": "123456", "role": "student", "name": "李娜", "student_id": "2024002", "class_name": "网络安全 2401"},
    "2024003": {"password": "123456", "role": "student", "name": "王强", "student_id": "2024003", "class_name": "网络安全 2402"},
    "teacher": {"password": "teacher123", "role": "teacher", "name": "陈老师"},
}

GRADE_RECORDS = [
    {"student_id": "2024001", "student_name": "张明", "class_name": "网络安全 2401", "course": "信息安全导论", "score": 88},
    {"student_id": "2024001", "student_name": "张明", "class_name": "网络安全 2401", "course": "网络攻防实验", "score": 92},
    {"student_id": "2024002", "student_name": "李娜", "class_name": "网络安全 2401", "course": "信息安全导论", "score": 91},
    {"student_id": "2024002", "student_name": "李娜", "class_name": "网络安全 2401", "course": "网络攻防实验", "score": 86},
    {"student_id": "2024003", "student_name": "王强", "class_name": "网络安全 2402", "course": "信息安全导论", "score": 79},
    {"student_id": "2024003", "student_name": "王强", "class_name": "网络安全 2402", "course": "网络攻防实验", "score": 83},
]

SESSIONS: dict[str, str] = {}


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
        return jsonify({"code": 1, "message": "账号或密码错误"}), 401

    token = secrets.token_urlsafe(24)
    SESSIONS[token] = username
    return jsonify({"code": 0, "data": {"token": token, "user": public_user(username)}})


@app.get("/api/me")
def me():
    username, user = current_user()
    if not user or not username:
        return jsonify({"code": 1, "message": "请先登录"}), 401
    return jsonify({"code": 0, "data": public_user(username)})


@app.post("/api/logout")
def logout():
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    SESSIONS.pop(token, None)
    return jsonify({"code": 0, "message": "OK"})


@app.get("/api/grades")
def list_grades():
    _, user = current_user()
    if not user:
        return jsonify({"code": 1, "message": "请先登录"}), 401

    if user["role"] == "student":
        records = [item for item in GRADE_RECORDS if item["student_id"] == user["student_id"]]
    else:
        student_id = request.args.get("student_id", "").strip()
        records = GRADE_RECORDS
        if student_id:
            records = [item for item in records if item["student_id"] == student_id]
    return jsonify({"code": 0, "data": {"items": records, "total": len(records)}})


@app.put("/api/grades")
def save_grade():
    _, user = current_user()
    if not user:
        return jsonify({"code": 1, "message": "请先登录"}), 401
    if user["role"] != "teacher":
        return jsonify({"code": 1, "message": "学生用户不能登记或修改成绩"}), 403

    data = request.get_json(silent=True) or {}
    student_id = str(data.get("student_id", "")).strip()
    course = str(data.get("course", "")).strip()
    raw_score = data.get("score")

    if isinstance(raw_score, bool):
        return jsonify({"code": 1, "message": "成绩必须是 0 到 100 的整数"}), 400
    if isinstance(raw_score, int):
        score = raw_score
    elif isinstance(raw_score, str) and raw_score.strip().isdecimal():
        score = int(raw_score.strip())
    else:
        return jsonify({"code": 1, "message": "成绩必须是 0 到 100 的整数"}), 400

    student = find_student(student_id)
    if not student:
        return jsonify({"code": 1, "message": "学生不存在"}), 400
    if not course:
        return jsonify({"code": 1, "message": "课程名称不能为空"}), 400
    if score < 0 or score > 100:
        return jsonify({"code": 1, "message": "成绩必须是 0 到 100 的整数"}), 400

    record = None
    for item in GRADE_RECORDS:
        if item["student_id"] == student_id and item["course"] == course:
            record = item
            break

    if record is None:
        record = {
            "student_id": student_id,
            "student_name": student["name"],
            "class_name": student["class_name"],
            "course": course,
            "score": score,
        }
        GRADE_RECORDS.append(record)
    else:
        record["student_name"] = student["name"]
        record["class_name"] = student["class_name"]
        record["score"] = score

    return jsonify({"code": 0, "data": record, "message": "保存成功"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
