from __future__ import annotations

import csv
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from src.detector.rules import detect_attacks
from src.parser.log_parser import parse_csv_log, parse_csv_rows
from src.utils.serialization import to_jsonable

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/sample")
def analyze_sample():
    events = parse_csv_log(DATA_DIR / "sample_logs.csv")
    alerts = detect_attacks(events)
    return jsonify({
        "events": len(events),
        "alerts": to_jsonable(alerts),
        "summary": summarize_alerts(alerts),
    })


@app.post("/api/analyze")
def analyze_upload():
    uploaded = request.files.get("file")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "请上传 CSV 日志文件"}), 400

    try:
        content = uploaded.stream.read().decode("utf-8-sig").splitlines()
        events = list(parse_csv_rows(csv.DictReader(content)))
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        return jsonify({"error": f"CSV 日志格式错误：{exc}"}), 400

    alerts = detect_attacks(events)
    return jsonify({
        "events": len(events),
        "alerts": to_jsonable(alerts),
        "summary": summarize_alerts(alerts),
    })


def summarize_alerts(alerts):
    summary = {"高危": 0, "中危": 0, "低危": 0}
    for alert in alerts:
        summary[alert.level] = summary.get(alert.level, 0) + 1
    return summary


if __name__ == "__main__":
    app.run(debug=True)
