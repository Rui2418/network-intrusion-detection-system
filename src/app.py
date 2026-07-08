from __future__ import annotations

import csv
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from src.detector.rules import detect_attacks
from src.parser.log_parser import parse_csv_log, parse_csv_rows
from src.utils.serialization import to_jsonable
from src.defense import (
    get_status as defense_status,
    set_enable as defense_set_enable,
    add_rule as defense_add_rule,
    del_rule as defense_del_rule,
    update_rule as defense_update_rule,
    list_rules as defense_list_rules,
    get_stats as defense_get_stats,
    set_default_policy as defense_set_default,
    clear_stats as defense_clear_stats,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"

app = Flask(__name__, static_folder=str(FRONTEND_DIST), static_url_path="/")
CORS(app)

_last_analysis = {
    "events": 0,
    "alerts": [],
    "summary": {"高危": 0, "中危": 0, "低危": 0},
    "source": "",
}


@app.get("/")
def index():
    dist_index = FRONTEND_DIST / "index.html"
    if dist_index.exists():
        return app.send_static_file("index.html")
    return render_template("index.html")


@app.get("/api/sample")
def analyze_sample():
    global _last_analysis
    events = parse_csv_log(DATA_DIR / "sample_logs.csv")
    alerts = detect_attacks(events)
    _last_analysis = {
        "events": len(events),
        "alerts": to_jsonable(alerts),
        "summary": summarize_alerts(alerts),
        "source": "示例数据",
    }
    return jsonify(_last_analysis)


@app.post("/api/analyze")
def analyze_upload():
    global _last_analysis
    uploaded = request.files.get("file")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "请上传 CSV 日志文件"}), 400

    try:
        content = uploaded.stream.read().decode("utf-8-sig").splitlines()
        events = list(parse_csv_rows(csv.DictReader(content)))
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        return jsonify({"error": f"CSV 日志格式错误：{exc}"}), 400

    alerts = detect_attacks(events)
    _last_analysis = {
        "events": len(events),
        "alerts": to_jsonable(alerts),
        "summary": summarize_alerts(alerts),
        "source": uploaded.filename,
    }
    return jsonify(_last_analysis)


@app.get("/api/alerts")
def get_alerts():
    alert_type = request.args.get("type", "")
    severity = request.args.get("severity", "")
    source_ip = request.args.get("source_ip", "")

    alerts = _last_analysis.get("alerts", [])
    if alert_type:
        alerts = [a for a in alerts if a.get("alert_type") == alert_type]
    if severity:
        alerts = [a for a in alerts if a.get("level") == severity]
    if source_ip:
        alerts = [a for a in alerts if a.get("source_ip") == source_ip]

    return jsonify({
        "total": len(alerts),
        "items": alerts,
    })


@app.get("/api/alerts/stats")
def get_alert_stats():
    alerts = _last_analysis.get("alerts", [])
    type_counts = {}
    severity_counts = {"高危": 0, "中危": 0, "低危": 0}
    source_counts = {}
    total_score = 0

    for a in alerts:
        t = a.get("alert_type", "未知")
        type_counts[t] = type_counts.get(t, 0) + 1
        s = a.get("level", "低危")
        severity_counts[s] = severity_counts.get(s, 0) + 1
        ip = a.get("source_ip", "未知")
        source_counts[ip] = source_counts.get(ip, 0) + 1
        total_score += a.get("score", 0)

    top_sources = sorted(source_counts.items(), key=lambda x: -x[1])[:5]

    return jsonify({
        "events": _last_analysis.get("events", 0),
        "total_alerts": len(alerts),
        "summary": _last_analysis.get("summary", {}),
        "type_counts": type_counts,
        "severity_counts": severity_counts,
        "top_sources": [{"ip": ip, "count": c} for ip, c in top_sources],
        "avg_score": round(total_score / len(alerts), 1) if alerts else 0,
        "source": _last_analysis.get("source", ""),
    })


@app.get("/api/alerts/recent")
def get_recent_alerts():
    alerts = _last_analysis.get("alerts", [])
    count = request.args.get("count", 20, type=int)
    severity = request.args.get("severity", "")
    filtered = alerts
    if severity:
        filtered = [a for a in alerts if a.get("level") == severity]
    return jsonify({
        "total": len(filtered),
        "items": filtered[:count],
    })


def summarize_alerts(alerts):
    summary = {"高危": 0, "中危": 0, "低危": 0}
    for alert in alerts:
        summary[alert.level] = summary.get(alert.level, 0) + 1
    return summary


@app.get("/api/dashboard")
def get_dashboard():
    ids_stats = get_alert_stats().get_json()
    try:
        ips_status = defense_status()
        ips_name = "available"
    except Exception:
        ips_status = {"enabled": False, "rule_count": 0, "uptime_seconds": 0, "default_policy": "accept"}
        ips_name = "unavailable"
    try:
        ips_stats = defense_get_stats()
    except Exception:
        ips_stats = {"total_checked": 0, "total_dropped": 0, "total_accepted": 0, "drop_rate": 0, "protocols": {"icmp": 0, "tcp": 0, "udp": 0}}
    return jsonify({
        "ids": ids_stats,
        "ips": {
            "status": ips_status,
            "stats": ips_stats,
            "availability": ips_name,
        },
    })


@app.get("/api/defense/status")
def api_defense_status():
    try: return jsonify({"code": 0, "data": defense_status()})
    except Exception as e: return jsonify({"code": 0, "data": {"enabled": False, "rule_count": 0, "uptime_seconds": 0, "note": str(e)}})

@app.post("/api/defense/enable")
def api_defense_enable():
    data = request.get_json(silent=True) or {}
    try: defense_set_enable(data.get("enabled", False))
    except: pass
    return jsonify({"code": 0, "message": "OK"})

@app.get("/api/defense/rules")
def api_defense_rules():
    try: rules = defense_list_rules()
    except: rules = []
    return jsonify({"code": 0, "data": rules})

@app.post("/api/defense/rules")
def api_defense_add_rule():
    data = request.get_json(silent=True) or {}
    proc = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17}
    if isinstance(data.get("protocol"), str):
        data["protocol"] = proc.get(data["protocol"], 0)
    try: defense_add_rule(data)
    except: pass
    return jsonify({"code": 0, "message": "OK"})

@app.put("/api/defense/rules/<int:rule_id>")
def api_defense_update_rule(rule_id):
    data = request.get_json(silent=True) or {}
    data["id"] = rule_id
    proc = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17}
    if isinstance(data.get("protocol"), str):
        data["protocol"] = proc.get(data["protocol"], 0)
    try: defense_update_rule(data)
    except: pass
    return jsonify({"code": 0, "message": "OK"})

@app.delete("/api/defense/rules/<int:rule_id>")
def api_defense_delete_rule(rule_id):
    try: defense_del_rule(rule_id)
    except: pass
    return jsonify({"code": 0, "message": "OK"})

@app.get("/api/defense/stats")
def api_defense_stats():
    try: return jsonify({"code": 0, "data": defense_get_stats()})
    except: return jsonify({"code": 0, "data": {"total_checked": 0, "total_dropped": 0, "total_accepted": 0, "drop_rate": 0}})

@app.post("/api/defense/stats/clear")
def api_defense_clear_stats():
    try: defense_clear_stats()
    except: pass
    return jsonify({"code": 0, "message": "OK"})

@app.get("/api/defense/default-policy")
def api_defense_get_default():
    try:
        status = defense_status()
        return jsonify({"code": 0, "data": {"policy": status.get("default_policy", "accept")}})
    except: return jsonify({"code": 0, "data": {"policy": "accept"}})

@app.put("/api/defense/default-policy")
def api_defense_set_default_policy():
    data = request.get_json(silent=True) or {}
    try: defense_set_default(data.get("policy", "accept"))
    except: pass
    return jsonify({"code": 0, "message": "OK"})

@app.get("/api/interfaces")
def api_interfaces():
    import subprocess, platform
    ifaces = []
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if ":" in line and "adapter" not in line.lower():
                    name = line.strip().rstrip(":")
                    if name: ifaces.append(name)
        else:
            result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if ": " in line:
                    parts = line.split(": ")
                    if len(parts) >= 2:
                        ifaces.append(parts[1].split(":")[0].split("@")[0])
    except:
        ifaces = ["eth0", "wlan0", "lo"]
    return jsonify({"code": 0, "data": ifaces[:20]})


if __name__ == "__main__":
    app.run(debug=True)
