from __future__ import annotations

import csv
from datetime import datetime, MINYEAR
from pathlib import Path

from flask import Flask, jsonify, render_template, request

try:
    from flask_cors import CORS
except ModuleNotFoundError:
    def CORS(_app):
        return _app

try:
    from flask_socketio import SocketIO
except ModuleNotFoundError:
    class SocketIO:
        def __init__(self, app, **_kwargs):
            self.app = app

        def on(self, _event):
            def decorator(func):
                return func
            return decorator

        def run(self, app, **kwargs):
            app.run(**kwargs)

from src.detector.anomaly import detect_anomalies
from src.detector.correlation import correlate_alerts
from src.detector.models import AnalysisResult, Alert, Incident
from src.detector.rules import detect_attacks
from src.detector.signatures import detect_signature_attacks
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
from src.llm import (
    analyze_alert, suggest_defense, analyze_attack_chain,
    is_available as llm_available, get_config, update_config, test_connection, list_models,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"

app = Flask(__name__, static_folder=str(FRONTEND_DIST), static_url_path="/")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

_last_analysis = to_jsonable(AnalysisResult(
    events=0,
    alerts=[],
    incidents=[],
    summary={
        "高危": 0,
        "中危": 0,
        "低危": 0,
        "by_level": {"高危": 0, "中危": 0, "低危": 0},
        "by_type": {},
        "by_category": {},
        "top_sources": [],
        "top_targets": [],
        "timeline": [],
    },
    baseline={
        "request_rate_per_ip": [],
        "unique_ports_per_ip": [],
        "login_failures_per_ip": [],
        "data_coverage": {"bytes_sent": False, "duration_ms": False, "tls_fingerprint": False},
    },
    metadata={"detectors": ["rule", "signature", "anomaly", "correlation"], "generated_at": ""},
    source="",
    recommendations=[],
))

@app.get("/")
def index():
    dist_index = FRONTEND_DIST / "index.html"
    if dist_index.exists():
        return app.send_static_file("index.html")
    return render_template("index.html")


@app.get("/api/sample")
def analyze_sample():
    global _last_analysis
    events = parse_csv_log(DATA_DIR / "sample_logs_extended.csv")
    _last_analysis = analyze_events(events, source="示例数据")
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

    _last_analysis = analyze_events(events, source=uploaded.filename)
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

    summary = _last_analysis.get("summary", {})
    return jsonify({
        "events": _last_analysis.get("events", 0),
        "total_alerts": len(alerts),
        "summary": summary,
        "type_counts": summary.get("by_type", type_counts),
        "severity_counts": summary.get("by_level", severity_counts),
        "top_sources": [
            {"ip": item.get("source_ip", "未知"), "count": item.get("count", 0)}
            for item in summary.get("top_sources", [])
        ] or [{"ip": ip, "count": c} for ip, c in top_sources],
        "avg_score": round(total_score / len(alerts), 1) if alerts else 0,
        "source": _last_analysis.get("source", ""),
        "by_category": summary.get("by_category", {}),
        "timeline": summary.get("timeline", []),
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


def analyze_events(events, source: str) -> dict[str, object]:
    rule_alerts = detect_attacks(events)
    signature_alerts = detect_signature_attacks(events)
    anomaly_alerts, baseline = detect_anomalies(events)
    alerts = sorted(
        [*rule_alerts, *signature_alerts, *anomaly_alerts],
        key=lambda item: item.first_seen or item.last_seen or datetime(MINYEAR, 1, 1),
    )
    incidents = correlate_alerts(alerts)
    summary = summarize_alerts(alerts)
    result = AnalysisResult(
        events=len(events),
        alerts=alerts,
        incidents=incidents,
        summary=summary,
        baseline=baseline,
        metadata={
            "detectors": ["rule", "signature", "anomaly", "correlation"],
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        source=source,
        recommendations=build_recommendations(alerts, incidents),
    )
    return to_jsonable(result)


def summarize_alerts(alerts: list[Alert]) -> dict[str, object]:
    by_level = {"高危": 0, "中危": 0, "低危": 0}
    by_type: dict[str, int] = {}
    by_category: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    target_counts: dict[str, int] = {}
    timeline: dict[str, int] = {}

    for alert in alerts:
        by_level[alert.level] = by_level.get(alert.level, 0) + 1
        by_type[alert.alert_type] = by_type.get(alert.alert_type, 0) + 1
        by_category[alert.category] = by_category.get(alert.category, 0) + 1
        source_counts[alert.source_ip] = source_counts.get(alert.source_ip, 0) + 1
        target_counts[alert.target] = target_counts.get(alert.target, 0) + 1
        timestamp = alert.first_seen or alert.last_seen
        if timestamp is not None:
            key = timestamp.isoformat(timespec="seconds")
            timeline[key] = timeline.get(key, 0) + 1

    return {
        "高危": by_level.get("高危", 0),
        "中危": by_level.get("中危", 0),
        "低危": by_level.get("低危", 0),
        "by_level": by_level,
        "by_type": by_type,
        "by_category": by_category,
        "top_sources": [
            {"source_ip": source_ip, "count": count}
            for source_ip, count in sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
        "top_targets": [
            {"target": target, "count": count}
            for target, count in sorted(target_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
        "timeline": [
            {"timestamp": timestamp, "count": count}
            for timestamp, count in sorted(timeline.items())
        ],
    }


def build_recommendations(alerts: list[Alert], incidents: list[Incident]) -> list[dict[str, object]]:
    recommendations: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    for incident in incidents:
        for action in incident.recommended_actions:
            key = (incident.source_ip, action)
            if key in seen:
                continue
            seen.add(key)
            recommendations.append({
                "source_ip": incident.source_ip,
                "action": action,
                "reason": incident.evidence,
                "severity": incident.level,
                "score": incident.score,
                "stages": list(incident.stages),
            })

    for alert in alerts:
        if alert.level != "高危":
            continue
        key = (alert.source_ip, alert.alert_type)
        if key in seen:
            continue
        seen.add(key)
        recommendations.append({
            "source_ip": alert.source_ip,
            "action": "加入高风险观察名单",
            "reason": alert.evidence,
            "severity": alert.level,
            "score": alert.score,
            "alert_type": alert.alert_type,
        })

    return recommendations


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


@app.get("/api/llm/status")
def api_llm_status():
    return jsonify({"code": 0, "data": {"available": llm_available()}})


@app.post("/api/alerts/analyze")
def api_analyze_alert():
    alert = (request.get_json(silent=True) or {}).get("alert", {})
    if not alert:
        return jsonify({"code": 1, "message": "缺少告警数据"}), 400
    result = analyze_alert(alert)
    return jsonify({"code": 0, "data": {"analysis": result, "llm_used": llm_available()}})


@app.post("/api/alerts/defend")
def api_defend_alert():
    alert = (request.get_json(silent=True) or {}).get("alert", {})
    if not alert:
        return jsonify({"code": 1, "message": "缺少告警数据"}), 400
    suggestion = suggest_defense(alert)
    rule = suggestion.get("rule", {})
    try:
        proc = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17}
        rule["protocol"] = proc.get(rule.get("protocol", "any"), 0)
        defense_add_rule(rule)
        rule_created = True
    except Exception:
        rule_created = False
    return jsonify({
        "code": 0,
        "data": {
            "rule": rule,
            "reason": suggestion.get("reason", ""),
            "rule_created": rule_created,
            "llm_used": llm_available(),
        },
    })


@app.post("/api/alerts/chain")
def api_attack_chain():
    alerts = (request.get_json(silent=True) or {}).get("alerts", [])
    if not alerts:
        alerts = _last_analysis.get("alerts", [])
    result = analyze_attack_chain(alerts)
    return jsonify({"code": 0, "data": {"chain": result, "llm_used": llm_available()}})


@app.get("/api/llm/config")
def api_llm_config():
    cfg = get_config()
    cfg.pop("api_key", None)
    return jsonify({"code": 0, "data": cfg})


@app.put("/api/llm/config")
def api_llm_update_config():
    data = request.get_json(silent=True) or {}
    update_config(data)
    return jsonify({"code": 0, "data": get_config()})


@app.post("/api/llm/test")
def api_llm_test():
    cfg = request.get_json(silent=True) or None
    if cfg:
        result = test_connection(cfg)
    else:
        result = test_connection()
    return jsonify({"code": 0, "data": result})


@app.get("/api/llm/models")
def api_llm_models():
    models = list_models()
    return jsonify({"code": 0, "data": models})


@socketio.on('connect')
def on_connect():
    pass


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
