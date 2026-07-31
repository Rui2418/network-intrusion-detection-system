from __future__ import annotations

import csv
import threading
import time
from datetime import datetime, MINYEAR
from io import StringIO
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

try:
    from flask_cors import CORS
except ModuleNotFoundError:
    def CORS(_app):
        return _app

try:
    from flask_socketio import SocketIO
except ModuleNotFoundError:
    # 未安装 SocketIO 依赖时保留同步接口可用，实时推送能力退化为空实现。
    class SocketIO:
        def __init__(self, app, **_kwargs):
            self.app = app

        def on(self, _event):
            def decorator(func):
                return func
            return decorator

        def emit(self, *_args, **_kwargs):
            return None

        def sleep(self, seconds):
            time.sleep(seconds)

        def start_background_task(self, target, *args, **kwargs):
            thread = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True)
            thread.start()
            return thread

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
    record_mock_packet as defense_record_mock_packet,
    is_mock_mode as defense_is_mock_mode,
)
from src.llm import (
    analyze_alert, suggest_defense, analyze_attack_chain,
    is_available as llm_available, get_config, update_config, test_connection, list_models,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LAB_ACCESS_LOG = BASE_DIR / "交大学生成绩管理系统_vuln_lab" / "data" / "access_log.csv"
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
LAB_ACCESS_LOG_FIELDS = [
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

app = Flask(__name__, static_folder=str(FRONTEND_DIST), static_url_path="/")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


def empty_analysis() -> dict[str, object]:
    return to_jsonable(AnalysisResult(
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


_last_analysis = empty_analysis()
# 用文件修改时间、大小和已读行数跟踪靶场日志，后台线程只分析新增记录。
_lab_log_signature: tuple[int, int] | None = None
_lab_log_seen_rows: int | None = None
_lab_watcher_started = False
_lab_watcher_lock = threading.Lock()

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
    update_analysis(analyze_events(events, source="示例数据"))
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

    update_analysis(analyze_events(events, source=uploaded.filename))
    return jsonify(_last_analysis)


@app.get("/api/analyze/lab-live")
def analyze_lab_live():
    global _last_analysis
    if not LAB_ACCESS_LOG.exists() or LAB_ACCESS_LOG.stat().st_size == 0:
        return jsonify({"error": "还没有靶场网站访问日志，请先启动靶场并执行登录或攻击请求"}), 404

    try:
        events = parse_csv_log(LAB_ACCESS_LOG)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        return jsonify({"error": f"靶场访问日志格式错误：{exc}"}), 400
    if not events:
        return jsonify({"error": "靶场访问日志为空，请先访问靶场网站或运行攻击脚本"}), 404

    update_analysis(analyze_events(events, source="靶场实时访问日志"), remember_lab_log=True)
    return jsonify(_last_analysis)


@app.get("/api/alerts")
def get_alerts():
    alert_type = request.args.get("type", "")
    severity = request.args.get("severity", "")
    source_ip = request.args.get("source_ip", "")

    alerts = filter_alerts(_last_analysis.get("alerts", []), alert_type, severity, source_ip)

    return jsonify({
        "total": len(alerts),
        "items": alerts,
    })


@app.get("/api/alerts/export")
def export_alerts():
    global _last_analysis
    if not _last_analysis.get("events") and not _last_analysis.get("alerts"):
        events = parse_csv_log(DATA_DIR / "sample_logs_extended.csv")
        _last_analysis = analyze_events(events, source="示例数据")

    alert_type = request.args.get("type", "")
    severity = request.args.get("severity", "")
    source_ip = request.args.get("source_ip", "")
    alerts = filter_alerts(_last_analysis.get("alerts", []), alert_type, severity, source_ip)

    output = StringIO()
    output.write("\ufeff")
    writer = csv.DictWriter(output, fieldnames=[
        "alert_type",
        "category",
        "level",
        "score",
        "confidence",
        "source_ip",
        "target",
        "evidence",
        "rule_id",
        "count",
        "first_seen",
        "last_seen",
        "matched_fields",
    ])
    writer.writeheader()
    for alert in alerts:
        writer.writerow({
            "alert_type": alert.get("alert_type", ""),
            "category": alert.get("category", ""),
            "level": alert.get("level", ""),
            "score": alert.get("score", ""),
            "confidence": alert.get("confidence", ""),
            "source_ip": alert.get("source_ip", ""),
            "target": alert.get("target", ""),
            "evidence": alert.get("evidence", ""),
            "rule_id": alert.get("rule_id", ""),
            "count": alert.get("count", ""),
            "first_seen": alert.get("first_seen", ""),
            "last_seen": alert.get("last_seen", ""),
            "matched_fields": ";".join(alert.get("matched_fields", []) or []),
        })

    filename = f"alerts-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/alerts/clear")
def api_clear_alerts():
    global _last_analysis, _lab_log_signature, _lab_log_seen_rows
    _last_analysis = empty_analysis()
    clear_lab_access_log()
    _lab_log_signature = lab_log_signature()
    _lab_log_seen_rows = lab_log_row_count()
    socketio.emit("analysis_result", _last_analysis)
    return jsonify({"code": 0, "message": "cleared"})


@app.get("/api/alerts/stats")
def get_alert_stats():
    alerts = _last_analysis.get("alerts", [])
    type_counts = {}
    severity_counts = {"高危": 0, "中危": 0, "低危": 0}
    source_counts = {}
    total_score = 0
    total_hits = 0

    for a in alerts:
        hits = int(a.get("count") or 1)
        t = a.get("alert_type", "未知")
        type_counts[t] = type_counts.get(t, 0) + hits
        s = a.get("level", "低危")
        severity_counts[s] = severity_counts.get(s, 0) + hits
        ip = a.get("source_ip", "未知")
        source_counts[ip] = source_counts.get(ip, 0) + hits
        total_score += a.get("score", 0)
        total_hits += hits

    top_sources = sorted(source_counts.items(), key=lambda x: -x[1])[:5]

    summary = _last_analysis.get("summary", {})
    return jsonify({
        "events": _last_analysis.get("events", 0),
        "total_alerts": len(alerts),
        "total_hits": summary.get("total_hits", total_hits),
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


def filter_alerts(alerts: list[dict[str, object]], alert_type: str = "", severity: str = "", source_ip: str = "") -> list[dict[str, object]]:
    filtered = alerts
    if alert_type:
        filtered = [alert for alert in filtered if alert.get("alert_type") == alert_type]
    if severity:
        filtered = [alert for alert in filtered if alert.get("level") == severity]
    if source_ip:
        filtered = [alert for alert in filtered if alert.get("source_ip") == source_ip]
    return filtered


def update_analysis(result: dict[str, object], remember_lab_log: bool = False) -> None:
    global _last_analysis, _lab_log_signature, _lab_log_seen_rows
    _last_analysis = result
    if remember_lab_log:
        _lab_log_signature = lab_log_signature()
        _lab_log_seen_rows = lab_log_row_count()
    socketio.emit("analysis_result", _last_analysis)


def update_lab_incremental_analysis(result: dict[str, object]) -> None:
    global _last_analysis
    existing_alerts = list(_last_analysis.get("alerts", []))
    new_alerts = list(result.get("alerts", []))
    merged_alerts = sorted(
        [*existing_alerts, *new_alerts],
        key=lambda alert: alert.get("timestamp") or alert.get("first_seen") or alert.get("last_seen") or "",
        reverse=True,
    )

    if not merged_alerts and not _last_analysis.get("events"):
        _last_analysis = result
    else:
        _last_analysis = {
            **_last_analysis,
            "events": int(_last_analysis.get("events") or 0) + int(result.get("events") or 0),
            "alerts": merged_alerts,
            "incidents": merge_unique_items(_last_analysis.get("incidents", []), result.get("incidents", [])),
            "summary": summarize_alert_dicts(merged_alerts),
            "baseline": result.get("baseline") or _last_analysis.get("baseline", {}),
            "metadata": result.get("metadata") or _last_analysis.get("metadata", {}),
            "source": "靶场实时访问日志",
            "recommendations": merge_unique_items(_last_analysis.get("recommendations", []), result.get("recommendations", [])),
        }
    socketio.emit("analysis_result", _last_analysis)


def merge_unique_items(existing: object, new: object) -> list[dict[str, object]]:
    merged = []
    seen = set()
    for item in [*(existing or []), *(new or [])]:
        if isinstance(item, dict):
            key = repr(sorted(item.items()))
        else:
            key = repr(item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def summarize_alert_dicts(alerts: list[dict[str, object]]) -> dict[str, object]:
    by_level = {"高危": 0, "中危": 0, "低危": 0}
    by_type: dict[str, int] = {}
    by_category: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    target_counts: dict[str, int] = {}
    timeline: dict[str, int] = {}
    total_hits = 0

    for alert in alerts:
        hits = int(alert.get("count") or 1)
        level = str(alert.get("level") or "低危")
        alert_type = str(alert.get("alert_type") or "未知")
        category = str(alert.get("category") or "未知")
        source_ip = str(alert.get("source_ip") or "未知")
        target = str(alert.get("target") or "未知")
        timestamp = str(alert.get("timestamp") or alert.get("first_seen") or alert.get("last_seen") or "")

        by_level[level] = by_level.get(level, 0) + hits
        by_type[alert_type] = by_type.get(alert_type, 0) + hits
        by_category[category] = by_category.get(category, 0) + hits
        source_counts[source_ip] = source_counts.get(source_ip, 0) + hits
        target_counts[target] = target_counts.get(target, 0) + hits
        total_hits += hits
        if timestamp:
            timeline[timestamp] = timeline.get(timestamp, 0) + hits

    return {
        "高危": by_level.get("高危", 0),
        "中危": by_level.get("中危", 0),
        "低危": by_level.get("低危", 0),
        "total_hits": total_hits,
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


def clear_lab_access_log() -> None:
    if not LAB_ACCESS_LOG.parent.exists():
        return
    with LAB_ACCESS_LOG.open("w", encoding="utf-8", newline="") as log_file:
        csv.DictWriter(log_file, fieldnames=LAB_ACCESS_LOG_FIELDS).writeheader()


def lab_log_signature() -> tuple[int, int] | None:
    if not LAB_ACCESS_LOG.exists() or LAB_ACCESS_LOG.stat().st_size == 0:
        return None
    stat = LAB_ACCESS_LOG.stat()
    return (stat.st_mtime_ns, stat.st_size)


def lab_log_row_count() -> int | None:
    if not LAB_ACCESS_LOG.exists() or LAB_ACCESS_LOG.stat().st_size == 0:
        return None
    with LAB_ACCESS_LOG.open("r", encoding="utf-8", newline="") as log_file:
        return max(sum(1 for _ in log_file) - 1, 0)


def parse_lab_log_new_rows(start_row: int) -> list:
    with LAB_ACCESS_LOG.open("r", encoding="utf-8", newline="") as log_file:
        reader = csv.DictReader(log_file)
        return list(parse_csv_rows(row for index, row in enumerate(reader) if index >= start_row))


_lab_log_signature = lab_log_signature()
_lab_log_seen_rows = lab_log_row_count()


def analyze_lab_log_if_changed() -> None:
    global _lab_log_signature, _lab_log_seen_rows
    signature = lab_log_signature()
    if signature is None:
        _lab_log_signature = None
        _lab_log_seen_rows = None
        return
    if signature == _lab_log_signature:
        return
    if _lab_log_seen_rows is None:
        _lab_log_signature = signature
        _lab_log_seen_rows = lab_log_row_count()
        return
    try:
        events = parse_lab_log_new_rows(_lab_log_seen_rows)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError):
        return
    _lab_log_signature = signature
    _lab_log_seen_rows = lab_log_row_count()
    if not events:
        return
    update_lab_incremental_analysis(analyze_events(events, source="靶场实时访问日志"))


def lab_log_watcher() -> None:
    while True:
        analyze_lab_log_if_changed()
        socketio.sleep(2)


def start_lab_log_watcher() -> None:
    global _lab_watcher_started
    with _lab_watcher_lock:
        if _lab_watcher_started:
            return
        _lab_watcher_started = True
        socketio.start_background_task(lab_log_watcher)


def analyze_events(events, source: str) -> dict[str, object]:
    # 统一分析入口：规则、特征库和异常检测先独立产出告警，再做攻击链关联和响应建议。
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
    jsonable = to_jsonable(result)
    for alert in jsonable.get("alerts", []):
        alert["timestamp"] = alert.get("first_seen") or alert.get("last_seen") or ""
    return jsonable


def summarize_alerts(alerts: list[Alert]) -> dict[str, object]:
    by_level = {"高危": 0, "中危": 0, "低危": 0}
    by_type: dict[str, int] = {}
    by_category: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    target_counts: dict[str, int] = {}
    timeline: dict[str, int] = {}
    total_hits = 0

    for alert in alerts:
        hits = alert.count or 1
        by_level[alert.level] = by_level.get(alert.level, 0) + hits
        by_type[alert.alert_type] = by_type.get(alert.alert_type, 0) + hits
        by_category[alert.category] = by_category.get(alert.category, 0) + hits
        source_counts[alert.source_ip] = source_counts.get(alert.source_ip, 0) + hits
        target_counts[alert.target] = target_counts.get(alert.target, 0) + hits
        total_hits += hits
        timestamp = alert.first_seen or alert.last_seen
        if timestamp is not None:
            key = timestamp.isoformat(timespec="seconds")
            timeline[key] = timeline.get(key, 0) + hits

    return {
        "高危": by_level.get("高危", 0),
        "中危": by_level.get("中危", 0),
        "低危": by_level.get("低危", 0),
        "total_hits": total_hits,
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
        ips_name = "mock" if defense_is_mock_mode() else "available"
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
    try:
        defense_set_enable(data.get("enabled", False))
        status = defense_status()
        return jsonify({"code": 0, "data": status})
    except Exception as e:
        return jsonify({"code": 1, "message": f"设置失败: {e}"}), 500

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
    try:
        defense_add_rule(data)
        return jsonify({"code": 0, "message": "OK"})
    except Exception as e:
        return jsonify({"code": 1, "message": f"添加规则失败: {e}"}), 500

@app.put("/api/defense/rules/<int:rule_id>")
def api_defense_update_rule(rule_id):
    data = request.get_json(silent=True) or {}
    data["id"] = rule_id
    proc = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17}
    if isinstance(data.get("protocol"), str):
        data["protocol"] = proc.get(data["protocol"], 0)
    try:
        if defense_update_rule(data) is False:
            return jsonify({"code": 1, "message": "规则不存在"}), 404
        return jsonify({"code": 0, "message": "OK"})
    except Exception as e:
        return jsonify({"code": 1, "message": f"修改规则失败: {e}"}), 500

@app.delete("/api/defense/rules/<int:rule_id>")
def api_defense_delete_rule(rule_id):
    try:
        if defense_del_rule(rule_id) is False:
            return jsonify({"code": 1, "message": "规则不存在"}), 404
        return jsonify({"code": 0, "message": "OK"})
    except Exception as e:
        return jsonify({"code": 1, "message": f"删除规则失败: {e}"}), 500

@app.get("/api/defense/stats")
def api_defense_stats():
    try: return jsonify({"code": 0, "data": defense_get_stats()})
    except: return jsonify({"code": 0, "data": {"total_checked": 0, "total_dropped": 0, "total_accepted": 0, "drop_rate": 0}})

@app.post("/api/defense/stats/record")
def api_defense_record_stats():
    data = request.get_json(silent=True) or {}
    try:
        recorded = defense_record_mock_packet(data.get("action", "accept"), data.get("protocol", "tcp"))
        return jsonify({"code": 0, "data": {"recorded": recorded, "stats": defense_get_stats()}})
    except Exception as e:
        return jsonify({"code": 1, "message": f"记录统计失败: {e}"}), 500

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


@socketio.on("connect")
def on_connect():
    socketio.emit("analysis_result", _last_analysis, to=request.sid)
    start_lab_log_watcher()


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
