from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from src.detector.models import Alert
from src.parser.log_parser import LogEvent


BASE_DIR = Path(__file__).resolve().parent.parent.parent
SIGNATURE_FILE = BASE_DIR / "data" / "signatures.json"


def load_signatures() -> list[dict[str, object]]:
    with SIGNATURE_FILE.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def detect_signature_attacks(events: list[LogEvent]) -> list[Alert]:
    signatures = load_signatures()
    grouped: dict[tuple[str, str, str], dict[str, object]] = defaultdict(dict)

    for event in events:
        for signature in signatures:
            matched_fields = []
            matched_pattern = None
            for field in signature.get("fields", []):
                value = str(getattr(event, field, "") or "")
                lowered = value.lower()
                for pattern in signature.get("patterns", []):
                    if pattern.lower() in lowered:
                        matched_fields.append(field)
                        matched_pattern = pattern
                        break
            if not matched_fields:
                continue

            key = (event.source_ip, event.target_ip, str(signature["id"]))
            current = grouped.get(key)
            if not current:
                grouped[key] = {
                    "count": 1,
                    "first_seen": event.timestamp,
                    "last_seen": event.timestamp,
                    "matched_fields": set(matched_fields),
                    "matched_pattern": matched_pattern,
                    "target": getattr(event, str(signature.get("target_field", "path")), event.path) or event.path,
                    "signature": signature,
                    "source_ip": event.source_ip,
                }
            else:
                current["count"] = int(current["count"]) + 1
                current["last_seen"] = event.timestamp
                current["matched_fields"].update(matched_fields)

    alerts: list[Alert] = []
    for entry in grouped.values():
        signature = entry["signature"]
        count = int(entry["count"])
        score = min(100, int(signature.get("base_score", 50)) + (count - 1) * 6)
        if score >= 80:
            level = "高危"
        elif score >= 50:
            level = "中危"
        else:
            level = "低危"
        alerts.append(Alert(
            alert_type=str(signature["alert_type"]),
            category=str(signature.get("category", "特征匹配")),
            source_ip=str(entry["source_ip"]),
            target=str(entry["target"]),
            level=level,
            score=score,
            confidence=float(signature.get("confidence", 0.8)),
            evidence=f"命中特征 {entry['matched_pattern']}，共 {count} 次",
            rule_id=str(signature["id"]),
            count=count,
            first_seen=entry["first_seen"],
            last_seen=entry["last_seen"],
            matched_fields=tuple(sorted(entry["matched_fields"])),
        ))
    return alerts
