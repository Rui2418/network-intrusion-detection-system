from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    source_ip: str
    target_ip: str
    port: int
    path: str
    status_code: int
    username: str
    login_success: bool | None


def parse_bool(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "success", "yes"}:
        return True
    if normalized in {"false", "0", "fail", "failed", "no"}:
        return False
    return None


def parse_csv_log(file_path: str | Path) -> list[LogEvent]:
    path = Path(file_path)
    with path.open("r", encoding="utf-8", newline="") as log_file:
        return list(parse_csv_rows(csv.DictReader(log_file)))


def parse_csv_rows(rows: Iterable[dict[str, str]]) -> Iterable[LogEvent]:
    for row in rows:
        yield LogEvent(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source_ip=row["source_ip"].strip(),
            target_ip=row["target_ip"].strip(),
            port=int(row["port"]),
            path=row.get("path", "").strip(),
            status_code=int(row.get("status_code") or 0),
            username=row.get("username", "").strip(),
            login_success=parse_bool(row.get("login_success", "")),
        )
