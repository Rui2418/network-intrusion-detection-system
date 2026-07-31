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
    method: str = ""
    protocol: str = ""
    host: str = ""
    user_agent: str = ""
    bytes_sent: int | None = None
    duration_ms: int | None = None
    tls_fingerprint: str = ""


def parse_bool(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "success", "yes"}:
        return True
    if normalized in {"false", "0", "fail", "failed", "no"}:
        return False
    return None


def _parse_optional_int(value: str) -> int | None:
    normalized = value.strip()
    if normalized == "":
        return None
    return int(normalized)


def parse_csv_log(file_path: str | Path) -> list[LogEvent]:
    path = Path(file_path)
    with path.open("r", encoding="utf-8", newline="") as log_file:
        return list(parse_csv_rows(csv.DictReader(log_file)))


def parse_csv_rows(rows: Iterable[dict[str, str]]) -> Iterable[LogEvent]:
    # 基础字段保持必填，扩展字段为空时保留为默认值，兼容旧版 CSV 样例。
    for row_index, row in enumerate(rows, start=1):
        try:
            yield LogEvent(
                timestamp=datetime.fromisoformat(row["timestamp"]),
                source_ip=row["source_ip"].strip(),
                target_ip=row["target_ip"].strip(),
                port=int(row["port"]),
                path=row.get("path", "").strip(),
                status_code=int(row.get("status_code") or 0),
                username=row.get("username", "").strip(),
                login_success=parse_bool(row.get("login_success", "")),
                method=row.get("method", "").strip(),
                protocol=row.get("protocol", "").strip(),
                host=row.get("host", "").strip(),
                user_agent=row.get("user_agent", "").strip(),
                bytes_sent=_parse_optional_int(row.get("bytes_sent", "")),
                duration_ms=_parse_optional_int(row.get("duration_ms", "")),
                tls_fingerprint=row.get("tls_fingerprint", "").strip(),
            )
        except KeyError as e:
            # 捕获缺少必要字段的异常
            raise ValueError(f"第 {row_index} 行缺少必要字段: {str(e)}") from e
        except ValueError as e:
            # 捕获类型转换失败（如 port 不是整数，timestamp 格式不对）的异常
            raise ValueError(f"第 {row_index} 行数据格式错误: {str(e)}") from e
