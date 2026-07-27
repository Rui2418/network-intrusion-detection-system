"""
Zeek 日志解析器

将 Zeek 输出的 TSV / JSON 日志转换为统一的 LogEvent 对象。
支持的日志类型:
  - conn.log    → 连接摘要 (基础字段)
  - http.log    → HTTP 请求 (method, path, host, user_agent, status_code)
  - ssl.log     → TLS 指纹 (ja3/ja3s → tls_fingerprint)
  - dns.log     → DNS 查询 (可选)
"""

from __future__ import annotations

import csv
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import TextIO


@dataclass
class ZeekLogHeader:
    """Zeek TSV 日志元信息"""
    path: str = ""
    open_ts: str = ""
    fields: list[str] = field(default_factory=list)
    types: list[str] = field(default_factory=list)
    separator: str = "\t"
    set_separator: str = ","
    empty_field: str = "(empty)"
    unset_field: str = "-"


def parse_tsv_meta(line: str) -> tuple[str, str] | None:
    """解析 Zeek TSV 的 # 元数据行。返回 (tag, value) 或 None"""
    if not line.startswith("#"):
        return None
    content = line[1:].lstrip()  # 只去掉左侧空白，保留右侧
    # 找到第一个空白分隔符
    for i, ch in enumerate(content):
        if ch in (" ", "\t"):
            tag = content[:i]
            value = content[i + 1:].rstrip("\r\n")  # 保留值本身的空白
            return tag, value
    return content, ""


def parse_tsv_header(file: TextIO) -> tuple[ZeekLogHeader, list[str]]:
    """读取 Zeek TSV 文件头，返回 header 信息和后续数据行"""
    header = ZeekLogHeader()
    data_lines: list[str] = []

    for line in file:
        line = line.rstrip("\r\n")
        if not line:
            continue
        if line.startswith("#"):
            meta = parse_tsv_meta(line)
            if meta:
                tag, value = meta
                if tag == "separator":
                    header.separator = value
                elif tag == "set_separator":
                    header.set_separator = value
                elif tag == "empty_field":
                    header.empty_field = value
                elif tag == "unset_field":
                    header.unset_field = value
                elif tag == "path":
                    header.path = value
                elif tag == "open":
                    header.open_ts = value
                elif tag == "fields":
                    header.fields = [f.strip() for f in value.split(header.separator)]
                elif tag == "types":
                    header.types = [t.strip() for t in value.split(header.separator)]
            continue
        # 数据行
        data_lines.append(line)

    return header, data_lines


def zeek_tsv_to_dicts(file_path: str | Path) -> Iterable[dict[str, str]]:
    """
    将 Zeek TSV 日志逐行解析为字典。
    自动跳过 # 开头的元数据行。
    """
    path = Path(file_path)
    if not path.exists():
        return

    with path.open("r", encoding="utf-8", errors="replace") as f:
        header, data_lines = parse_tsv_header(f)

    if not header.fields:
        return

    sep = header.separator
    empty = header.empty_field
    unset = header.unset_field

    for line in data_lines:
        parts = line.split(sep)
        row: dict[str, str] = {}
        for i, field in enumerate(header.fields):
            val = parts[i] if i < len(parts) else ""
            if val in (empty, unset):
                val = ""
            row[field] = val
        yield row


def parse_zeek_timestamp(ts_str: str) -> datetime | None:
    """
    Zeek 时间戳为 Unix epoch 秒，如 "1720400000.123456"
    也支持标准 ISO 格式
    """
    if not ts_str:
        return None
    try:
        # 尝试 Unix 时间戳
        if "." in ts_str:
            parts = ts_str.split(".")
            secs = int(parts[0])
            micro = int(parts[1].ljust(6, "0")[:6]) if parts[1] else 0
            return datetime.fromtimestamp(secs + micro / 1_000_000)
        # 整数秒
        return datetime.fromtimestamp(int(ts_str))
    except (ValueError, OSError):
        pass
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def _clean(val: str) -> str:
    return val.strip().strip('"').strip("'")


def conn_to_logevent(row: dict[str, str]) -> dict | None:
    """将 conn.log 的一行映射为 LogEvent-兼容字典"""
    ts = parse_zeek_timestamp(row.get("ts", ""))
    if ts is None:
        return None

    return {
        "timestamp": ts.isoformat(),
        "source_ip": _clean(row.get("id.orig_h", "")),
        "target_ip": _clean(row.get("id.resp_h", "")),
        "port": int(row.get("id.resp_p", 0)) if row.get("id.resp_p", "").isdigit() else 0,
        "path": "/",
        "status_code": 0,
        "username": "",
        "login_success": None,
        "method": "",
        "protocol": row.get("proto", "").lower(),
        "host": "",
        "user_agent": "",
        "bytes_sent": int(row.get("orig_bytes", "0") or "0") if row.get("orig_bytes", "").strip().lstrip("-").isdigit() else None,
        "duration_ms": int(float(row.get("duration", "0")) * 1000) if row.get("duration", "").strip() else None,
        "tls_fingerprint": "",
    }


def http_to_logevent(row: dict[str, str]) -> dict | None:
    """将 http.log 的一行映射为 LogEvent-兼容字典"""
    ts = parse_zeek_timestamp(row.get("ts", ""))
    if ts is None:
        return None

    status_str = row.get("status_code", "").strip()
    status_code = int(status_str) if status_str.isdigit() else 0

    return {
        "timestamp": ts.isoformat(),
        "source_ip": _clean(row.get("id.orig_h", "")),
        "target_ip": _clean(row.get("id.resp_h", "")),
        "port": int(row.get("id.resp_p", 0)) if row.get("id.resp_p", "").isdigit() else 80,
        "path": row.get("uri", "/"),
        "status_code": status_code,
        "username": row.get("username", ""),
        "login_success": None,
        "method": row.get("method", "GET"),
        "protocol": "tcp",
        "host": row.get("host", ""),
        "user_agent": row.get("user_agent", ""),
        "bytes_sent": int(row.get("request_body_len", "0") or "0") + int(row.get("response_body_len", "0") or "0")
            if (row.get("request_body_len", "").strip().lstrip("-").isdigit() and row.get("response_body_len", "").strip().lstrip("-").isdigit())
            else None,
        "duration_ms": None,
        "tls_fingerprint": "",
    }


def ssl_to_logevent(row: dict[str, str]) -> dict | None:
    """将 ssl.log 的一行映射为 LogEvent-兼容字典 (补充 TLS 指纹)"""
    ts = parse_zeek_timestamp(row.get("ts", ""))
    if ts is None:
        return None

    return {
        "timestamp": ts.isoformat(),
        "source_ip": _clean(row.get("id.orig_h", "")),
        "target_ip": _clean(row.get("id.resp_h", "")),
        "port": int(row.get("id.resp_p", 0)) if row.get("id.resp_p", "").isdigit() else 443,
        "path": "/",
        "status_code": 0,
        "username": "",
        "login_success": None,
        "method": "",
        "protocol": "tcp",
        "host": row.get("server_name", ""),
        "user_agent": "",
        "bytes_sent": None,
        "duration_ms": None,
        "tls_fingerprint": row.get("ja3", row.get("ja3s", "")),
    }


def parse_zeek_log(file_path: str | Path, log_type: str = "auto") -> list[dict]:
    """
    解析单个 Zeek 日志文件，返回 LogEvent-兼容字典列表。

    参数:
        file_path: Zeek 日志文件路径
        log_type: 日志类型 - "conn", "http", "ssl", "dns" 或 "auto"(自动从文件名推断)
    """
    path_str = str(file_path)
    fname = Path(file_path).name.lower()

    if log_type == "auto":
        if "http" in fname:
            log_type = "http"
        elif "ssl" in fname or "tls" in fname:
            log_type = "ssl"
        elif "conn" in fname:
            log_type = "conn"
        elif "dns" in fname:
            log_type = "dns"
        else:
            log_type = "conn"  # 默认

    parser_map = {
        "conn": conn_to_logevent,
        "http": http_to_logevent,
        "ssl": ssl_to_logevent,
    }

    parser = parser_map.get(log_type, conn_to_logevent)
    results: list[dict] = []
    for row in zeek_tsv_to_dicts(file_path):
        event = parser(row)
        if event:
            results.append(event)
    return results


def parse_zeek_directory(zeek_log_dir: str | Path, log_types: list[str | None] | None = None) -> list[dict]:
    """
    解析整个 Zeek 日志目录中所有相关日志文件，合并返回。

    参数:
        zeek_log_dir: Zeek 日志输出目录 (含 current/ 子目录或直接放日志)
        log_types: 需要解析的类型列表，如 ["conn", "http", "ssl"]；None 则全部
    """
    log_dir = Path(zeek_log_dir)
    if not log_dir.exists():
        return []

    # Zeek 可以把日志放在 current/ 子目录
    search_dirs = [log_dir]
    current_dir = log_dir / "current"
    if current_dir.exists():
        search_dirs.append(current_dir)

    type_map: dict[str, str] = {
        "conn.log": "conn", "http.log": "http",
        "ssl.log": "ssl", "dns.log": "dns",
    }

    all_events: list[dict] = []
    seen_paths: set[Path] = set()

    for sd in search_dirs:
        for fpath in sorted(sd.iterdir()):
            if not fpath.is_file():
                continue
            if fpath in seen_paths:
                continue
            fname = fpath.name
            if fname not in type_map:
                continue
            log_type = type_map[fname]
            if log_types and log_type not in log_types:
                continue
            seen_paths.add(fpath)
            try:
                events = parse_zeek_log(fpath, log_type=log_type)
                all_events.extend(events)
            except Exception:
                continue

    # 按时间戳排序去重 (同 timestamp+source_ip+target_ip 视为重复)
    seen_dedup: set[tuple] = set()
    deduped: list[dict] = []
    for evt in sorted(all_events, key=lambda x: x.get("timestamp", "")):
        key = (evt.get("timestamp"), evt.get("source_ip"), evt.get("target_ip"),
               evt.get("port"), evt.get("path"))
        if key in seen_dedup:
            continue
        seen_dedup.add(key)

        # 如果有 http 日志补充了 host/user_agent/method/path，合并到 conn 基础信息上
        deduped.append(evt)

    return deduped


def convert_to_csv(events: list[dict]) -> str:
    """将 Zeek 解析结果转换为标准 CSV 字符串，供现有分析流水线使用"""
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "timestamp", "source_ip", "target_ip", "port", "path",
        "status_code", "username", "login_success", "method", "protocol",
        "host", "user_agent", "bytes_sent", "duration_ms", "tls_fingerprint",
    ])
    writer.writeheader()
    for evt in events:
        writer.writerow({
            k: evt.get(k, "")
            for k in [
                "timestamp", "source_ip", "target_ip", "port", "path",
                "status_code", "username", "login_success", "method", "protocol",
                "host", "user_agent", "bytes_sent", "duration_ms", "tls_fingerprint",
            ]
        })
    return output.getvalue()
