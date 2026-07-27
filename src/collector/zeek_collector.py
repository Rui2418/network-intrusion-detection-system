"""
Zeek 采集器管理器

负责:
  1. 检测环境中 Zeek 的安装位置
  2. 启动 / 停止 Zeek 进程进行实时抓包
  3. 监听 Zeek 日志目录文件变化，增量解析新日志行
  4. 将新事件注入分析流水线
  5. 自动清理超过保留时长的旧日志

回退机制:
  - Linux: 检测 zeek/zeekctl 并直接管理
  - Windows / 无 Zeek 环境: 回退到"离线解析"模式，
    只解析已有的 Zeek 日志文件，不启动抓包进程
"""

from __future__ import annotations

import csv
import io
import os
import platform
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from src.collector.zeek_parser import parse_zeek_log, zeek_tsv_to_dicts

# ── 常量 ──────────────────────────────────────────────────────────

ZEEK_DEFAULT_PATHS: list[str] = [
    "/opt/zeek/bin/zeek",
    "/usr/local/zeek/bin/zeek",
    "/usr/bin/zeek",
    "/usr/local/bin/zeek",
]

ZEEK_LOG_DIR_CANDIDATES: list[str] = [
    "/opt/zeek/logs",
    "/usr/local/zeek/logs",
    "/var/log/zeek",
    "/var/log/bro",
]

IS_LINUX = platform.system().startswith("Linux")
IS_WINDOWS = platform.system().startswith("Win")

# 日志类型到分析流水线所需字段的映射
LOG_TYPE_WEIGHT = {"http": 10, "ssl": 8, "conn": 5, "dns": 3}

# ── 全局状态 ──────────────────────────────────────────────────────

_zeek_process: subprocess.Popen | None = None
_capture_interface: str = ""
_capture_running = False
_capture_lock = threading.Lock()
_log_dir: str = ""
_on_event_callback: Callable[[list[dict]], None] | None = None
_watcher_thread: threading.Thread | None = None
_watcher_stop = threading.Event()
_last_positions: dict[str, int] = {}  # filename → bytes read


# ── 检测函数 ──────────────────────────────────────────────────────


def find_zeek() -> str:
    """返回 zeek 可执行文件路径，未找到返回空字符串"""
    # 检查常见路径
    for p in ZEEK_DEFAULT_PATHS:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # 检查 PATH
    try:
        result = subprocess.run(
            ["which", "zeek"] if IS_LINUX else ["where", "zeek"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return ""


def find_zeek_log_dir() -> str:
    """查找 Zeek 日志目录，用于离线解析"""
    for d in ZEEK_LOG_DIR_CANDIDATES:
        if os.path.isdir(d):
            return d
    return ""


def zeek_version() -> str:
    """获取 Zeek 版本信息"""
    zeek_path = find_zeek()
    if not zeek_path:
        return ""
    try:
        result = subprocess.run(
            [zeek_path, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception:
        return ""


def list_interfaces() -> list[str]:
    """列出可用网络接口"""
    ifaces: list[str] = []
    try:
        if IS_LINUX:
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if ": " in line and "lo:" not in line:
                    parts = line.split(": ")
                    if len(parts) >= 2:
                        name = parts[1].split(":")[0].split("@")[0].strip()
                        if name:
                            ifaces.append(name)
        elif IS_WINDOWS:
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "adapter" in line.lower():
                    name = line.split(":")[-1].strip()
                    if name:
                        ifaces.append(name)
        else:
            result = subprocess.run(
                ["ifconfig"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if line and not line.startswith(" "):
                    name = line.split(":")[0].split()[0].strip()
                    if name and name != "lo":
                        ifaces.append(name)
    except Exception:
        pass
    return ifaces if ifaces else ["eth0", "wlan0"]


# ── 状态查询 ──────────────────────────────────────────────────────


def get_zeek_info() -> dict[str, Any]:
    """返回 Zeek 安装和运行状态"""
    zeek_path = find_zeek()
    log_dir = find_zeek_log_dir()
    return {
        "installed": bool(zeek_path),
        "zeek_path": zeek_path or "",
        "version": zeek_version() if zeek_path else "",
        "log_dir": log_dir,
        "running": _capture_running,
        "interface": _capture_interface,
        "platform": platform.system(),
    }


def get_capture_status() -> dict[str, Any]:
    """返回当前抓包状态"""
    with _capture_lock:
        return {
            "running": _capture_running,
            "interface": _capture_interface,
            "log_dir": _log_dir,
            "active_since": "",
            "events_collected": 0,
        }


def get_log_files() -> list[dict[str, Any]]:
    """列出 Zeek 日志目录下可解析的日志文件"""
    log_dir = find_zeek_log_dir()
    if not log_dir:
        return []

    files: list[dict[str, Any]] = []
    search = [Path(log_dir)]
    current = Path(log_dir) / "current"
    if current.exists():
        search.append(current)

    for sd in search:
        for f in sorted(sd.iterdir()):
            if not f.is_file():
                continue
            fname = f.name
            if not any(fname.endswith(ext) for ext in [".log"]):
                continue
            if fname in ("stdout.log", "stderr.log", "packet_filter.log",
                         "notice.log", "weird.log", "loaded_scripts.log",
                         "capture_loss.log", "reporter.log"):
                continue
            stat = f.stat()
            files.append({
                "name": fname,
                "path": str(f),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    return files


# ── 进程管理 ──────────────────────────────────────────────────────


def start_capture(interface: str = "", zeek_script: str = "", log_dir: str = "") -> dict[str, Any]:
    """
    启动 Zeek 抓包进程。

    参数:
        interface: 监听的网络接口，空则自动选择
        zeek_script: 额外 Zeek 脚本路径
        log_dir: Zeek 日志输出目录

    返回:
        状态字典
    """
    global _zeek_process, _capture_running, _capture_interface, _log_dir
    global _watcher_thread, _watcher_stop, _last_positions

    with _capture_lock:
        if _capture_running:
            return {"success": False, "message": "Zeek 已在运行中"}

        zeek_path = find_zeek()
        if not zeek_path:
            return {"success": False, "message": "未找到 Zeek，请先安装 (https://zeek.org)"}

        if not interface:
            ifaces = list_interfaces()
            if not ifaces:
                return {"success": False, "message": "未检测到网络接口"}
            interface = ifaces[0]

        if not log_dir:
            log_dir = str(Path.cwd() / "zeek" / "logs")

        os.makedirs(log_dir, exist_ok=True)
        _log_dir = log_dir

        # 构建命令
        cmd = [zeek_path, "-i", interface]
        if zeek_script and os.path.isfile(zeek_script):
            cmd.append(zeek_script)
        # 使用自定义日志路径
        cmd.extend([
            f"Log::default_logdir={log_dir}",
            # 启用 JSON 格式以便前端更易消费
            # 但我们仍然支持 TSV 解析
        ])

        try:
            _zeek_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _capture_running = True
            _capture_interface = interface
            _last_positions = {}

            # 启动日志监控线程
            _watcher_stop.clear()
            _watcher_thread = threading.Thread(
                target=_watch_log_loop,
                args=(log_dir,),
                daemon=True,
            )
            _watcher_thread.start()

            return {
                "success": True,
                "message": f"Zeek 已在 {interface} 启动",
                "pid": _zeek_process.pid,
                "log_dir": log_dir,
                "interface": interface,
            }
        except Exception as e:
            _capture_running = False
            _zeek_process = None
            return {"success": False, "message": f"启动失败: {e}"}


def stop_capture() -> dict[str, Any]:
    """停止 Zeek 抓包进程"""
    global _zeek_process, _capture_running, _capture_interface

    with _capture_lock:
        _watcher_stop.set()

        if _zeek_process is not None:
            try:
                _zeek_process.terminate()
                _zeek_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _zeek_process.kill()
                _zeek_process.wait(timeout=5)
            except Exception:
                pass
            _zeek_process = None

        _capture_running = False
        iface = _capture_interface
        _capture_interface = ""

        return {"success": True, "message": f"Zeek 在 {iface} 已停止" if iface else "Zeek 已停止"}


# ── 日志监控 ──────────────────────────────────────────────────────


def set_event_callback(callback: Callable[[list[dict]], None]) -> None:
    """设置新事件回调，用于将解析结果注入分析流水线"""
    global _on_event_callback
    _on_event_callback = callback


def _watch_log_loop(log_dir: str) -> None:
    """后台线程：监控 Zeek 日志目录的文件变化"""
    watched_files: set[str] = set()

    while not _watcher_stop.is_set():
        try:
            log_path = Path(log_dir)
            if not log_path.exists():
                time.sleep(2)
                continue

            # 同时检查 current/ 子目录
            search_dirs = [log_path]
            current_dir = log_path / "current"
            if current_dir.exists():
                search_dirs.append(current_dir)

            for sd in search_dirs:
                for fpath in sorted(sd.iterdir()):
                    if not fpath.is_file():
                        continue
                    fname = fpath.name
                    if not fname.endswith(".log"):
                        continue
                    if fname in ("stdout.log", "stderr.log", "reporter.log",
                                 "loaded_scripts.log", "capture_loss.log"):
                        continue

                    fkey = str(fpath)
                    current_size = fpath.stat().st_size
                    last_size = _last_positions.get(fkey, 0)
                    was_new = fkey not in watched_files

                    if current_size > last_size:
                        # 读取新增行
                        new_events = _read_new_lines(fpath, last_size, current_size)
                        _last_positions[fkey] = current_size
                        watched_files.add(fkey)

                        if new_events and _on_event_callback:
                            try:
                                _on_event_callback(new_events)
                            except Exception:
                                pass
                    elif was_new and current_size > 0:
                        # 全新文件，首次读取
                        new_events = _read_new_lines(fpath, 0, current_size)
                        _last_positions[fkey] = current_size
                        watched_files.add(fkey)
                        if new_events and _on_event_callback:
                            try:
                                _on_event_callback(new_events)
                            except Exception:
                                pass

        except Exception:
            pass

        # 每 2 秒检查一次
        _watcher_stop.wait(2)


def _read_new_lines(fpath: Path, start: int, end: int) -> list[dict]:
    """读取文件从 start 到 end 字节之间的新行并解析"""
    if start >= end:
        return []

    try:
        fname = fpath.name.lower()
        # 确定日志类型
        if "http" in fname:
            log_type = "http"
        elif "ssl" in fname or "tls" in fname:
            log_type = "ssl"
        elif "dns" in fname:
            log_type = "dns"
        else:
            log_type = "conn"

        with fpath.open("r", encoding="utf-8", errors="replace") as f:
            # 如果从文件中间开始读，需要包含文件头（# 开头的元数据行）
            # 所以我们总是从头开始解析增量行
            if start == 0:
                f.seek(0)
            else:
                # 从文件开头读取，但只处理新增的部分
                f.seek(start)

            new_text = f.read(end - start)
            if not new_text.strip():
                return []

        # 重新解析整个文件增量部分
        # 简单方法：用 parse_zeek_log 重新解析增量部分
        # 但为了效率，我们只解析新增的行
        from src.collector.zeek_parser import parse_tsv_header, conn_to_logevent, http_to_logevent, ssl_to_logevent

        parser_map = {
            "conn": conn_to_logevent,
            "http": http_to_logevent,
            "ssl": ssl_to_logevent,
        }
        parser = parser_map.get(log_type, conn_to_logevent)

        # 对于追加写入的 Zeek 日志，新增行可能包含 # 头信息
        # 但如果文件已存在且我们只读取增量，可能需要处理不完整的行
        lines = new_text.splitlines()
        events: list[dict] = []

        # 过滤掉元数据行
        data_lines = [l for l in lines if l and not l.startswith("#")]

        if not data_lines:
            return []

        # 从文件开头获取字段定义
        header_fields: list[str] = []
        try:
            with fpath.open("r", encoding="utf-8", errors="replace") as hf:
                for line in hf:
                    if line.startswith("#fields"):
                        parts = line[8:].strip().split("\t")
                        header_fields = [f.strip() for f in parts]
                        break
        except Exception:
            pass

        if not header_fields:
            return events

        sep = "\t"
        for line in data_lines:
            parts = line.split(sep)
            row: dict[str, str] = {}
            for i, field in enumerate(header_fields):
                val = parts[i] if i < len(parts) else ""
                row[field] = val
            event = parser(row)
            if event:
                events.append(event)

        return events

    except Exception:
        return []


# ── 离线解析 ──────────────────────────────────────────────────────


def load_zeek_logs(log_types: list[str] | None = None) -> list[dict]:
    """
    加载 Zeek 日志目录中的所有日志并转换为 LogEvent-兼容字典。
    供 /api/collector/analyze 等离线分析接口使用。
    """
    log_dir = find_zeek_log_dir()
    if not log_dir:
        # 尝试 zeek/ 目录下的 logs/
        local_logs = Path.cwd() / "zeek" / "logs"
        if local_logs.exists():
            log_dir = str(local_logs)
        else:
            return []

    from src.collector.zeek_parser import parse_zeek_directory
    return parse_zeek_directory(log_dir, log_types=log_types)
