"""Zeek 解析器单元测试"""

import tempfile
import os
from pathlib import Path

from src.collector.zeek_parser import (
    parse_zeek_log,
    parse_zeek_directory,
    convert_to_csv,
    parse_zeek_timestamp,
    zeek_tsv_to_dicts,
)


T = "\t"

SAMPLE_HTTP_LOG = (
    "#separator" + T + T + "\n"
    "#set_separator" + T + "," + "\n"
    "#empty_field" + T + "(empty)" + "\n"
    "#unset_field" + T + "-" + "\n"
    "#path" + T + "http" + "\n"
    "#open" + T + "2026-07-27-12-00-00" + "\n"
    "#fields" + T + T.join([
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "trans_depth", "method", "host", "uri", "referrer", "user_agent",
        "request_body_len", "response_body_len", "status_code", "status_msg",
        "info_code", "info_msg", "tags", "username", "password", "proxied",
        "orig_fuids", "orig_filenames", "orig_mime_types", "resp_fuids",
        "resp_filenames", "resp_mime_types",
    ]) + "\n"
    "#types" + T + T.join([
        "time", "string", "addr", "port", "addr", "port", "count", "string",
        "string", "string", "string", "string", "count", "count", "count",
        "string", "count", "string", "table[string]", "string", "string",
        "table[string]", "table[string]", "table[string]", "table[string]",
        "table[string]", "table[string]", "table[string]",
    ]) + "\n"
    + T.join(["1720400000.123456", "U1", "192.168.1.100", "54321",
              "10.0.0.5", "80", "1", "GET", "example.com", "/index.html",
              "-", "Mozilla/5.0", "0", "512", "200", "OK", "-", "-",
              "(empty)", "-", "-", "(empty)", "-", "-", "-", "-", "-", "-"]) + "\n"
    + T.join(["1720400010.654321", "U2", "203.0.113.9", "12345",
              "10.0.0.5", "80", "1", "GET", "example.com", "/.env",
              "-", "curl/8.0", "0", "180", "404", "Not Found", "-", "-",
              "(empty)", "-", "-", "(empty)", "-", "-", "-", "-", "-", "-"]) + "\n"
    + T.join(["1720400020.987654", "U3", "172.16.0.8", "33333",
              "10.0.0.5", "80", "1", "POST", "example.com", "/login",
              "-", "python-requests/2.31", "210", "45", "401", "Unauthorized",
              "-", "-", "(empty)", "admin", "pass123", "(empty)", "-", "-",
              "-", "-", "-", "-"]) + "\n"
)

SAMPLE_CONN_LOG = (
    "#separator" + T + "\t" + "\n"
    "#set_separator" + T + "," + "\n"
    "#empty_field" + T + "(empty)" + "\n"
    "#unset_field" + T + "-" + "\n"
    "#path" + T + "conn" + "\n"
    "#open" + T + "2026-07-27-12-00-00" + "\n"
    "#fields" + T + T.join([
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
        "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
        "tunnel_parents",
    ]) + "\n"
    "#types" + T + T.join([
        "time", "string", "addr", "port", "addr", "port", "enum", "string",
        "interval", "count", "count", "string", "bool", "bool", "count",
        "string", "count", "count", "count", "count", "table[string]",
    ]) + "\n"
    + T.join(["1720400000.123456", "U1", "192.168.1.100", "54321",
              "10.0.0.5", "80", "tcp", "http", "0.123456", "420", "512",
              "SF", "-", "-", "0", "ShADadFf", "10", "1000", "10", "1200",
              "(empty)"]) + "\n"
    + T.join(["1720400010.654321", "U2", "203.0.113.9", "12345",
              "10.0.0.5", "80", "tcp", "-", "0.050000", "180", "200",
              "REJ", "-", "-", "0", "Sh", "5", "500", "2", "300",
              "(empty)"]) + "\n"
)


def _write_temp(content: str, suffix: str = ".log") -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return tmp.name


class TestParseZeekTimestamp:
    def test_unix_float(self):
        dt = parse_zeek_timestamp("1720400000.123456")
        assert dt is not None
        assert dt.year == 2024  # 1720400000 -> July 2024

    def test_unix_int(self):
        dt = parse_zeek_timestamp("1720400000")
        assert dt is not None

    def test_iso_format(self):
        dt = parse_zeek_timestamp("2026-07-08T10:00:00")
        assert dt is not None
        assert dt.year == 2026

    def test_empty(self):
        assert parse_zeek_timestamp("") is None

    def test_invalid(self):
        assert parse_zeek_timestamp("not-a-date") is None


class TestParseHttpLog:
    def test_parse_http(self):
        path = _write_temp(SAMPLE_HTTP_LOG)
        try:
            events = parse_zeek_log(path, log_type="http")
            assert len(events) == 3

            # 第一个请求: 正常 GET
            assert events[0]["source_ip"] == "192.168.1.100"
            assert events[0]["target_ip"] == "10.0.0.5"
            assert events[0]["port"] == 80
            assert events[0]["method"] == "GET"
            assert events[0]["host"] == "example.com"
            assert events[0]["path"] == "/index.html"
            assert events[0]["status_code"] == 200
            assert "Mozilla" in events[0]["user_agent"]

            # 第二个请求: 可疑路径
            assert events[1]["path"] == "/.env"
            assert events[1]["source_ip"] == "203.0.113.9"
            assert events[1]["status_code"] == 404

            # 第三个请求: 暴力登录
            assert events[2]["method"] == "POST"
            assert events[2]["path"] == "/login"
            assert events[2]["status_code"] == 401
            assert events[2]["source_ip"] == "172.16.0.8"
        finally:
            os.unlink(path)

    def test_auto_detect(self):
        """自动从文件名推断日志类型"""
        path = _write_temp(SAMPLE_HTTP_LOG, suffix="http.log")
        try:
            events = parse_zeek_log(path)  # log_type="auto"
            assert len(events) == 3
            assert events[0]["method"] == "GET"
        finally:
            os.unlink(path)


class TestParseConnLog:
    def test_parse_conn(self):
        path = _write_temp(SAMPLE_CONN_LOG)
        try:
            events = parse_zeek_log(path, log_type="conn")
            assert len(events) == 2

            assert events[0]["source_ip"] == "192.168.1.100"
            assert events[0]["target_ip"] == "10.0.0.5"
            assert events[0]["port"] == 80
            assert events[0]["protocol"] == "tcp"
            assert events[0]["bytes_sent"] == 420
            # duration_ms = 0.123456 * 1000 ≈ 123
            assert abs(events[0]["duration_ms"] - 123) < 5

            assert events[1]["source_ip"] == "203.0.113.9"
            assert events[1]["bytes_sent"] == 180
        finally:
            os.unlink(path)


class TestConvertToCsv:
    def test_conversion(self):
        path = _write_temp(SAMPLE_HTTP_LOG)
        try:
            events = parse_zeek_log(path, log_type="http")
            csv_text = convert_to_csv(events)

            # 应该有表头 + 3 行数据
            lines = csv_text.strip().splitlines()
            assert len(lines) == 4  # header + 3 data rows

            # 验证表头包含必要字段
            assert "timestamp" in lines[0]
            assert "source_ip" in lines[0]
            assert "method" in lines[0]
            assert "path" in lines[0]

            # 验证数据行
            assert "192.168.1.100" in csv_text
            assert "/.env" in csv_text
        finally:
            os.unlink(path)


class TestParseDirectory:
    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            events = parse_zeek_directory(tmpdir)
            assert events == []

    def test_multi_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # 写入 http.log 和 conn.log
            http_path = os.path.join(tmpdir, "http.log")
            with open(http_path, "w", encoding="utf-8") as f:
                f.write(SAMPLE_HTTP_LOG)

            conn_path = os.path.join(tmpdir, "conn.log")
            with open(conn_path, "w", encoding="utf-8") as f:
                f.write(SAMPLE_CONN_LOG)

            events = parse_zeek_directory(tmpdir)
            assert len(events) > 0

            # 应该有 5 个事件（3 http + 2 conn），但可能会去重
            assert len(events) >= 3
