# Zeek 集成说明

本目录包含与 [Zeek](https://zeek.org/)（原名 Bro）集成的配置和脚本，用于为系统添加实时网络抓包与流量分析能力。

## 概述

Zeek 是一个强大的网络安全监控框架。通过与本系统集成，你可以：

1. **实时抓包**：在指定网络接口上捕获流量
2. **协议解析**：自动解析 HTTP、SSL/TLS、DNS 等应用层协议
3. **结构化日志**：输出标准 TSV 日志，被本系统自动消费分析
4. **自定义检测**：通过 Zeek 脚本（`ids.zeek`）在数据源端进行初步检测

## 架构

```
[网络流量] → Zeek (抓包+协议解析) → TSV 日志文件
                                         ↓
[本系统采集器] → 解析 TSV → LogEvent → IDS 分析引擎 → 界面展示
```

## 环境要求

### Linux (推荐)

```bash
# Ubuntu / Debian
sudo apt install zeek

# 或源码编译
# https://docs.zeek.org/en/current/install/install.html

# 验证安装
zeek --version
```

### Windows

Windows 下的 Zeek 支持为实验性。推荐在 WSL 或 Linux 虚拟机中运行 Zeek，
然后将日志目录映射到本系统。

## 使用方法

### 1. 启动 Zeek 抓包

通过 Web 界面 ("设置" → "Zeek 数据采集") 点击"启动抓包"，
或手动启动：

```bash
# 手动启动（eth0 替换为实际接口）
zeek -i eth0 /path/to/zeek/ids.zeek
```

### 2. 查看 Zeek 状态

```
GET /api/collector/status
```

### 3. 分析 Zeek 已产生的日志

```
GET /api/collector/analyze
```

### 4. 停止抓包

通过 Web 界面点击"停止抓包"，
或按 Ctrl+C 停止前台运行的 Zeek。

## Zeek 日志字段映射

| Zeek 日志     | 字段                           | 映射到 LogEvent        |
|---------------|--------------------------------|------------------------|
| conn.log      | ts, id.orig_h, id.resp_h,     | timestamp, source_ip,  |
|               | id.resp_p, proto, duration,    | target_ip, port,       |
|               | orig_bytes                     | protocol, duration_ms, |
|               |                                | bytes_sent             |
| http.log      | ts, id.orig_h, id.resp_h,     | timestamp, source_ip,  |
|               | id.resp_p, method, host, uri,  | target_ip, port,       |
|               | user_agent, status_code        | method, host, path,    |
|               |                                | user_agent, status_code|
| ssl.log       | ts, id.orig_h, id.resp_h,     | timestamp, source_ip,  |
|               | id.resp_p, server_name, ja3,   | target_ip, port, host, |
|               | ja3s                           | tls_fingerprint        |

## 实验场景演示流程

1. 启动本系统后端和前端
2. 打开"设置"页面 → "Zeek 数据采集" → 选择接口 → 启动抓包
3. 运行攻击脚本（如 `交大学生成绩管理系统_vuln_lab/scripts/demo_attacks.py`）
4. 在"实时监控"页面查看实时告警推送
5. 在"仪表盘"查看统计概览
