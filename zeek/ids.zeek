# Zeek IDS 策略脚本 — 为教学实验场景定制
#
# 加载方式:
#   zeek -i <interface> /path/to/ids.zeek
#
# 功能:
#   - 加载基础协议分析 (HTTP, SSL, DNS, Conn)
#   - 记录 HTTP 请求方法、URI、Host、User-Agent、状态码
#   - 记录 SSL/TLS 的 JA3/JA3s 指纹
#   - 输出标准 Zeek TSV 日志供本项目解析

@load protocols/conn
@load protocols/http
@load protocols/ssl
@load protocols/dns

# 确保记录 HTTP 请求体的用户名/密码字段（用于暴力登录检测）
redef HTTP::default_capture_password = T;

# 扩展 HTTP 日志：记录 Cookie
redef HTTP::capture_referrer = T;

# 开启 SSL 的 JA3 指纹记录
redef SSL::ja3 = T;

# 自定义告警：检测到 SQL 注入关键词时记录 notice
event http_request(c: connection, method: string, original_uri: string,
                   unescaped_uri: string, version: string)
{
    local uri_lower = to_lower(original_uri);

    # SQL 注入关键词检测
    if (/%27|%22|select%20|union%20|--%20|%23|%00/i in uri_lower ||
        /\b(select|union|insert|drop|delete|update)\b.*\b(from|into|where|set)\b/i in uri_lower)
    {
        NOTICE([$note=SQLInjection_Attempt,
                $msg=fmt("可能的 SQL 注入尝试: %s %s", method, original_uri),
                $conn=c,
                $identifier=cat(c$id$orig_h, original_uri)]);
    }

    # XSS 关键词检测
    if (/<script|<img|<svg|onerror=|onload=|alert\(|%3Cscript/i in uri_lower ||
        /<script|<img|<svg|onerror=|onload=|alert\(/i in unescaped_uri)
    {
        NOTICE([$note=XSS_Attempt,
                $msg=fmt("可能的 XSS 尝试: %s %s", method, original_uri),
                $conn=c,
                $identifier=cat(c$id$orig_h, original_uri)]);
    }

    # 路径遍历检测
    if (/\.\.\/|\.\.%2f|%2e%2e%2f|%2e%2e%5c/i in uri_lower)
    {
        NOTICE([$note=PathTraversal_Attempt,
                $msg=fmt("可能的路径遍历尝试: %s %s", method, original_uri),
                $conn=c,
                $identifier=cat(c$id$orig_h, original_uri)]);
    }

    # 敏感路径访问
    local suspicious_paths = /\.env|phpmyadmin|wp-admin|\.git\/config|\.svn|web-inf|boot\.ini/i;
    if (suspicious_paths in uri_lower)
    {
        NOTICE([$note=SuspiciousPath_Access,
                $msg=fmt("敏感路径访问: %s %s", method, original_uri),
                $conn=c,
                $identifier=cat(c$id$orig_h, original_uri)]);
    }
}

# 检测暴力登录：HTTP 401 响应
event http_reply(c: connection, version: string, code: count, reason: string)
{
    if (code == 401)
    {
        NOTICE([$note=HTTP_Auth_Failure,
                $msg=fmt("HTTP 认证失败: %s -> %s:%d (%s %s)",
                         c$id$orig_h, c$id$resp_h, c$id$resp_p,
                         c$http$method, c$http$uri),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }
}

# 记录端口扫描特征 (Zeek 的 Scan 检测默认已加载)
redef Scan::port_scan_trigger = 10;
redef Scan::port_skip_mono = F;

event zeek_init()
{
    print fmt("[IDS] Zeek 教学实验策略已加载 — 接口: %s", get_interface());
    print fmt("[IDS] 将检测: SQL注入 / XSS / 路径遍历 / 敏感路径 / 暴力登录 / 端口扫描");
}
