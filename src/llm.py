import json
import os
from pathlib import Path

try:
    import requests
    _HTTP_OK = True
except ImportError:
    _HTTP_OK = False

CONFIG_PATH = Path(__file__).resolve().parent.parent / "data" / "llm_config.json"
DEFAULT_CONFIG = {
    "provider": "ollama",
    "api_url": "http://localhost:11434",
    "api_key": "",
    "model": "qwen2.5:3b",
    "enabled": True,
}

def _load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                return {**DEFAULT_CONFIG, **cfg}
        except (json.JSONDecodeError, IOError):
            pass
    _save_config(DEFAULT_CONFIG)
    return dict(DEFAULT_CONFIG)

def _save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def get_config() -> dict:
    return _load_config()

def update_config(cfg: dict):
    current = _load_config()
    current.update({k: v for k, v in cfg.items() if k in DEFAULT_CONFIG})
    _save_config(current)

def _list_openai_models(api_url: str, api_key: str) -> list:
    try:
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        resp = requests.get(f"{api_url}/models", headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return [m.get("id", "") for m in data.get("data", data.get("models", []))]
    except Exception:
        pass
    return []


def list_models() -> list:
    cfg = _load_config()
    provider = cfg.get("provider", "ollama")
    api_url = cfg.get("api_url", "").rstrip("/")
    api_key = cfg.get("api_key", "")
    if provider == "ollama" and _HTTP_OK:
        try:
            resp = requests.get(f"{api_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                return [m.get("name", "") for m in resp.json().get("models", [])]
        except Exception:
            pass
    elif provider == "openai":
        return _list_openai_models(api_url, api_key)
    return []


def test_connection(cfg: dict = None) -> dict:
    if cfg is None:
        cfg = _load_config()
    if not _HTTP_OK:
        return {"ok": False, "error": "requests 库未安装"}

    provider = cfg.get("provider", "ollama")
    api_url = cfg.get("api_url", "").rstrip("/")
    api_key = cfg.get("api_key", "")
    model = cfg.get("model", "qwen2.5:3b")

    try:
        if provider == "ollama":
            resp = requests.get(f"{api_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                names = [m.get("name", "") for m in models]
                if model in names:
                    return {"ok": True, "provider": "ollama", "model": model}
                if names:
                    return {"ok": True, "provider": "ollama", "model": names[0], "hint": f"模型 {model} 不存在，可用: {names[0]}"}
                return {"ok": True, "provider": "ollama", "model": "none", "hint": "无可用模型，请先 ollama pull 下载"}
            return {"ok": False, "error": f"HTTP {resp.status_code}"}

        elif provider == "openai":
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            resp = requests.post(
                f"{api_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "回复OK"}],
                    "max_tokens": 10,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                return {"ok": True, "provider": "openai", "model": model}
            err = resp.json().get("error", {}).get("message", f"HTTP {resp.status_code}")
            models = _list_openai_models(api_url, api_key)
            return {"ok": False, "error": err, "available_models": models}

        else:
            return {"ok": False, "error": f"未知 provider: {provider}"}
    except requests.ConnectionError:
        return {"ok": False, "error": f"无法连接到 {api_url}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _call_llm(prompt: str) -> str or None:
    cfg = _load_config()
    if not cfg.get("enabled", True):
        return None
    if not _HTTP_OK:
        return None

    provider = cfg.get("provider", "ollama")
    api_url = cfg.get("api_url", "").rstrip("/")
    api_key = cfg.get("api_key", "")
    model = cfg.get("model", "qwen2.5:3b")

    try:
        if provider == "ollama":
            resp = requests.post(
                f"{api_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()

        elif provider == "openai":
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            resp = requests.post(
                f"{api_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        pass
    return None

def is_available() -> bool:
    return test_connection().get("ok", False)

def _fallback_analyze(alert: dict) -> str:
    alert_type = alert.get("alert_type", "未知")
    source_ip = alert.get("source_ip", "未知")
    target = alert.get("target", "未知")
    suggestions = {
        "端口扫描": "攻击者正在探测目标主机开放的服务端口，属于侦察阶段。建议立即在防火墙中阻断来源IP的所有入站流量，并检查目标主机上非必要服务是否已关闭。",
        "暴力登录": f"攻击者通过反复尝试密码来猜测目标账号 {target} 的凭据。建议立即封锁来源IP {source_ip}，检查目标账号的登录日志，启用密码复杂度策略和账号锁定策略。",
        "异常访问频率": f"来源IP {source_ip} 的请求频率显著超出正常范围，可能在进行爬虫、暴力枚举或DoS准备。建议对该IP进行限速或临时封禁，分析其请求模式以确定攻击意图。",
        "可疑路径访问": f"检测到对敏感路径 {target} 的访问，可能是攻击者在探测Web应用漏洞。建议检查该路径是否存在安全风险，确认Web服务器配置已正确限制敏感目录访问。",
        "异常状态码": f"大量异常HTTP状态码表明请求被服务器拒绝或目标资源不存在，可能为目录暴力枚举或漏洞扫描。建议拦截持续产生404/403/500的IP，并审查访问日志。",
    }
    key = alert_type if alert_type in suggestions else "异常访问频率"
    cfg = _load_config()
    provider_name = "Ollama" if cfg["provider"] == "ollama" else "OpenAI"
    return f"""【攻击分析】{key}的自动化分析（{provider_name} 模型不可用，以下为专家规则建议）：
{suggestions.get(key, suggestions['异常访问频率'])}

【处置建议】在IPS中创建规则：DROP 来自 {source_ip} 的流量。
【后续观察】持续监控 {source_ip} 的后续行为，如发现新的攻击特征及时告警。"""

def analyze_alert(alert: dict) -> str:
    alert_type = alert.get("alert_type", "未知")
    source_ip = alert.get("source_ip", "未知")
    target = alert.get("target", "未知")
    score = alert.get("score", 0)
    level = alert.get("level", "低危")
    evidence = alert.get("evidence", "")

    prompt = f"""你是一名网络安全专家。请分析以下入侵检测告警并用中文给出简短的安全分析和建议（150字以内）。

告警类型: {alert_type}
来源IP: {source_ip}
目标: {target}
风险等级: {level} (分数: {score}/100)
检测依据: {evidence}

请按以下格式回复:
【攻击分析】{alert_type}的威胁程度和常见攻击目的
【处置建议】具体的防御措施（如阻断IP、限制端口等）
【后续观察】建议监控的重点"""

    result = _call_llm(prompt)
    return result if result else _fallback_analyze(alert)

def suggest_defense(alert: dict) -> dict:
    alert_type = alert.get("alert_type", "未知")
    source_ip = alert.get("source_ip", "未知")
    target = alert.get("target", "未知")
    score = alert.get("score", 0)

    prompt = f"""你是一名网络安全自动化系统。根据以下告警，直接生成一个JSON格式的IPS防御规则。只返回JSON，不要任何解释。

告警: {alert_type} 来自 {source_ip}，目标 {target}，风险分 {score}

JSON格式:
{{"protocol": "any", "saddr": "{source_ip}", "dport": 0, "action": "drop", "priority": 100, "reason": "简短理由"}}

规则:"""

    result = _call_llm(prompt)
    if result:
        try:
            cleaned = result.strip().lstrip("```json").rstrip("```").strip()
            return {"rule": json.loads(cleaned), "ai_generated": True}
        except json.JSONDecodeError:
            pass

    priority = min(100, max(10, score + 20))
    return {
        "rule": {
            "protocol": "any",
            "saddr": source_ip if source_ip and source_ip != "未知" else "",
            "daddr": "",
            "sport": 0,
            "dport": 0,
            "action": "drop",
            "priority": priority,
            "enabled": True,
        },
        "ai_generated": False,
        "reason": f"基于{alert_type}告警自动生成的防御规则",
    }

def analyze_attack_chain(alerts: list) -> str:
    if not alerts:
        return "暂无足够告警数据用于攻击链分析。"

    alert_types = [a.get("alert_type", "未知") for a in alerts[:20]]
    sources = list(set(a.get("source_ip", "未知") for a in alerts[:20] if a.get("source_ip")))
    levels = [a.get("level", "") for a in alerts[:20]]
    critical_high = sum(1 for l in levels if l in ("高危", "critical", "high"))

    type_summary = "; ".join(alert_types[:5])
    source_summary = "; ".join(sources[:3])

    prompt = f"""你是一名网络安全事件响应专家。根据以下告警序列，分析可能的攻击链并用中文给出简短的攻击链条分析（200字以内）。

告警序列: {type_summary}
来源IP: {source_summary}
高危/严重告警数: {critical_high}/{len(alerts)}

请描述攻击者可能的攻击阶段（侦察→渗透→提权→横向移动→目标达成）和关键事件。"""

    result = _call_llm(prompt)
    if result:
        return result

    has_portscan = any("端口扫描" in t for t in alert_types)
    has_brute = any("暴力登录" in t for t in alert_types)
    has_suspicious = any("可疑路径" in t for t in alert_types)
    has_highfreq = any("异常访问频率" in t for t in alert_types)
    has_status = any("异常状态码" in t for t in alert_types)

    stages = []
    if has_portscan:
        stages.append("🔍 侦察阶段: 攻击者对目标进行了端口扫描，探测开放服务")
    if has_brute:
        stages.append("🔑 渗透阶段: 攻击者对SSH/登录服务进行了暴力破解尝试")
    if has_suspicious:
        stages.append("🎯 利用阶段: 攻击者探测了敏感路径和漏洞入口")
    if has_highfreq:
        stages.append("⚡ 攻击实施: 大量异常请求表明攻击正在执行中")
    if has_status:
        stages.append("📊 结果反馈: 大量异常状态码表明攻击试探已获取了系统反馈")

    if not stages:
        stages.append("⚠ 告警类型分散，建议逐条审查以确定攻击模式")

    chain = f"""【攻击链推演】（AI模型不可用，基于规则统计推断）

""" + "\n".join(stages) + f"""

【关键发现】共检测到 {len(alerts)} 条告警，涉及 {len(sources)} 个可疑IP，其中 {critical_high} 条为高危/严重级别。
【建议措施】对已确认的攻击IP下发IPS阻断规则，加强目标主机的监控和日志审计。"""
    return chain
