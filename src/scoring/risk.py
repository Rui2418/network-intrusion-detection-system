BASE_SCORES = {
    "port_scan": 45,
    "brute_force": 55,
    "high_frequency": 35,
    "suspicious_path": 30,
    "abnormal_status": 25,
}


def score_alert(alert_key: str, count: int) -> tuple[int, str]:
    score = min(100, BASE_SCORES.get(alert_key, 20) + count * 5)
    if score >= 80:
        return score, "高危"
    if score >= 50:
        return score, "中危"
    return score, "低危"
