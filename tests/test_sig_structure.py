"""签名库结构完整性验证"""
from src.detector.signatures import load_signatures


def test_signature_count_meets_target():
    """设计报告要求覆盖6大类，签名总数应≥8条"""
    sigs = load_signatures()
    assert len(sigs) >= 8, f"签名数应≥8，实际{len(sigs)}"


def test_all_signatures_have_valid_structure():
    """所有签名必须具备核心字段且数值在合法范围"""
    sigs = load_signatures()
    required = {"id", "alert_type", "category", "fields", "patterns", "base_score", "confidence"}
    for sig in sigs:
        missing = required - set(sig.keys())
        assert not missing, f"签名 {sig.get('id', '?')} 缺少字段: {missing}"
        assert 0 <= sig["base_score"] <= 100, f"{sig['id']} base_score={sig['base_score']}"
        assert 0 <= sig["confidence"] <= 1, f"{sig['id']} confidence={sig['confidence']}"
        assert len(sig["patterns"]) > 0, f"{sig['id']} patterns为空"
