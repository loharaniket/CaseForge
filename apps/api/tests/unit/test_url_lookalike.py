import pytest
from src.services.intelligence.lookalike_detector import detect_lookalike

def test_detect_lookalike_normal():
    is_lookalike, target, explanation = detect_lookalike("example.com")
    assert not is_lookalike
    
def test_detect_lookalike_exact_match():
    # If the domain is exactly the brand, it's not a lookalike (it's either legit or spoofing)
    is_lookalike, target, explanation = detect_lookalike("microsoft.com")
    assert not is_lookalike
    
def test_detect_lookalike_substring():
    is_lookalike, target, explanation = detect_lookalike("microsoft-secure-login.com")
    assert is_lookalike
    assert target == "microsoft"
    
def test_detect_lookalike_typosquatting():
    # 'rn' instead of 'm' or similar edit distance
    is_lookalike, target, explanation = detect_lookalike("microsft.com")
    assert is_lookalike
    assert target == "microsoft"
    
def test_detect_lookalike_punycode():
    is_lookalike, target, explanation = detect_lookalike("xn--mcrosoft-q2a.com")
    assert is_lookalike
    assert "Punycode" in explanation
