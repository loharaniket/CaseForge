import pytest
from src.services.intelligence.ip_service import is_valid_public_ip

def test_is_valid_public_ip():
    assert is_valid_public_ip("8.8.8.8") is True
    assert is_valid_public_ip("192.168.1.1") is False
    assert is_valid_public_ip("10.0.0.1") is False
    assert is_valid_public_ip("127.0.0.1") is False
    assert is_valid_public_ip("169.254.1.1") is False
    assert is_valid_public_ip("invalid") is False
    assert is_valid_public_ip("256.256.256.256") is False
