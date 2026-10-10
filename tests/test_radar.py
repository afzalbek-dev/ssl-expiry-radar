"""Unit tests for SSL Expiry Radar."""
from datetime import datetime, timezone, timedelta
import pytest
from ssl_radar.checker import CertInspector
from ssl_radar.scanner import DomainScanner

def test_parse_cert_mock():
    inspector = CertInspector()
    
    # Mock cert dict
    future_date = datetime.now(timezone.utc) + timedelta(days=45)
    not_after_str = future_date.strftime("%b %d %H:%M:%S %Y GMT")
    
    mock_cert = {
        "notAfter": not_after_str,
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com"))
    }
    
    parsed = inspector.parse_cert(mock_cert, "example.com")
    assert parsed["valid"] is True
    assert parsed["hostname"] == "example.com"
    assert parsed["issuer"] == "Let's Encrypt"
    assert parsed["days_remaining"] >= 44
    assert "www.example.com" in parsed["san"]

def test_domain_scanner_classification():
    scanner = DomainScanner(warning_days=30, critical_days=7)
    
    healthy_res = {"valid": True, "days_remaining": 60}
    assert scanner.classify_status(healthy_res) == "HEALTHY"
    
    warning_res = {"valid": True, "days_remaining": 20}
    assert scanner.classify_status(warning_res) == "WARNING"
    
    critical_res = {"valid": True, "days_remaining": 5}
    assert scanner.classify_status(critical_res) == "CRITICAL"
    
    expired_res = {"valid": True, "days_remaining": 0}
    assert scanner.classify_status(expired_res) == "EXPIRED"
    
    error_res = {"valid": False}
    assert scanner.classify_status(error_res) == "ERROR"
