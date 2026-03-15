"""Unit tests for IOC Validator module"""

import pytest
from ioc_intel.validator import (
    detect_ioc_type, is_ipv4, is_ipv6, is_domain, is_url, is_hash
)


class TestIPDetection:
    """Test IP address detection"""
    
    def test_ipv4_detection(self):
        """Test IPv4 detection"""
        assert detect_ioc_type("8.8.8.8") == "ipv4"
        assert detect_ioc_type("192.168.1.1") == "ipv4"
        assert detect_ioc_type("10.0.0.1") == "ipv4"
    
    def test_ipv6_detection(self):
        """Test IPv6 detection"""
        assert detect_ioc_type("2001:db8::1") == "ipv6"
        assert detect_ioc_type("2001:4860:4860::8888") == "ipv6"
    
    def test_invalid_ip(self):
        """Test invalid IP detection"""
        assert detect_ioc_type("999.999.999.999") == "unknown"
        assert detect_ioc_type("192.168.1") == "unknown"


class TestDomainDetection:
    """Test domain detection"""
    
    def test_domain_detection(self):
        """Test domain detection"""
        assert detect_ioc_type("malware.example.com") == "domain"
        assert detect_ioc_type("google.com") == "domain"
        assert detect_ioc_type("evil-domain.net") == "domain"
    
    def test_invalid_domain(self):
        """Test invalid domain detection"""
        assert detect_ioc_type("not a domain") == "unknown"
        assert detect_ioc_type(".com") == "unknown"


class TestHashDetection:
    """Test hash detection"""
    
    def test_md5_detection(self):
        """Test MD5 hash detection"""
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
        assert detect_ioc_type("5d41402abc4b2a76b9719d911017c592") == "md5"
    
    def test_sha1_detection(self):
        """Test SHA1 hash detection"""
        assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    
    def test_sha256_detection(self):
        """Test SHA256 hash detection"""
        assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
        assert detect_ioc_type("a" * 64) == "sha256"
    
    def test_invalid_hash(self):
        """Test invalid hash detection"""
        assert detect_ioc_type("not_a_hash") == "unknown"
        assert detect_ioc_type("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") == "unknown"  # 32 chars but not hex


class TestURLDetection:
    """Test URL detection"""
    
    def test_url_detection(self):
        """Test URL detection"""
        assert detect_ioc_type("http://malware.example.com/payload") == "url"
        assert detect_ioc_type("https://evil-site.net/malware.exe") == "url"
    
    def test_invalid_url(self):
        """Test invalid URL detection"""
        assert detect_ioc_type("not a url") == "unknown"


class TestEdgeCases:
    """Test edge cases"""
    
    def test_empty_string(self):
        """Test empty string"""
        assert detect_ioc_type("") == "unknown"
    
    def test_whitespace(self):
        """Test whitespace"""
        assert detect_ioc_type("   ") == "unknown"
    
    def test_none(self):
        """Test None input"""
        assert detect_ioc_type(None) == "unknown"


class TestHelperFunctions:
    """Test individual helper functions"""
    
    def test_is_ipv4(self):
        """Test is_ipv4 function"""
        assert is_ipv4("8.8.8.8") is True
        assert is_ipv4("999.999.999.999") is False
    
    def test_is_ipv6(self):
        """Test is_ipv6 function"""
        assert is_ipv6("2001:db8::1") is True
        assert is_ipv6("8.8.8.8") is False
    
    def test_is_domain(self):
        """Test is_domain function"""
        assert is_domain("example.com") is True
        assert is_domain("not a domain") is False
    
    def test_is_hash(self):
        """Test is_hash function"""
        assert is_hash("d41d8cd98f00b204e9800998ecf8427e") == "md5"
        assert is_hash("a" * 64) == "sha256"
        assert is_hash("not a hash") is None
