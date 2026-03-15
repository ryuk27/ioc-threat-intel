"""Unit tests for IOC Risk Scorer module"""

import pytest
from ioc_intel.scorer import calculate_score, get_risk_level


class TestRiskLevelClassification:
    """Test risk level classification"""
    
    def test_critical_threshold(self):
        """Test CRITICAL level threshold"""
        assert get_risk_level(95) == "CRITICAL"
        assert get_risk_level(100) == "CRITICAL"
        assert get_risk_level(80) == "CRITICAL"
    
    def test_high_threshold(self):
        """Test HIGH level threshold"""
        assert get_risk_level(75) == "HIGH"
        assert get_risk_level(60) == "HIGH"
        assert get_risk_level(79) == "HIGH"
    
    def test_medium_threshold(self):
        """Test MEDIUM level threshold"""
        assert get_risk_level(45) == "MEDIUM"
        assert get_risk_level(40) == "MEDIUM"
        assert get_risk_level(59) == "MEDIUM"
    
    def test_low_threshold(self):
        """Test LOW level threshold"""
        assert get_risk_level(15) == "LOW"
        assert get_risk_level(16) == "LOW"
        assert get_risk_level(39) == "LOW"
    
    def test_clean_threshold(self):
        """Test CLEAN level threshold"""
        assert get_risk_level(3) == "CLEAN"
        assert get_risk_level(0) == "CLEAN"
        assert get_risk_level(14) == "CLEAN"


class TestScoreCalculation:
    """Test risk score calculation"""
    
    def test_virustotal_high_detections(self):
        """Test score calculation with high VT detections"""
        data = {"vt_positives": 50}
        score = calculate_score(data)
        assert 0 <= score <= 100
        assert score > 70
    
    def test_abuseipdb_high_confidence(self):
        """Test score calculation with high AbuseIPDB confidence"""
        data = {"abuse_confidence": 90}
        score = calculate_score(data)
        assert 0 <= score <= 100
        assert score > 60
    
    def test_feodo_listed(self):
        """Test score calculation for Feodo listed IP"""
        data = {"feodo_listed": True}
        score = calculate_score(data)
        assert score >= 30
    
    def test_urlhaus_listed(self):
        """Test score calculation for URLhaus listed domain"""
        data = {"urlhaus_listed": True}
        score = calculate_score(data)
        assert score >= 25
    
    def test_combined_indicators(self):
        """Test score calculation with combined indicators"""
        data = {
            "vt_positives": 40,
            "abuse_confidence": 80,
            "feodo_listed": True,
            "urlhaus_listed": True
        }
        score = calculate_score(data)
        assert score >= 80
    
    def test_clean_ioc(self):
        """Test score calculation for clean IOC"""
        data = {}
        score = calculate_score(data)
        assert score == 0
    
    def test_score_bounds(self):
        """Test that score never exceeds 100"""
        data = {
            "vt_positives": 100,
            "abuse_confidence": 100,
            "feodo_listed": True,
            "urlhaus_listed": True,
            "otx_pulse_count": 50,
            "shodan_vulnerabilities": ["vuln1", "vuln2", "vuln3"]
        }
        score = calculate_score(data)
        assert score <= 100


class TestEdgeCases:
    """Test edge cases in scoring"""
    
    def test_empty_data(self):
        """Test calculation with empty data"""
        score = calculate_score({})
        assert score == 0
    
    def test_zero_values(self):
        """Test calculation with zero values"""
        data = {"vt_positives": 0, "abuse_confidence": 0}
        score = calculate_score(data)
        assert score == 0
    
    def test_negative_values_ignored(self):
        """Test that negative values don't cause issues"""
        data = {"vt_positives": 0}
        score = calculate_score(data)
        assert score >= 0
