"""Unit tests for MITRE ATT&CK Mapper module"""

import pytest
from ioc_intel.mitre_mapper import map_to_mitre, get_mitre_matrix


class TestIPMapping:
    """Test MITRE mapping for IP addresses"""
    
    def test_malicious_ip_maps_to_c2(self):
        """Test that malicious IP maps to C2 technique"""
        result = map_to_mitre("ipv4", {"feodo_listed": True})
        assert result["technique_id"] == "T1071.001"
        assert "Command and Control" in result["tactic"]
    
    def test_abuse_ip_maps_to_c2(self):
        """Test that high abuse score IP maps to C2"""
        result = map_to_mitre("ipv4", {"abuse_confidence": 90})
        assert result["technique_id"] == "T1071"
        assert "Command and Control" in result["tactic"]
    
    def test_vt_positive_ip_maps_to_c2(self):
        """Test that VT positive IP maps to C2"""
        result = map_to_mitre("ipv4", {"vt_positives": 10})
        assert result["technique_id"] == "T1071"


class TestDomainMapping:
    """Test MITRE mapping for domains"""
    
    def test_phishing_domain_maps_correctly(self):
        """Test that phishing domain maps to phishing technique"""
        result = map_to_mitre("domain", {"tags": ["phishing"], "urlhaus_listed": True})
        assert result["technique_id"] == "T1566"
        assert result["tactic"] == "Initial Access"
    
    def test_malware_domain_maps_to_distribution(self):
        """Test that malware domain maps to distribution"""
        result = map_to_mitre("domain", {"urlhaus_listed": True})
        assert result["technique_id"] == "T1020"


class TestHashMapping:
    """Test MITRE mapping for file hashes"""
    
    def test_malware_hash_maps_correctly(self):
        """Test that detected malware hash maps correctly"""
        result = map_to_mitre("md5", {"vt_positives": 40})
        assert result["technique_id"] == "T1204"
        assert result["tactic"] == "Execution"
    
    def test_urlhaus_hash_maps_to_distribution(self):
        """Test that URLhaus hash maps to distribution"""
        result = map_to_mitre("sha256", {"urlhaus_listed": True})
        assert result["technique_id"] == "T1020"


class TestURLMapping:
    """Test MITRE mapping for URLs"""
    
    def test_malware_url_maps_to_distribution(self):
        """Test that malware URL maps to distribution"""
        result = map_to_mitre("url", {"urlhaus_listed": True})
        assert result["technique_id"] == "T1020"
    
    def test_exploit_url_maps_correctly(self):
        """Test that exploit URL maps correctly"""
        result = map_to_mitre("url", {"tags": ["exploit"]})
        assert result["technique_id"] == "T1189"
        assert result["tactic"] == "Initial Access"


class TestUnknownIOCType:
    """Test MITRE mapping for unknown IOC types"""
    
    def test_unknown_returns_default(self):
        """Test that unknown type returns default mapping"""
        result = map_to_mitre("unknown", {})
        assert "technique_id" in result
        assert result["technique_id"] == "T0000"


class TestMITREMatrix:
    """Test MITRE matrix retrieval"""
    
    def test_matrix_returns_list(self):
        """Test that matrix returns a list"""
        matrix = get_mitre_matrix()
        assert isinstance(matrix, list)
        assert len(matrix) > 0
    
    def test_matrix_entries_have_required_fields(self):
        """Test that matrix entries have required fields"""
        matrix = get_mitre_matrix()
        for entry in matrix:
            assert "technique_id" in entry
            assert "technique_name" in entry
            assert "tactic" in entry
            assert "description" in entry


class TestEdgeCases:
    """Test edge cases in MITRE mapping"""
    
    def test_empty_enrichment_data(self):
        """Test mapping with empty enrichment data"""
        result = map_to_mitre("ipv4", {})
        assert "technique_id" in result
    
    def test_null_enrichment_data(self):
        """Test mapping with minimal enrichment data"""
        result = map_to_mitre("domain", {})
        assert "technique_id" in result
