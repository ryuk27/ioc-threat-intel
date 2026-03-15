"""Unit tests for MITRE ATT&CK Mapper module"""

import pytest
from ioc_intel.mitre_mapper import map_to_mitre, get_mitre_matrix, normalize_tag


class TestIPMapping:
    """Test MITRE mapping for IP addresses"""
    
    def test_malicious_ip_maps_to_c2(self):
        """Test that botnet IP maps to botnet technique"""
        result = map_to_mitre("ipv4", {"feodo_malware": "botnet"})
        assert result["technique_id"] == "T1583.004"
        assert "Resource Development" in result["tactic"]
    
    def test_abuse_ip_maps_to_c2(self):
        """Test that high abuse score IP maps to C2"""
        result = map_to_mitre("ipv4", {"otx_tags": ["c2"]})
        assert result["technique_id"] == "T1071.001"
        assert "Command and Control" in result["tactic"]
    
    def test_vt_positive_ip_maps_to_c2(self):
        """Test that VT positive IP maps to C2"""
        result = map_to_mitre("ipv4", {"vt_categories": ["c2"]})
        assert result["technique_id"] == "T1071.001"


class TestDomainMapping:
    """Test MITRE mapping for domains"""
    
    def test_phishing_domain_maps_correctly(self):
        """Test that phishing domain maps to phishing technique"""
        result = map_to_mitre("domain", {"urlhaus_tags": ["phishing"]})
        assert result["technique_id"] == "T1566"
        assert result["tactic"] == "Initial Access"
    
    def test_malware_domain_maps_to_distribution(self):
        """Test that malware domain maps to distribution"""
        result = map_to_mitre("domain", {"urlhaus_tags": ["malware-distribution"]})
        assert result["technique_id"] == "T1105"


class TestHashMapping:
    """Test MITRE mapping for file hashes"""
    
    def test_malware_hash_maps_correctly(self):
        """Test that detected malware hash maps correctly"""
        result = map_to_mitre("md5", {"vt_categories": ["trojan"]})
        assert result["technique_id"] == "T1204"
        assert result["tactic"] == "Execution"
    
    def test_urlhaus_hash_maps_to_distribution(self):
        """Test that URLhaus hash maps to distribution"""
        result = map_to_mitre("sha256", {"urlhaus_tags": ["malware-distribution"]})
        assert result["technique_id"] == "T1105"


class TestURLMapping:
    """Test MITRE mapping for URLs"""
    
    def test_malware_url_maps_to_distribution(self):
        """Test that malware URL maps to distribution"""
        result = map_to_mitre("url", {"urlhaus_tags": ["malware-distribution"]})
        assert result["technique_id"] == "T1105"
    
    def test_exploit_url_maps_correctly(self):
        """Test that exploit URL maps correctly"""
        result = map_to_mitre("url", {"urlhaus_tags": ["exploit"]})
        assert result["technique_id"] == "T1190"
        assert result["tactic"] == "Initial Access"


class TestUnknownIOCType:
    """Test MITRE mapping for unknown IOC types"""
    
    def test_unknown_returns_default(self):
        """Test that unknown type returns fallback mapping"""
        result = map_to_mitre("unknown_type", {})
        assert "technique_id" in result
        # Unknown IOC type defaults to infrastructure key which is T1583
        assert result["technique_id"] in ["T1583", "T1090", "T1071"]


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


class TestTagNormalization:
    """Test tag normalization functionality"""
    
    def test_normalize_phishing_tag(self):
        """Test that phishing variations normalize correctly"""
        assert normalize_tag("phishing") == "phishing"
        assert normalize_tag("Phishing") == "phishing"
        assert normalize_tag("PHISHING") == "phishing"
    
    def test_normalize_c2_tag(self):
        """Test that C2 variations normalize correctly"""
        assert normalize_tag("c2") == "c2_web"
        assert normalize_tag("c&c") == "c2_web"
        assert normalize_tag("command-and-control") == "c2_web"
    
    def test_normalize_unknown_tag(self):
        """Test that unknown tag returns 'unknown'"""
        assert normalize_tag("unknown_malware_type") == "unknown"


class TestMultipleTechniques:
    """Test that map_to_mitre returns multiple techniques when appropriate"""
    
    def test_multiple_tags_produce_additional_techniques(self):
        """Test that multiple tags produce additional techniques"""
        result = map_to_mitre("domain", {
            "urlhaus_tags": ["phishing", "c2"]
        })
        assert "technique_id" in result
        assert "additional_techniques" in result
        assert isinstance(result["additional_techniques"], list)
    
    def test_confidence_score_present(self):
        """Test that confidence score is calculated"""
        result = map_to_mitre("ipv4", {"otx_tags": ["botnet"]})
        assert "confidence_score" in result
        assert 0 <= result["confidence_score"] <= 100
    
    def test_source_tags_preserved(self):
        """Test that source tags are preserved in result"""
        result = map_to_mitre("domain", {"urlhaus_tags": ["phishing"]})
        assert "source_tags" in result
        assert len(result["source_tags"]) > 0


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
