"""MITRE ATT&CK Mapping Module"""

from typing import Dict, Any, List


MITRE_MAPPINGS = {
    "c2_ip": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversary using IP for C2 communication"
    },
    "botnet_c2": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "C2 communication over web protocols"
    },
    "phishing_domain": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "description": "Domain used in phishing campaign"
    },
    "malware_hash": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
        "description": "Malicious file requiring user execution"
    },
    "data_exfil": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Data exfiltration using established C2 channel"
    },
    "malware_distribution": {
        "technique_id": "T1020",
        "technique_name": "Automated Exfiltration",
        "tactic": "Exfiltration",
        "description": "Malware distribution infrastructure"
    },
    "exploit_kit": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Exploit kit infrastructure"
    }
}


def map_to_mitre(ioc_type: str, enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map IOC findings to MITRE ATT&CK techniques
    
    Args:
        ioc_type: Type of IOC ('ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', etc.)
        enrichment_data: Enrichment results from threat intelligence sources
        
    Returns:
        Dict: MITRE technique mapping with technique_id, technique_name, tactic, description
    """
    
    # Default mapping if nothing matches
    default_mapping = {
        "technique_id": "T0000",
        "technique_name": "Unknown Technique",
        "tactic": "Reconnaissance",
        "description": "Unable to determine specific MITRE technique"
    }
    
    # Determine mapping based on IOC type and enrichment indicators
    
    # IPv4/IPv6 mapping
    if ioc_type in ['ipv4', 'ipv6']:
        # Check for botnet C2 (Feodo Tracker)
        if enrichment_data.get('feodo_listed'):
            return MITRE_MAPPINGS["botnet_c2"]
        
        # Check for abuse reports (AbuseIPDB)
        if enrichment_data.get('abuse_confidence', 0) > 75:
            return MITRE_MAPPINGS["c2_ip"]
        
        # Check for general malicious traffic
        if enrichment_data.get('vt_positives', 0) > 0:
            return MITRE_MAPPINGS["c2_ip"]
        
        return MITRE_MAPPINGS["c2_ip"]
    
    # Domain mapping
    elif ioc_type == 'domain':
        # Check for phishing
        tags = enrichment_data.get('tags', [])
        if 'phishing' in tags or enrichment_data.get('urlhaus_listed') and any('phishing' in str(t).lower() for t in tags):
            return MITRE_MAPPINGS["phishing_domain"]
        
        # Check for malware distribution
        if enrichment_data.get('urlhaus_listed'):
            return MITRE_MAPPINGS["malware_distribution"]
        
        # Check for general malicious domain
        if enrichment_data.get('vt_positives', 0) > 0:
            return MITRE_MAPPINGS["phishing_domain"]
        
        return MITRE_MAPPINGS["phishing_domain"]
    
    # URL mapping
    elif ioc_type == 'url':
        # Check for exploit kit
        tags = enrichment_data.get('tags', [])
        if 'exploit' in str(tags).lower():
            return MITRE_MAPPINGS["exploit_kit"]
        
        # Check for malware distribution
        if enrichment_data.get('urlhaus_listed'):
            return MITRE_MAPPINGS["malware_distribution"]
        
        # Check for phishing URL
        if enrichment_data.get('vt_positives', 0) > 0:
            return MITRE_MAPPINGS["phishing_domain"]
        
        return MITRE_MAPPINGS["malware_distribution"]
    
    # Hash mapping (file-based)
    elif ioc_type in ['md5', 'sha1', 'sha256', 'sha512']:
        # Check for detection (malware)
        if enrichment_data.get('vt_positives', 0) >= 5:
            return MITRE_MAPPINGS["malware_hash"]
        
        # Check for URLhaus (indicates malicious file)
        if enrichment_data.get('urlhaus_listed'):
            return MITRE_MAPPINGS["malware_distribution"]
        
        return MITRE_MAPPINGS["malware_hash"]
    
    # Unknown type
    return default_mapping


def get_mitre_matrix() -> List[Dict[str, str]]:
    """
    Return the complete MITRE technique mapping matrix
    
    Returns:
        List of all MITRE technique mappings
    """
    return list(MITRE_MAPPINGS.values())


def get_tactics_for_ioc_type(ioc_type: str) -> List[str]:
    """
    Get applicable MITRE tactics for a given IOC type
    
    Args:
        ioc_type: Type of IOC
        
    Returns:
        List of applicable tactics
    """
    mapping = map_to_mitre(ioc_type, {})
    tactics = set()
    
    for technique in MITRE_MAPPINGS.values():
        tactics.add(technique['tactic'])
    
    return sorted(list(tactics))
