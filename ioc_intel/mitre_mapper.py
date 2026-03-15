"""MITRE ATT&CK Mapping Module"""

from typing import Dict, Any, List


MITRE_MAPPINGS = {

    # Command and Control
    "c2": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversary communicating with C2 over standard application layer protocols"
    },
    "c2_web": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "C2 communication over HTTP/HTTPS"
    },
    "c2_dns": {
        "technique_id": "T1071.004",
        "technique_name": "DNS",
        "tactic": "Command and Control",
        "description": "C2 communication tunnelled over DNS"
    },
    "proxy": {
        "technique_id": "T1090",
        "technique_name": "Proxy",
        "tactic": "Command and Control",
        "description": "Adversary using proxy infrastructure (Tor exit nodes, anonymization services)"
    },
    "botnet": {
        "technique_id": "T1583.004",
        "technique_name": "Server — Botnet",
        "tactic": "Resource Development",
        "description": "Adversary operating botnet infrastructure for coordinated attacks"
    },

    # Initial Access
    "phishing": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "description": "Domain or URL used in phishing campaign"
    },
    "phishing_link": {
        "technique_id": "T1566.002",
        "technique_name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Malicious URL delivered via phishing email"
    },
    "driveby": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Malicious website or URL used for drive-by compromise"
    },
    "exploit": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploitation of vulnerability in public-facing application"
    },

    # Execution
    "malware_execution": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
        "description": "Malicious file requiring user execution"
    },
    "script": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Malicious script execution"
    },

    # Defense Evasion
    "obfuscated": {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Malware using obfuscation to evade detection"
    },
    "packer": {
        "technique_id": "T1027.002",
        "technique_name": "Software Packing",
        "tactic": "Defense Evasion",
        "description": "Malware using packer to hide malicious code"
    },

    # Persistence
    "backdoor": {
        "technique_id": "T1543",
        "technique_name": "Create or Modify System Process",
        "tactic": "Persistence",
        "description": "Backdoor establishing persistent access"
    },
    "rat": {
        "technique_id": "T1219",
        "technique_name": "Remote Access Software",
        "tactic": "Command and Control",
        "description": "Remote access trojan providing persistent remote control"
    },

    # Credential Access
    "stealer": {
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "description": "Malware targeting stored credentials"
    },
    "keylogger": {
        "technique_id": "T1056.001",
        "technique_name": "Keylogging",
        "tactic": "Credential Access",
        "description": "Malware capturing keystrokes for credential theft"
    },

    # Collection and Exfiltration
    "exfil": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Data exfiltration using established C2 channel"
    },
    "exfil_auto": {
        "technique_id": "T1020",
        "technique_name": "Automated Exfiltration",
        "tactic": "Exfiltration",
        "description": "Automated collection and exfiltration of data"
    },

    # Impact
    "ransomware": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Ransomware encrypting data for extortion"
    },
    "ddos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "DDoS attack infrastructure"
    },
    "wiper": {
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "tactic": "Impact",
        "description": "Malware designed to destroy data"
    },

    # Resource Development
    "infrastructure": {
        "technique_id": "T1583",
        "technique_name": "Acquire Infrastructure",
        "tactic": "Resource Development",
        "description": "Adversary-controlled attack infrastructure"
    },
    "malware_distribution": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "URL or server used to deliver malware payloads"
    },

    # Default fallback
    "unknown": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Malicious indicator — specific technique undetermined"
    }
}


# Tag normalization map — maps external tags to internal MITRE keys
TAG_TO_MITRE_KEY = {
    # C2 / Botnet tags
    "c2": "c2_web",
    "c&c": "c2_web",
    "command-and-control": "c2_web",
    "command_and_control": "c2_web",
    "botnet": "botnet",
    "bot": "botnet",
    "emotet": "botnet",
    "trickbot": "botnet",
    "mirai": "botnet",
    "lokibot": "botnet",
    "qakbot": "botnet",
    "tor": "proxy",
    "tor-exit": "proxy",
    "proxy": "proxy",
    "vpn": "proxy",

    # Phishing tags
    "phishing": "phishing",
    "phish": "phishing",
    "phishing-url": "phishing_link",
    "spearphishing": "phishing_link",
    "credential-phishing": "phishing",
    "fake-login": "phishing",

    # Malware distribution
    "malware": "malware_execution",
    "malware-distribution": "malware_distribution",
    "malware_distribution": "malware_distribution",
    "dropper": "malware_distribution",
    "downloader": "malware_distribution",
    "payload": "malware_distribution",

    # Specific malware types
    "trojan": "malware_execution",
    "trojan.generic": "malware_execution",
    "rat": "rat",
    "remote-access-trojan": "rat",
    "backdoor": "backdoor",
    "keylogger": "keylogger",
    "stealer": "stealer",
    "infostealer": "stealer",
    "credential-stealer": "stealer",
    "spyware": "stealer",

    # Ransomware
    "ransomware": "ransomware",
    "ransom": "ransomware",
    "cryptolocker": "ransomware",
    "lockbit": "ransomware",
    "conti": "ransomware",

    # Exploitation
    "exploit": "exploit",
    "exploit-kit": "exploit",
    "drive-by": "driveby",
    "driveby": "driveby",

    # Exfiltration
    "exfiltration": "exfil",
    "exfil": "exfil",
    "data-theft": "exfil",

    # DDoS
    "ddos": "ddos",
    "dos": "ddos",

    # Infrastructure
    "scanner": "infrastructure",
    "scanning": "infrastructure",
    "brute-force": "infrastructure",
    "bruteforce": "infrastructure",
    "attack": "infrastructure",
    "malicious": "infrastructure",
}


def normalize_tag(tag: str) -> str:
    """
    Normalize a raw tag from any threat feed into an internal MITRE key.
    Returns 'unknown' if no match found.
    
    Args:
        tag: Raw tag from threat feed (any case, spacing)
        
    Returns:
        str: Internal MITRE key or 'unknown'
    """
    normalized = tag.lower().strip().replace(" ", "-").replace("_", "-")
    return TAG_TO_MITRE_KEY.get(normalized, "unknown")


def collect_tags_from_enrichment(enrichment_data: Dict[str, Any]) -> List[str]:
    """
    Collect all tags from various threat intelligence sources.
    
    Args:
        enrichment_data: Enrichment results from multiple sources
        
    Returns:
        List of normalized tags
    """
    all_tags = []
    
    # URLhaus tags
    if enrichment_data.get('urlhaus_tags'):
        urlhaus_tags = enrichment_data.get('urlhaus_tags', [])
        if isinstance(urlhaus_tags, list):
            all_tags.extend(urlhaus_tags)
        else:
            all_tags.append(urlhaus_tags)
    
    # OTX tags
    if enrichment_data.get('otx_tags'):
        otx_tags = enrichment_data.get('otx_tags', [])
        if isinstance(otx_tags, list):
            all_tags.extend(otx_tags)
        else:
            all_tags.append(otx_tags)
    
    # VirusTotal categories
    if enrichment_data.get('vt_categories'):
        vt_cats = enrichment_data.get('vt_categories', [])
        if isinstance(vt_cats, list):
            all_tags.extend(vt_cats)
        elif isinstance(vt_cats, dict):
            all_tags.extend(vt_cats.values())
    
    # Feodo malware family
    if enrichment_data.get('feodo_malware'):
        all_tags.append(enrichment_data.get('feodo_malware'))
    
    return [t for t in all_tags if t]


def get_default_keys_for_ioc_type(ioc_type: str) -> List[str]:
    """
    Get default MITRE key fallbacks when no tags are available.
    Provides sensible defaults based on IOC type for data-driven mapping.
    
    Args:
        ioc_type: Type of IOC
        
    Returns:
        List of MITRE keys to check
    """
    defaults = {
        'ipv4': ['c2_web', 'proxy', 'c2_dns'],
        'ipv6': ['c2_web', 'proxy', 'c2_dns'],
        'domain': ['phishing', 'malware_distribution', 'c2_web'],
        'url': ['malware_distribution', 'phishing_link', 'driveby'],
        'md5': ['malware_execution', 'malware_distribution'],
        'sha1': ['malware_execution', 'malware_distribution'],
        'sha256': ['malware_execution', 'malware_distribution'],
        'sha512': ['malware_execution', 'malware_distribution'],
        'email': ['phishing'],
        'asn': ['infrastructure', 'c2_web']
    }
    
    return defaults.get(ioc_type, ['infrastructure'])


def map_to_mitre(ioc_type: str, enrichment_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Data-driven mapping of IOC findings to MITRE ATT&CK techniques.
    
    Collects tags from multiple threat sources (URLhaus, OTX, VirusTotal, Feodo),
    normalizes them, and maps to applicable MITRE techniques with confidence scores.
    Falls back to IOC type defaults if no tags available.
    
    Args:
        ioc_type: Type of IOC ('ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', etc.)
        enrichment_data: Enrichment results from threat intelligence sources
        
    Returns:
        Dict: Primary MITRE technique with:
            - technique_id, technique_name, tactic, description
            - additional_techniques: List of secondary techniques
            - source_tags: Tags that drove the mapping
            - confidence_score: 0-100 confidence in the mapping
    """
    
    # Collect tags from all sources
    tags = collect_tags_from_enrichment(enrichment_data)
    
    # Normalize tags and build MITRE key set
    matched_keys = set()
    tag_mapping_log = []
    
    for tag in tags:
        mitre_key = normalize_tag(tag)
        if mitre_key != "unknown":
            matched_keys.add(mitre_key)
            tag_mapping_log.append({
                "source_tag": tag,
                "mitre_key": mitre_key
            })
    
    # If no tags matched, use IOC type defaults as fallback
    if not matched_keys:
        default_keys = get_default_keys_for_ioc_type(ioc_type)
        matched_keys = set(default_keys)
    
    # Select primary technique (first matched key or first default)
    primary_key = (
        list(matched_keys)[0] if matched_keys 
        else get_default_keys_for_ioc_type(ioc_type)[0]
    )
    
    primary_technique = MITRE_MAPPINGS.get(primary_key, MITRE_MAPPINGS["unknown"])
    
    # Build additional techniques (all matched except primary)
    additional_techniques = []
    for key in matched_keys:
        if key != primary_key:
            tech = MITRE_MAPPINGS.get(key)
            if tech:
                additional_techniques.append(tech)
    
    # Calculate confidence score based on number of sources confirming
    confidence_score = min(100, 65 + (len(tag_mapping_log) * 10))
    
    return {
        "technique_id": primary_technique["technique_id"],
        "technique_name": primary_technique["technique_name"],
        "tactic": primary_technique["tactic"],
        "description": primary_technique["description"],
        "additional_techniques": additional_techniques,
        "source_tags": tags,
        "confidence_score": confidence_score
    }


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
