# MITRE ATT&CK Mapping Expansion
**File:** `ioc_intel/mitre_mapper.py`  
**Goal:** Replace static 7-technique dictionary with dynamic tag-based mapping  
**Result:** Contextual, intelligent technique selection based on actual threat data

---

## Current Problem

The existing mapper uses a flat dictionary — every malicious IP maps to T1071 regardless of what the threat feeds actually say about it. A Tor exit node, a ransomware C2, and a phishing server all get the same technique. That is not how MITRE mapping works in a real SOC.

---

## Step 1 — Expand the Technique Dictionary

Replace your existing `MITRE_MAPPINGS` dict in `mitre_mapper.py` with this expanded version:

```python
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
```

---

## Step 2 — Build the Tag Normalizer

Different sources use different tag formats. URLhaus uses `phishing`, OTX might use `Phishing-URL`, VirusTotal categories say `Trojan.Generic`. This function normalizes all of them into your internal keys:

```python
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
    """
    normalized = tag.lower().strip().replace(" ", "-").replace("_", "-")
    return TAG_TO_MITRE_KEY.get(normalized, "unknown")
```

---

## Step 3 — Rewrite the map_to_mitre Function

Replace your existing `map_to_mitre()` with this dynamic version:

```python
def map_to_mitre(ioc_type: str, enrichment_results: dict) -> dict:
    """
    Dynamically map IOC findings to MITRE ATT&CK techniques.
    
    Uses tags from URLhaus, OTX, and VirusTotal categories to select
    the most relevant technique rather than a static IOC-type lookup.
    
    Args:
        ioc_type: Detected IOC type (ipv4, domain, md5, sha256, url)
        enrichment_results: Combined results from all threat feeds
    
    Returns:
        Dict with technique_id, technique_name, tactic, description,
        and all_techniques list for multi-technique IOCs
    """
    collected_tags = []

    # Extract tags from URLhaus
    urlhaus = enrichment_results.get("urlhaus", {})
    if urlhaus.get("listed"):
        urlhaus_tags = urlhaus.get("tags", [])
        collected_tags.extend([t.lower() for t in urlhaus_tags])

    # Extract tags from OTX pulses
    otx = enrichment_results.get("otx", {})
    otx_tags = otx.get("tags", [])
    collected_tags.extend([t.lower() for t in otx_tags])

    # Extract categories from VirusTotal
    vt = enrichment_results.get("virustotal", {})
    vt_categories = vt.get("categories", [])
    collected_tags.extend([c.lower() for c in vt_categories])

    # Extract Feodo Tracker malware family
    feodo = enrichment_results.get("feodo", {})
    if feodo.get("listed"):
        malware_family = feodo.get("malware", "").lower()
        if malware_family:
            collected_tags.append(malware_family)
        collected_tags.append("botnet")
        collected_tags.append("c2")

    # Normalize all collected tags to internal MITRE keys
    mitre_keys = []
    for tag in collected_tags:
        key = normalize_tag(tag)
        if key != "unknown" and key not in mitre_keys:
            mitre_keys.append(key)

    # If no tags found, fall back to IOC type defaults
    if not mitre_keys:
        mitre_keys = get_default_keys_for_ioc_type(ioc_type, enrichment_results)

    # Build primary technique (first/most specific match)
    primary_key = mitre_keys[0] if mitre_keys else "unknown"
    primary_technique = MITRE_MAPPINGS.get(primary_key, MITRE_MAPPINGS["unknown"]).copy()

    # Build additional techniques list (deduplicated)
    all_techniques = []
    seen_ids = set()
    for key in mitre_keys:
        technique = MITRE_MAPPINGS.get(key, MITRE_MAPPINGS["unknown"])
        if technique["technique_id"] not in seen_ids:
            all_techniques.append(technique)
            seen_ids.add(technique["technique_id"])

    primary_technique["all_techniques"] = all_techniques
    primary_technique["confidence"] = "high" if collected_tags else "low"
    primary_technique["source_tags"] = collected_tags[:10]  # cap at 10 for readability

    return primary_technique


def get_default_keys_for_ioc_type(ioc_type: str, enrichment_results: dict) -> list:
    """
    Fallback mapping when no tags are available from threat feeds.
    Uses IOC type and basic enrichment signals.
    """
    vt_positives = enrichment_results.get("virustotal", {}).get("malicious", 0)
    abuse_confidence = enrichment_results.get("abuseipdb", {}).get("confidence", 0)

    if ioc_type in ("ipv4", "ipv6"):
        if abuse_confidence > 80 or vt_positives > 10:
            return ["c2_web", "infrastructure"]
        return ["infrastructure"]

    elif ioc_type == "domain":
        return ["phishing", "malware_distribution"]

    elif ioc_type == "url":
        return ["phishing_link", "malware_distribution"]

    elif ioc_type in ("md5", "sha1", "sha256", "sha512"):
        if vt_positives > 30:
            return ["malware_execution", "malware_distribution"]
        return ["malware_execution"]

    return ["unknown"]
```

---

## Step 4 — Update the Reporter

In `ioc_intel/reporter.py`, update the MITRE section to show multiple techniques when present:

```python
def format_mitre_section(mitre_result: dict) -> str:
    """Format MITRE ATT&CK mapping for report output."""
    
    lines = []
    lines.append("**MITRE ATT&CK:**")
    lines.append(f"- Primary Technique: {mitre_result['technique_id']} — {mitre_result['technique_name']}")
    lines.append(f"- Tactic: {mitre_result['tactic']}")
    lines.append(f"- Confidence: {mitre_result.get('confidence', 'low').upper()}")

    # Show additional techniques if more than one identified
    all_techniques = mitre_result.get("all_techniques", [])
    if len(all_techniques) > 1:
        lines.append("- Additional Techniques:")
        for technique in all_techniques[1:]:  # skip primary, already shown
            lines.append(f"  - {technique['technique_id']} — {technique['technique_name']} ({technique['tactic']})")

    # Show source tags that drove the mapping
    source_tags = mitre_result.get("source_tags", [])
    if source_tags:
        lines.append(f"- Mapped From Tags: {', '.join(source_tags[:5])}")

    return "\n".join(lines)
```

---

## Step 5 — Update the README MITRE Coverage Table

Replace the existing 7-row table with this expanded version:

```markdown
## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic | Trigger |
|---|---|---|---|
| T1071 | Application Layer Protocol | Command and Control | Malicious IP, C2 tags |
| T1071.001 | Web Protocols | Command and Control | HTTP/HTTPS C2 tags |
| T1071.004 | DNS | Command and Control | DNS tunneling tags |
| T1090 | Proxy | Command and Control | Tor exit node, proxy tags |
| T1105 | Ingress Tool Transfer | Command and Control | Malware distribution URLs |
| T1189 | Drive-by Compromise | Initial Access | Drive-by tags |
| T1190 | Exploit Public-Facing Application | Initial Access | Exploit tags |
| T1204 | User Execution | Execution | Malicious file hashes |
| T1059 | Command and Scripting Interpreter | Execution | Script tags |
| T1027 | Obfuscated Files or Information | Defense Evasion | Obfuscation tags |
| T1027.002 | Software Packing | Defense Evasion | Packer detection |
| T1219 | Remote Access Software | Command and Control | RAT tags |
| T1543 | Create or Modify System Process | Persistence | Backdoor tags |
| T1486 | Data Encrypted for Impact | Impact | Ransomware tags |
| T1498 | Network Denial of Service | Impact | DDoS tags |
| T1485 | Data Destruction | Impact | Wiper tags |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Exfil tags |
| T1020 | Automated Exfiltration | Exfiltration | Auto-exfil tags |
| T1555 | Credentials from Password Stores | Credential Access | Stealer tags |
| T1056.001 | Keylogging | Credential Access | Keylogger tags |
| T1566 | Phishing | Initial Access | Phishing domain/URL tags |
| T1566.002 | Spearphishing Link | Initial Access | Phishing link tags |
| T1583 | Acquire Infrastructure | Resource Development | Attack infrastructure |
| T1583.004 | Server — Botnet | Resource Development | Botnet tags |
```

---

## What Changes After This

**Before:** Every malicious IP → T1071. Every domain → T1566. Static, dumb.

**After:** 
- A Tor exit node flagged by Feodo → T1090 (Proxy) + T1583.004 (Botnet)
- A URLhaus domain tagged `phishing, c2` → T1566 (Phishing) + T1071.001 (Web Protocols)
- An EICAR hash → T1204 (User Execution)
- A ransomware hash tagged `ransomware, lockbit` → T1486 (Data Encrypted for Impact)

The mapping now reflects what the threat feeds actually say about the IOC.

---

## Updated Project Rating After This Change

| Area | Before | After |
|------|--------|-------|
| Technical Depth | 7.5/10 | 8/10 |
| SOC Relevance | 9/10 | 9/10 |
| Code Quality | 8/10 | 8.5/10 |
| Presentation | 8.5/10 | 9/10 |
| **Overall** | **8.5/10** | **9/10** |

The README MITRE table going from 7 rows to 24 rows with a Trigger column is alone worth the README bump. The dynamic mapping logic is what pushes code quality up — it shows you understand that threat intelligence is data-driven, not hardcoded.

---

*Implement Steps 1-3 first — they are the core logic.*  
*Step 4 is a reporter cosmetic update — do it after 1-3 are working.*  
*Step 5 is README only — do it last on March 29-30 polish day.*
