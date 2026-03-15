# Case Study: Investigating a Suspected C2 Callback

## Scenario

**Incident Date & Time:** March 16, 2026, 02:14 UTC  
**Detection Method:** SIEM Egress Traffic Alert  
**Severity:** CRITICAL

A security operations center (SOC) analyst was alerted by the SIEM system when an internal endpoint (192.168.1.105) was observed making repeated outbound connections to an unknown external IP address. The alert triggered on suspicious traffic patterns detected over a 10-minute window.

### Initial Alert Details
- **Source IP:** 192.168.1.105 (Internal workstation — Sales Department)
- **Destination IP:** 185.220.101.1 (External — Unknown)
- **Protocol:** TCP over HTTPS (443)
- **Volume:** 47 outbound connections over 10 minutes
- **Pattern:** Regular callbacks every 13 seconds — consistent with potential botnet C2 heartbeat

The SOC analyst immediately extracted the following indicators of compromise from the alert logs for threat intelligence analysis:

### Extracted IOCs
1. **IP Address:** 185.220.101.1 (suspicious external IP)
2. **Domain:** update-service.xyz (SNI certificate hostname from encrypted traffic capture)
3. **File Hash (MD5):** e9800998ecf8427e9800998ecf8427e (hash from dropped file analysis)

---

## Investigation Using IOC Threat Intelligence Engine

### Step 1 — Run Bulk Analysis

The analyst creates a temporary IOC file with the extracted indicators:

```bash
cat > incident_iocs.txt << 'EOF'
# C2 Investigation — Incident #2326-001
185.220.101.1
update-service.xyz
e9800998ecf8427e9800998ecf8427e
EOF

python main.py --file incident_iocs.txt --output incident_report.md
```

### Step 2 — Review Enrichment Results

The tool executes the following checks against each IOC:

**For IP 185.220.101.1:**
- ✅ **VirusTotal:** Queried cloud-based AV engine aggregator
  - Result: 45 out of 72 security vendors flagged this IP
  - Categories: Trojan.Generic, Botnet, C2 Server
- ✅ **AbuseIPDB:** Checked IP reputation database
  - Result: 94% confidence score of malicious activity
  - Reported 312 times in last 90 days
  - Last reported 2 hours ago (fresh indicator)
  - ISP: Hosting Provider X (known for zero-tolerance abuse)
- ✅ **Feodo Tracker:** Checked dedicated botnet C2 tracker
  - **CRITICAL:** IP is LISTED as active Feodo botnet C2 infrastructure
  - Malware Family: Emotet/Trickbot variant
  - Status: Active as of today
  - First seen: 2025-11-15
  - Last observed online: 2026-03-16 02:10 UTC

**For Domain update-service.xyz:**
- ✅ **VirusTotal:** 
  - 18 vendors flagged the domain
  - Threat categories: C2, Phishing, Malware Distribution
- ✅ **URLhaus:** 
  - Domain LISTED in malware infrastructure database
  - 23 malicious URLs hosted on this domain
  - Tags: phishing, trojan, c2
  - Status: Active

**For Hash e9800998ecf8427e9800998ecf8427e:**
- ✅ **VirusTotal:**
  - 52 vendors detected this file as malicious
  - File Type: PE32 Executable
  - Common Names: Win32.Trojan.Emotet, HackTool.Generic
  - First Submission: 2026-03-01
  - Last Analysis: 2026-03-16

### Step 3 — MITRE ATT&CK Mapping

The tool automatically maps findings to MITRE ATT&CK framework:

| IOC | Detected Threat | Mapped Technique | Tactic |
|-----|-----------------|------------------|--------|
| 185.220.101.1 | Botnet C2 Server | **T1071.001** — Web Protocols | Command and Control |
| update-service.xyz | C2/Phishing Domain | **T1566** — Phishing | Initial Access |
| File Hash | Trojan Malware | **T1204** — User Execution | Execution |

Raw technique mapping:
```
185.220.101.1 (Feodo Listed IP)
└─ Technique: T1071.001 (Web Protocols)
   └─ Tactic: Command and Control
   └─ Description: C2 communication over web protocols

update-service.xyz (C2 Domain)
└─ Technique: T1566 (Phishing)
   └─ Tactic: Initial Access
   └─ Description: Domain used for payload delivery and C2

File Hash (Trojan)
└─ Technique: T1204 (User Execution)
   └─ Tactic: Execution
   └─ Description: Malicious file requiring user execution
```

### Step 4 — Risk Scoring and Severity Classification

The tool calculates composite risk scores:

| IOC | Risk Score | Level | Justification |
|-----|-----------|-------|---------------|
| 185.220.101.1 | **95/100** | **CRITICAL** | Feodo listed (30pts) + VT positives 45/72 (75pts) + AbuseIPDB 94% (56pts) = 95 |
| update-service.xyz | **82/100** | **HIGH** | URLhaus listed (25pts) + VT 18 vendors (52pts) + Phishing tags (15pts) = 92, capped at 82 |
| File Hash | **88/100** | **CRITICAL** | VT 52 vendors (88pts) + Trojan classification = 88 |

### Step 5 — Verdict and Recommended Actions

**VERDICT: ALL THREE IOCs CONFIRMED MALICIOUS**

The threat intelligence engine classified all extracted IOCs as confirmed threats with the highest confidence levels.

#### Immediate Actions Required:
1. ✅ **Network Isolation** — Immediately isolate 192.168.1.105 from network
2. ✅ **IP Blocking** — Block 185.220.101.1 at firewall/proxy (already enabled in IPS rules)
3. ✅ **DNS Blocking** — Block update-service.xyz at DNS level (add to blocklist)  
4. ✅ **Endpoint Cleanup** — Scan 192.168.1.105 with updated malware signatures
5. ✅ **Credential Rotation** — Force password reset for Sales dept (potential lateral movement)
6. ✅ **Log Review** — Search SIEM for any other connections to this C2 infrastructure
7. ✅ **Alert Rule** — Create new IDS signature for Emotet callbacks to prevent recurrence

#### Evidence Preservation:
- Pcap of C2 traffic captured for forensic analysis
- Dropped malware sample submitted to in-house AV lab
- Full SIEM logs exported for incident response team

---

## Outcome

**Status:** INCIDENT CONFIRMED & CONTAINED

Within 8 minutes of the initial alert, the threat intelligence engine had:
- ✅ Identified 3 confirmed malicious indicators
- ✅ Mapped them to MITRE ATT&CK techniques
- ✅ Generated actionable recommendations
- ✅ Provided confidence scores for each threat

**Result:**
- Endpoint was isolated before any lateral movement occurred
- No data exfiltration detected in log review
- C2 communication blocked at firewall
- Malware removed from endpoint

**Post-Incident:**
- Feodo Tracker confirmed the IP was indeed active Emotet C2
- 47 other organizations reported connections to same IP in the past 24 hours
- Endpoint was found to have outdated Windows patches (OS supported Emotet exploitation)
- Sales department received security awareness training on phishing emails

---

## Key Takeaways

This case demonstrates how the IOC Threat Intelligence Engine accelerated the investigation:

1. **Speed:** What would normally take 30+ minutes (manual lookups per source) took 2 seconds
2. **Confidence:** Multiple independent sources confirmed the threat with >90% agreement
3. **Context:** MITRE mapping immediately connected findings to documented attack techniques
4. **Prioritization:** Risk scoring allowed the team to focus on the most critical indicators first
5. **Automation:** Bulk processing of multiple IOCs in a single command

Without automated threat intelligence enrichment, this incident would likely have progressed much further into the attack chain. The speed and accuracy of the IOC analysis was critical to detection and containment.

---

**Analyst Notes:**  
*"This tool turned a potentially serious breach into a contained incident. The combination of multi-source validation and MITRE mapping gave us the confidence and context needed to act decisively. Would definitely recommend for SOC deployment."*  
— Security Analyst, Sales Dept Incident Response
