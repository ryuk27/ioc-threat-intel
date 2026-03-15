# IOC Threat Intelligence Engine

Automated threat intelligence enrichment tool for security teams and SOC analysts.

Analyzes IPs, domains, URLs, and file hashes against **5 independent threat intelligence sources** and maps findings to **MITRE ATT&CK techniques** for contextualized threat assessment.

```
Input: Single IOC or file of IOCs
  ↓
Detection: Automatic type identification (IPv4, IPv6, domain, URL, hash)
  ↓
Enrichment: Query 5 threat feeds simultaneously
  ├─ VirusTotal (AV engine aggregator)
  ├─ AbuseIPDB (IP reputation)
  ├─ AlienVault OTX (threat pulses)
  ├─ Feodo Tracker (botnet C2 tracker)
  └─ URLhaus (malware URL database)
  ↓
Scoring: Composite risk score (0-100)
  ↓
Mapping: MITRE ATT&CK technique & tactic
  ↓
Report: Markdown or JSON output
```

---

## Features

**Multi-IOC Support**  
Analyze IPv4, IPv6, domains, URLs, and file hashes (MD5, SHA1, SHA256, SHA512)

**5 Independent Threat Sources**  
- VirusTotal (multi-engine AV scan results)
- AbuseIPDB (IP reputation & abuse reporting database)
- AlienVault OTX (threat pulses & crowdsourced intel)
- Feodo Tracker (real-time botnet C2 blocklist)
- URLhaus (malware URL database)

**Automatic IOC Type Detection**  
Intelligent validation and type classification with zero user configuration

**Composite Risk Scoring**  
Weighted scoring algorithm combining signals from all sources (0-100 scale with 5 severity levels)

**MITRE ATT&CK Mapping**  
Automatic technique & tactic mapping for all detections — connect findings to known attack patterns

**Bulk Processing**  
Process 10, 100, or 1000 IOCs with a single command

**Professional Reporting**  
Clean markdown reports with summary statistics, risk breakdown, and actionable recommendations

**Production-Grade**  
Rate limiting, error handling, and graceful degradation if individual sources fail

---

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

```bash
# Clone or download repository
cd ioc-threat-intel

# Install dependencies
pip install -r requirements.txt

# Copy .env.example to .env and add API keys
cp .env.example .env

# Edit .env with your credentials
# Required keys: VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
# Optional: SHODAN_API_KEY
```

### API Keys Required

| Service | Key | Free Tier | Sign Up |
|---------|-----|-----------|---------|
| VirusTotal | `VT_API_KEY` | Yes (limits apply) | https://www.virustotal.com |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Yes (limits apply) | https://www.abuseipdb.com |
| AlienVault OTX | `OTX_API_KEY` | Yes | https://otx.alienvault.com |
| Shodan | `SHODAN_API_KEY` | No (paid only) | https://www.shodan.io |
| **Feodo Tracker** | Not required | Yes (no auth) | https://feodotracker.abuse.ch |
| **URLhaus** | Not required | Yes (no auth) | https://urlhaus.abuse.ch |

---

## Usage

### Single IOC Analysis

```bash
python main.py --ioc 8.8.8.8

# Output:
# Type: ipv4
# Risk Score: 10/100 — CLEAN
# VirusTotal: 0 malicious, 0 suspicious
# AbuseIPDB: Confidence 0%, 0 reports
# Feodo Tracker: Not listed
# MITRE: T1071 — Application Layer Protocol (Command and Control)
# Verdict: [+] CLEAN — No immediate action recommended
```

### Bulk File Processing

```bash
# Process multiple IOCs from file
python main.py --file iocs.txt --output report.md

# Input file format (one per line):
# 8.8.8.8
# malware.example.com
# d41d8cd98f00b204e9800998ecf8427e
# https://evil-site.net/malware
```

### Suppress Console Output

```bash
python main.py --file iocs.txt --output report.md --quiet
```

---

## Example Output

### Console Output
```
[1] IOC: 185.220.101.1
    Type: IPv4 Address
    Risk Score: 95/100 — CRITICAL
    
    Threat Intelligence:
      [+] VirusTotal: 45 malicious, 3 suspicious
      [+] AbuseIPDB: Confidence 94%, 312 reports
      [!] Feodo Tracker: LISTED — Known Botnet C2 (Emotet)
    
    MITRE ATT&CK:
      Technique: T1071.001 — Web Protocols
      Tactic: Command and Control
    
    Verdict: [!] MALICIOUS — Recommend immediate block
```

### Markdown Report
```markdown
# IOC Threat Intelligence Report
Generated: 2026-03-16 14:32:11 UTC

## [1] IOC: 185.220.101.1

Type: ipv4
Risk Score: 95/100 — CRITICAL

### Threat Intelligence

**VirusTotal:**
- Malicious: 45/72
- Suspicious: 3/72
- Categories: Trojan.Generic, Botnet, C2

**AbuseIPDB:**
- Confidence Score: 94%
- Total Reports: 312
- ISP: Hosting Provider X

**Feodo Tracker:**
- [!] LISTED — Known Botnet C2
- Malware: Emotet/Trickbot variant
- Status: Active

---

# Summary
Total IOCs Analyzed: 3
Critical: 1 | High: 1 | Medium: 0 | Low: 0 | Clean: 1

## Recommendations
[!] IMMEDIATE ACTION REQUIRED
- Block detected malicious IOCs at perimeter
- Alert security team for incident response
- Isolate affected endpoints
```

---

## Project Structure

```
ioc-threat-intel/
├── main.py                          # Entry point
├── ioc_intel/
│   ├── __init__.py
│   ├── validator.py                 # IOC type detection & validation
│   ├── enricher.py                  # API integration (all 5 sources)
│   ├── scorer.py                    # Risk scoring algorithm
│   ├── mitre_mapper.py              # MITRE ATT&CK mapping
│   └── reporter.py                  # Report generation & formatting
├── tests/
│   ├── test_validator.py            # IOC detection tests
│   ├── test_scorer.py               # Risk scoring tests
│   └── test_mitre_mapper.py         # MITRE mapping tests
├── samples/
│   ├── sample_iocs.txt              # Example IOC file
│   └── sample_report.md             # Example report output
├── docs/
│   └── case-study.md                # Real-world investigation scenario
├── .env.example                     # Template for API keys
├── .gitignore
├── requirements.txt
└── README.md
```

---

## How Scoring Works

Risk scores are calculated from multiple weighted signals:

| Signal | Weight | Max Points |
|--------|--------|------------|
| VirusTotal malicious detections (≥5) | 80 | 80 |
| VirusTotal suspicious detections | 2 | 20 |
| AbuseIPDB confidence score | 0.8 | 80 |
| AbuseIPDB total reports | 0.5 | 20 |
| Feodo Tracker listed | +30 | 30 |
| URLhaus listed | +25 | 25 |
| OTX pulse count | 5 | 30 |
| Shodan vulnerabilities | 10 | 25 |
| | | **Max: 100** |

### Severity Levels

| Level | Score | Action |
|-------|-------|--------|
| 🔴 **CRITICAL** | 80-100 | Block immediately, investigate |
| 🟠 **HIGH** | 60-79 | Escalate, block if possible |
| 🟡 **MEDIUM** | 40-59 | Monitor, investigate |
| 🔵 **LOW** | 15-39 | Log, monitor |
| ✅ **CLEAN** | 0-14 | Approved for use |

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name | Tactic |
|---|---|---|
| T1071 | Application Layer Protocol | Command and Control |
| T1071.001 | Web Protocols | Command and Control |
| T1566 | Phishing | Initial Access |
| T1204 | User Execution | Execution |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1020 | Automated Exfiltration | Exfiltration |
| T1189 | Drive-by Compromise | Initial Access |

---

## Testing

Run unit tests to verify functionality:

```bash
# Install pytest (if not already installed)
pip install pytest

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_validator.py -v

# Run with coverage
pytest tests/ --cov=ioc_intel
```

**Current Status:** ✅ 47 tests passing

---

## Case Study

See [docs/case-study.md](docs/case-study.md) for a real-world incident investigation scenario showing the tool in action.

### Scenario Highlights
- C2 callback detection
- Multi-source threat validation
- MITRE technique mapping
- Incident containment in 8 minutes

---

## Performance

- **Single IOC Analysis:** ~2-3 seconds (API dependent)
- **Bulk Processing (10 IOCs):** ~15-30 seconds (rate-limited)
- **Report Generation:** <1 second
- **Zero External Dependencies:** All threat feed queries use public/commercial APIs only

---

## Error Handling

The tool gracefully handles:
- Missing API keys → Skips source, continues with others
- Network timeouts → Partial results with available data
- Invalid IOCs → Marks as unknown, processes remaining
- Rate limits → Automatic retry with backoff
- File not found → Clear error message, exit

---

## Security Notes

[!] **Important**
- Never commit `.env` file with real API keys to version control
- `.env` is added to `.gitignore` by default
- Use `.env.example` template with placeholder values for reference
- Rotate API keys periodically
- Consider using short-lived tokens if your threat feed provider supports it

---

## Author

Built by **Ryuk27** — Threat Intelligence Security Engineer

**Find me on:**
- [GitHub](https://github.com/ryuk27)
- [LinkedIn](https://www.linkedin.com/in/ram0912/)

---

## Roadmap

Planned enhancements:
- Additional threat feed integrations (URLScan, Censys, AbuseIPDB API v2)
- Custom risk scoring rules and thresholds
- Slack/Teams integration for automated alerts
- Historical tracking and trend analysis
- Bulk API optimization for enterprise scale

---

## License

This tool is provided as-is for education and security research purposes.

---

## Resources

- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **VirusTotal API:** https://developers.virustotal.com/
- **AbuseIPDB API:** https://docs.abuseipdb.com/
- **AlienVault OTX:** https://otx.alienvault.com/
- **Feodo Tracker:** https://feodotracker.abuse.ch/
- **URLhaus:** https://urlhaus.abuse.ch/

---

**Last Updated:** March 2026  
**Status:** Active Development
