# IOC Threat Intel Engine — Upgrade Task List
**Project:** github.com/ryuk27 — IOC Threat Intel Engine  
**Goal:** Transform from a working script into a portfolio-grade threat intelligence tool  
**Complete all tasks before May 15, 2026**

---

## PHASE 1 — CODE CLEANUP (March 15-16)
*Do these first. Foundation must be solid before adding features.*

### Task 1 — Fix .env and API Key Security
**Why:** Having API keys in app.py is an automatic red flag for any technical reviewer.  
**What to do:**
- Install python-dotenv: `pip install python-dotenv`
- Create a `.env` file in project root with all API keys:
  ```
  VT_API_KEY=your_key_here
  ABUSEIPDB_API_KEY=your_key_here
  OTX_API_KEY=your_key_here
  ```
- Add `from dotenv import load_dotenv` and `load_dotenv()` to app.py
- Replace all hardcoded keys with `os.getenv("KEY_NAME")`
- Add `.env` to `.gitignore` — verify it is NOT being tracked
- Create `.env.example` with placeholder values and commit it
- **Verify:** Run `git status` — `.env` must not appear

---

### Task 2 — Modularize the Codebase
**Why:** A single 300-line app.py signals a beginner. A proper package structure signals a developer.  
**What to do:**
- Create package folder: `ioc_intel/`
- Create `ioc_intel/__init__.py` (can be empty)
- Create `ioc_intel/validator.py` — move all IOC type detection/validation logic here
  - Functions: `is_ip()`, `is_domain()`, `is_hash()`, `is_url()`, `detect_ioc_type()`
- Create `ioc_intel/enricher.py` — move all API call logic here
  - Functions: `enrich_virustotal()`, `enrich_abuseipdb()`, `enrich_otx()`, `enrich_ioc()`
- Create `ioc_intel/scorer.py` — move all risk scoring logic here
  - Functions: `calculate_score()`, `get_risk_level()`
- Create `ioc_intel/mitre_mapper.py` — new file for MITRE mapping (Task 3)
- Create `ioc_intel/reporter.py` — new file for output formatting (Task 5)
- Create `main.py` as the entry point that imports from the package:
  ```python
  from ioc_intel.validator import detect_ioc_type
  from ioc_intel.enricher import enrich_ioc
  from ioc_intel.scorer import calculate_score
  from ioc_intel.mitre_mapper import map_to_mitre
  from ioc_intel.reporter import generate_report
  ```
- Delete or gut the old app.py — main.py replaces it
- **Verify:** `python main.py` works exactly as before

---

## PHASE 2 — CORE FEATURE ADDITIONS (March 19-28)

### Task 3 — Add MITRE ATT&CK Mapping
**Why:** This is the single biggest differentiator. Most student tools don't do this. It directly maps to your internship work and makes the tool feel professional.  
**What to do:**
- Create `ioc_intel/mitre_mapper.py`
- Build a mapping dictionary that maps IOC findings to MITRE techniques:
  ```python
  MITRE_MAPPINGS = {
      "malicious_ip": {
          "technique_id": "T1071",
          "technique_name": "Application Layer Protocol",
          "tactic": "Command and Control",
          "description": "Adversary using IP for C2 communication"
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
      "c2_indicator": {
          "technique_id": "T1071.001",
          "technique_name": "Web Protocols",
          "tactic": "Command and Control",
          "description": "C2 communication over web protocols"
      },
      "data_exfil": {
          "technique_id": "T1041",
          "technique_name": "Exfiltration Over C2 Channel",
          "tactic": "Exfiltration",
          "description": "Data exfiltration using established C2 channel"
      }
  }
  ```
- Write `map_to_mitre(ioc_type, enrichment_results)` function that:
  - Takes the IOC type and enrichment data
  - Returns the most relevant MITRE technique based on findings
  - Returns multiple techniques if the IOC matches multiple patterns
- Add MITRE output to the final report for every IOC
- **Verify:** Running tool against a known malicious IP returns a MITRE technique ID

---

### Task 4 — Add Bulk IOC Processing
**Why:** Real SOC analysts process lists of IOCs, not one at a time. This makes the tool actually usable in a professional context.  
**What to do:**
- Add support for input file: `python main.py --file iocs.txt`
- Create `samples/sample_iocs.txt` with 10 test IOCs (mix of IPs, domains, hashes):
  ```
  8.8.8.8
  malware.example.com
  d41d8cd98f00b204e9800998ecf8427e
  185.220.101.1
  phishing-site.net
  ```
- Process each IOC in the file and output a combined report
- Add a summary section at the end: total IOCs, breakdown by risk level (Critical/High/Medium/Low/Clean)
- Add `--output` flag to save report to file: `python main.py --file iocs.txt --output report.md`
- **Verify:** `python main.py --file samples/sample_iocs.txt --output samples/sample_report.md` works end to end

---

### Task 5 — Improve Output Formatting
**Why:** The output needs to look like an analyst report, not a print statement dump.  
**What to do:**
- Create `ioc_intel/reporter.py`
- Write `generate_report(results)` that outputs clean structured text:
  ```
  ============================================================
  IOC THREAT INTELLIGENCE REPORT
  Generated: 2026-03-20 14:32:11
  ============================================================

  [1] IOC: 185.220.101.1
      Type: IPv4 Address
      Risk Score: 87/100 — CRITICAL
      
      Threat Intelligence:
        VirusTotal: 45/72 engines flagged
        AbuseIPDB: Confidence 94% — reported 312 times
        OTX: 3 threat pulses
        Feodo Tracker: LISTED — known botnet C2
        URLhaus: LISTED — active malware distribution
      
      MITRE ATT&CK:
        Technique: T1071 — Application Layer Protocol
        Tactic: Command and Control
      
      Verdict: Malicious — recommend immediate block
  ------------------------------------------------------------
  
  SUMMARY
  Total IOCs analysed: 10
  Critical: 2 | High: 3 | Medium: 2 | Low: 1 | Clean: 2
  ```
- Add `generate_markdown_report(results)` that outputs the same in proper Markdown for GitHub
- **Verify:** Output looks clean, structured, and readable

---

### Task 6 — Integrate Feodo Tracker and URLhaus (Real Threat Feeds)
**Why:** These are real threat feeds used in production SOC environments. Free, no auth required, updated daily. Adding them pushes this from "student API aggregator" to "legitimate threat intel tool."  
**What to do:**
- Add Feodo Tracker integration in `ioc_intel/enricher.py`:
  ```python
  import requests
  import json

  FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

  def check_feodo_tracker(ip):
      """Check if IP is a known Feodo botnet C2 server."""
      try:
          response = requests.get(FEODO_URL, timeout=10)
          blocklist = response.json()
          for entry in blocklist:
              if entry.get("ip_address") == ip:
                  return {
                      "listed": True,
                      "malware": entry.get("malware", "Unknown"),
                      "status": entry.get("status", "Unknown"),
                      "first_seen": entry.get("first_seen", "Unknown"),
                      "last_online": entry.get("last_online", "Unknown")
                  }
          return {"listed": False}
      except Exception as e:
          return {"listed": False, "error": str(e)}
  ```
- Add URLhaus integration in `ioc_intel/enricher.py`:
  ```python
  URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"

  def check_urlhaus(ioc, ioc_type):
      """Check URL or domain against URLhaus malware database."""
      try:
          if ioc_type == "url":
              payload = {"url": ioc}
              endpoint = URLHAUS_API + "url/"
          elif ioc_type == "domain":
              payload = {"host": ioc}
              endpoint = URLHAUS_API + "host/"
          elif ioc_type == "md5" or ioc_type == "sha256":
              payload = {"md5_hash": ioc} if ioc_type == "md5" else {"sha256_hash": ioc}
              endpoint = URLHAUS_API + "payload/"
          else:
              return {"listed": False}

          response = requests.post(endpoint, data=payload, timeout=10)
          data = response.json()

          if data.get("query_status") == "is_host" or data.get("query_status") == "ismalware":
              return {
                  "listed": True,
                  "url_count": data.get("url_count", 0),
                  "blacklists": data.get("blacklists", {}),
                  "tags": data.get("tags", [])
              }
          return {"listed": False}
      except Exception as e:
          return {"listed": False, "error": str(e)}
  ```
- Update `enrich_ioc()` to call both functions and include results
- Update `calculate_score()` in scorer.py to factor in Feodo and URLhaus hits:
  - Feodo listed = +30 to score (known botnet C2 is high confidence malicious)
  - URLhaus listed = +25 to score
- Update report output to show Feodo and URLhaus results
- Add to `.env.example` a note that these feeds require no API key
- **Verify:** Run tool against `185.220.101.1` (known Tor exit/C2) — Feodo check should return a result

---

## PHASE 3 — PORTFOLIO POLISH (March 29-30)

### Task 7 — Add Unit Tests
**Why:** No working tests = no confidence the code actually works. Reviewers notice this.  
**What to do:**
- Create `tests/` folder
- Create `tests/__init__.py`
- Create `tests/test_validator.py`:
  ```python
  import pytest
  from ioc_intel.validator import detect_ioc_type

  def test_ip_detection():
      assert detect_ioc_type("8.8.8.8") == "ipv4"

  def test_domain_detection():
      assert detect_ioc_type("malware.example.com") == "domain"

  def test_md5_detection():
      assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"

  def test_sha256_detection():
      assert detect_ioc_type("a" * 64) == "sha256"

  def test_invalid_ioc():
      assert detect_ioc_type("not_an_ioc") == "unknown"
  ```
- Create `tests/test_scorer.py`:
  ```python
  from ioc_intel.scorer import calculate_score, get_risk_level

  def test_critical_threshold():
      assert get_risk_level(90) == "CRITICAL"

  def test_high_threshold():
      assert get_risk_level(70) == "HIGH"

  def test_medium_threshold():
      assert get_risk_level(40) == "MEDIUM"

  def test_low_threshold():
      assert get_risk_level(15) == "LOW"

  def test_clean_threshold():
      assert get_risk_level(5) == "CLEAN"

  def test_score_in_range():
      score = calculate_score({"vt_positives": 50, "abuse_confidence": 90})
      assert 0 <= score <= 100
  ```
- Create `tests/test_mitre_mapper.py`:
  ```python
  from ioc_intel.mitre_mapper import map_to_mitre

  def test_malicious_ip_maps_to_c2():
      result = map_to_mitre("ipv4", {"feodo_listed": True})
      assert result["technique_id"] == "T1071"

  def test_phishing_domain_maps_correctly():
      result = map_to_mitre("domain", {"urlhaus_listed": True, "tags": ["phishing"]})
      assert result["technique_id"] == "T1566"

  def test_unknown_returns_default():
      result = map_to_mitre("unknown", {})
      assert "technique_id" in result
  ```
- Run: `pytest tests/ -v` — all must pass
- **Verify:** All green, no failures

---

### Task 8 — Write the Case Study Document
**Why:** A tool without a real-world scenario is just a script. A case study shows you understand how it would be used in an actual SOC.  
**What to do:**
- Create `docs/case-study.md`
- Write a simulated SOC scenario using this structure:
  ```markdown
  # Case Study: Investigating a Suspected C2 Callback

  ## Scenario
  A SIEM alert fired at 02:14 UTC — an internal endpoint (192.168.1.105)
  was observed making repeated outbound connections to an unknown external IP.
  The SOC analyst extracted the following IOCs from the alert:
  - External IP: 185.220.101.1
  - Domain contacted: update-service.xyz
  - File hash from endpoint: [hash from your sample_iocs.txt]

  ## Investigation Using IOC Threat Intel Engine

  ### Step 1 — Run bulk analysis
  [show the exact command used]

  ### Step 2 — Review results
  [paste actual tool output]

  ### Step 3 — MITRE mapping
  [show which techniques were identified and why]

  ### Step 4 — Verdict and recommended actions
  [what a SOC analyst would do next]

  ## Outcome
  All three IOCs confirmed malicious. Endpoint isolated pending IR.
  IP blocked at firewall. Domain added to DNS blocklist.
  Feodo Tracker confirmed IP as active botnet C2 infrastructure.
  ```
- Use real output from your tool — run it against actual test IOCs first
- **Verify:** Document reads like a real SOC investigation, not a tutorial

---

### Task 9 — Rewrite the README
**Why:** The README is the first thing any recruiter sees. It needs to sell the tool in 30 seconds.  
**What to do:**
- Structure it exactly like this:
  ```markdown
  # IOC Threat Intel Engine

  Automated threat intelligence enrichment tool for SOC analysts.
  Analyses IPs, domains, URLs, and file hashes against multiple threat
  intelligence sources and maps findings to MITRE ATT&CK techniques.

  ## Features
  - Multi-source enrichment: VirusTotal, AbuseIPDB, OTX, Feodo Tracker, URLhaus
  - Automatic IOC type detection (IPv4, IPv6, domain, URL, MD5, SHA256)
  - Risk scoring 0-100 with severity classification
  - MITRE ATT&CK technique mapping
  - Bulk processing from file input
  - Markdown and plain text report output

  ## Installation
  [clear steps — clone, pip install -r requirements.txt, copy .env.example to .env]

  ## Usage
  [show 3 example commands with real output]

  ## Example Output
  [paste a clean real output block]

  ## MITRE ATT&CK Coverage
  | Technique ID | Name | Tactic |
  |---|---|---|
  | T1071 | Application Layer Protocol | Command and Control |
  | T1566 | Phishing | Initial Access |
  | T1204 | User Execution | Execution |
  | T1071.001 | Web Protocols | Command and Control |
  | T1041 | Exfiltration Over C2 Channel | Exfiltration |

  ## Threat Feed Sources
  | Source | Type | Auth Required |
  |---|---|---|
  | VirusTotal | Multi-engine AV scan | API key |
  | AbuseIPDB | IP reputation | API key |
  | AlienVault OTX | Threat pulses | API key |
  | Feodo Tracker | Botnet C2 blocklist | None |
  | URLhaus | Malware URL database | None |

  ## Tech Stack
  Python 3.x | VirusTotal API | AbuseIPDB API | OTX API | Feodo Tracker | URLhaus
  ```
- **Verify:** Someone who knows nothing about the project understands it in 30 seconds

---

### Task 10 — Clean Git History and Final Commit
**Why:** A commit history full of "fix", "wip", "test123" looks amateur.  
**What to do:**
- Review history: `git log --oneline`
- Squash messy commits into logical ones using interactive rebase if needed
- Final commits should read cleanly — example:
  ```
  feat: add Feodo Tracker and URLhaus threat feed integration
  feat: add MITRE ATT&CK mapping module
  feat: add bulk IOC processing with --file and --output flags
  refactor: modularize codebase into ioc_intel package
  fix: move API keys to .env, remove hardcoded credentials
  docs: add case study and rewrite README
  test: add unit tests for validator, scorer, and mitre_mapper
  ```
- Ensure these files are all committed and present:
  - `main.py`
  - `ioc_intel/__init__.py`, `validator.py`, `enricher.py`, `scorer.py`, `mitre_mapper.py`, `reporter.py`
  - `tests/__init__.py`, `test_validator.py`, `test_scorer.py`, `test_mitre_mapper.py`
  - `samples/sample_iocs.txt`, `samples/sample_report.md`
  - `docs/case-study.md`
  - `.env.example`
  - `requirements.txt` — run `pip freeze > requirements.txt` before final commit
  - `README.md`
  - `.gitignore` — must include `.env`
- Pin repo on GitHub profile
- **Verify:** Repo looks clean, professional, and complete from the outside

---

## FINAL CHECKLIST

| Task | What It Proves | Done? |
|------|----------------|-------|
| Task 1 — .env security | Basic security hygiene | ☐ |
| Task 2 — Modular structure | Maintainable code | ☐ |
| Task 3 — MITRE mapping | Threat intelligence understanding | ☐ |
| Task 4 — Bulk processing | Tool is usable in a real SOC | ☐ |
| Task 5 — Clean output | You think about the end user | ☐ |
| Task 6 — Feodo + URLhaus | Real threat feeds, production-grade | ☐ |
| Task 7 — Unit tests | Reliable, testable code | ☐ |
| Task 8 — Case study | Real SOC workflow understanding | ☐ |
| Task 9 — README | You can communicate your work | ☐ |
| Task 10 — Clean git history | You work like a professional | ☐ |

---

*Complete Tasks 1-2 on March 15-16. Tasks 3-6 during March 19-28. Tasks 7-10 on March 29-30.*  
*After March 30 this project is frozen — do not touch it during Phase 2.*
