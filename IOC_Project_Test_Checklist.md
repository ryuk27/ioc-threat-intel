# IOC Threat Intel Engine — Testing & Verification Checklist
**Run this after completing all 10 upgrade tasks.**  
**Every single item must pass before the project is considered portfolio-ready.**

---

## TEST 1 — Environment and Setup

```bash
# Run these commands and verify each output
```

| # | Command | Expected Result | Pass? |
|---|---------|-----------------|-------|
| 1.1 | `cat .gitignore \| grep .env` | `.env` appears in output | ☐ |
| 1.2 | `git status` | `.env` does NOT appear as tracked or untracked | ☐ |
| 1.3 | `ls .env.example` | File exists | ☐ |
| 1.4 | `cat .env.example` | Shows placeholder keys, no real values | ☐ |
| 1.5 | `pip install -r requirements.txt` | Installs without errors | ☐ |
| 1.6 | `ls ioc_intel/` | Shows: `__init__.py validator.py enricher.py scorer.py mitre_mapper.py reporter.py` | ☐ |
| 1.7 | `ls tests/` | Shows: `__init__.py test_validator.py test_scorer.py test_mitre_mapper.py` | ☐ |
| 1.8 | `ls samples/` | Shows: `sample_iocs.txt sample_report.md` | ☐ |
| 1.9 | `ls docs/` | Shows: `case-study.md` | ☐ |

---

## TEST 2 — Unit Tests

```bash
pytest tests/ -v
```

| # | Test | Expected Result | Pass? |
|---|------|-----------------|-------|
| 2.1 | `test_ip_detection` | PASSED | ☐ |
| 2.2 | `test_domain_detection` | PASSED | ☐ |
| 2.3 | `test_md5_detection` | PASSED | ☐ |
| 2.4 | `test_sha256_detection` | PASSED | ☐ |
| 2.5 | `test_invalid_ioc` | PASSED | ☐ |
| 2.6 | `test_critical_threshold` | PASSED | ☐ |
| 2.7 | `test_high_threshold` | PASSED | ☐ |
| 2.8 | `test_medium_threshold` | PASSED | ☐ |
| 2.9 | `test_low_threshold` | PASSED | ☐ |
| 2.10 | `test_clean_threshold` | PASSED | ☐ |
| 2.11 | `test_score_in_range` | PASSED | ☐ |
| 2.12 | `test_malicious_ip_maps_to_c2` | PASSED | ☐ |
| 2.13 | `test_phishing_domain_maps_correctly` | PASSED | ☐ |
| 2.14 | `test_unknown_returns_default` | PASSED | ☐ |
| 2.15 | **Overall result** | `X passed, 0 failed` | ☐ |

---

## TEST 3 — IOC Validator

```bash
python -c "from ioc_intel.validator import detect_ioc_type; print(detect_ioc_type('INPUT'))"
```

Replace INPUT with each value below and verify the output:

| # | Input | Expected Output | Pass? |
|---|-------|-----------------|-------|
| 3.1 | `8.8.8.8` | `ipv4` | ☐ |
| 3.2 | `2001:db8::1` | `ipv6` | ☐ |
| 3.3 | `malware.example.com` | `domain` | ☐ |
| 3.4 | `http://malware.example.com/payload` | `url` | ☐ |
| 3.5 | `d41d8cd98f00b204e9800998ecf8427e` | `md5` | ☐ |
| 3.6 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `sha256` | ☐ |
| 3.7 | `not_an_ioc_at_all` | `unknown` | ☐ |
| 3.8 | ` ` (empty string) | `unknown` or raises handled error | ☐ |

---

## TEST 4 — Risk Scorer

```bash
python -c "from ioc_intel.scorer import get_risk_level; print(get_risk_level(INPUT))"
```

| # | Input Score | Expected Level | Pass? |
|---|-------------|----------------|-------|
| 4.1 | `95` | `CRITICAL` | ☐ |
| 4.2 | `75` | `HIGH` | ☐ |
| 4.3 | `45` | `MEDIUM` | ☐ |
| 4.4 | `15` | `LOW` | ☐ |
| 4.5 | `3` | `CLEAN` | ☐ |
| 4.6 | `0` | `CLEAN` | ☐ |
| 4.7 | `100` | `CRITICAL` | ☐ |

---

## TEST 5 — MITRE Mapper

```bash
python -c "from ioc_intel.mitre_mapper import map_to_mitre; import json; print(json.dumps(map_to_mitre('INPUT_TYPE', INPUT_DATA), indent=2))"
```

| # | IOC Type | Input Data | Expected technique_id | Pass? |
|---|----------|------------|-----------------------|-------|
| 5.1 | `ipv4` | `{"feodo_listed": True}` | `T1071` | ☐ |
| 5.2 | `domain` | `{"urlhaus_listed": True}` | `T1566` or `T1071` | ☐ |
| 5.3 | `md5` | `{"vt_positives": 40}` | `T1204` | ☐ |
| 5.4 | `ipv4` | `{"abuse_confidence": 90}` | `T1071` | ☐ |
| 5.5 | `unknown` | `{}` | Returns dict with `technique_id` key | ☐ |

---

## TEST 6 — Feodo Tracker Integration

```bash
python -c "from ioc_intel.enricher import check_feodo_tracker; import json; print(json.dumps(check_feodo_tracker('INPUT'), indent=2))"
```

| # | Input IP | Expected Result | Pass? |
|---|----------|-----------------|-------|
| 6.1 | `8.8.8.8` | `{"listed": false}` | ☐ |
| 6.2 | Any IP from feodotracker.abuse.ch/browse | `{"listed": true, "malware": "...", ...}` | ☐ |
| 6.3 | `999.999.999.999` (invalid) | Returns dict, does not crash | ☐ |

> To find a listed IP for test 6.2: visit https://feodotracker.abuse.ch/browse and copy any IP from the list.

---

## TEST 7 — URLhaus Integration

```bash
python -c "from ioc_intel.enricher import check_urlhaus; import json; print(json.dumps(check_urlhaus('INPUT', 'TYPE'), indent=2))"
```

| # | Input | Type | Expected Result | Pass? |
|---|-------|------|-----------------|-------|
| 7.1 | `google.com` | `domain` | `{"listed": false}` | ☐ |
| 7.2 | Any domain from urlhaus.abuse.ch | `domain` | `{"listed": true, ...}` | ☐ |
| 7.3 | `d41d8cd98f00b204e9800998ecf8427e` | `md5` | Returns dict, does not crash | ☐ |

> To find a listed domain for test 7.2: visit https://urlhaus.abuse.ch and copy any active host.

---

## TEST 8 — Single IOC Analysis

```bash
python main.py --ioc 8.8.8.8
```

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 8.1 | Tool runs without error | No traceback | ☐ |
| 8.2 | Output shows IOC type | `Type: IPv4 Address` | ☐ |
| 8.3 | Output shows risk score | `Risk Score: X/100 — LEVEL` | ☐ |
| 8.4 | Output shows VirusTotal result | VT section present | ☐ |
| 8.5 | Output shows AbuseIPDB result | AbuseIPDB section present | ☐ |
| 8.6 | Output shows OTX result | OTX section present | ☐ |
| 8.7 | Output shows Feodo result | Feodo Tracker section present | ☐ |
| 8.8 | Output shows URLhaus result | URLhaus section present | ☐ |
| 8.9 | Output shows MITRE technique | Technique ID and name present | ☐ |
| 8.10 | Output shows verdict | `Verdict:` line present | ☐ |

---

## TEST 9 — Bulk IOC Processing

First create this test file:
```bash
cat << 'IOCFILE' > test_bulk.txt
8.8.8.8
1.1.1.1
malware.example.com
d41d8cd98f00b204e9800998ecf8427e
not_an_ioc
IOCFILE
```

Then run:
```bash
python main.py --file test_bulk.txt --output test_output.md
```

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 9.1 | Tool runs without error | No traceback | ☐ |
| 9.2 | All 5 IOCs processed | 5 results in output | ☐ |
| 9.3 | Invalid IOC handled | `not_an_ioc` shows `unknown` type, does not crash | ☐ |
| 9.4 | Output file created | `test_output.md` exists | ☐ |
| 9.5 | Summary section present | Shows total count and breakdown by risk level | ☐ |
| 9.6 | Markdown file is valid | Open in any markdown viewer — renders correctly | ☐ |

---

## TEST 10 — Sample Report Generation

```bash
python main.py --file samples/sample_iocs.txt --output samples/sample_report.md
```

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 10.1 | Command runs without error | No traceback | ☐ |
| 10.2 | sample_report.md is created/updated | File exists and is not empty | ☐ |
| 10.3 | Report has timestamp | `Generated:` line present | ☐ |
| 10.4 | Each IOC has its own section | Numbered entries [1], [2], etc. | ☐ |
| 10.5 | Summary at end | Total IOCs + risk level breakdown | ☐ |
| 10.6 | Commit report to GitHub | `git add samples/sample_report.md && git commit -m "docs: add sample report output"` | ☐ |

---

## TEST 11 — Error Handling

These tests verify the tool fails gracefully, not catastrophically.

| # | Scenario | How to Test | Expected Behaviour | Pass? |
|---|----------|-------------|-------------------|-------|
| 11.1 | No API key set | Remove VT_API_KEY from .env, run tool | Prints clear error message, does not crash with traceback | ☐ |
| 11.2 | Empty input file | `echo "" > empty.txt && python main.py --file empty.txt` | Handles gracefully, prints "no IOCs found" | ☐ |
| 11.3 | File does not exist | `python main.py --file nonexistent.txt` | Prints clear error, does not crash | ☐ |
| 11.4 | Network timeout | Disconnect internet, run tool | Handles timeout gracefully, shows partial results | ☐ |
| 11.5 | Invalid IOC in bulk file | Include `!!!not@valid###` in file | Marks as unknown, continues processing rest | ☐ |

> Restore your .env after test 11.1.

---

## TEST 12 — Git and Repository

```bash
git log --oneline
git status
```

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 12.1 | `.env` not tracked | `git status` shows no `.env` file | ☐ |
| 12.2 | `.env.example` committed | Appears in repo | ☐ |
| 12.3 | `requirements.txt` committed | Appears in repo | ☐ |
| 12.4 | No `__pycache__` committed | Not in repo | ☐ |
| 12.5 | Commit messages are clean | No "wip", "fix", "test123" in log | ☐ |
| 12.6 | README renders on GitHub | Open repo in browser — README looks professional | ☐ |
| 12.7 | Repo is pinned on profile | Visible on github.com/ryuk27 | ☐ |

---

## FINAL SIGN-OFF

Only mark this complete when every single test above has passed.

| Section | All Passed? |
|---------|-------------|
| Test 1 — Environment and Setup | ☐ |
| Test 2 — Unit Tests | ☐ |
| Test 3 — IOC Validator | ☐ |
| Test 4 — Risk Scorer | ☐ |
| Test 5 — MITRE Mapper | ☐ |
| Test 6 — Feodo Tracker | ☐ |
| Test 7 — URLhaus | ☐ |
| Test 8 — Single IOC | ☐ |
| Test 9 — Bulk Processing | ☐ |
| Test 10 — Sample Report | ☐ |
| Test 11 — Error Handling | ☐ |
| Test 12 — Git and Repository | ☐ |

**When all 12 sections are green — project is portfolio-ready. Freeze it and move on.**

---

*If any test fails — fix it before moving to the next task. Do not skip failures.*  
*Tag me in this document with what broke and I will help you fix it.*
