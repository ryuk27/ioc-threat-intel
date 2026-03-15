# IOC Threat Intel Engine — Test IOC List
**Use this file as samples/sample_iocs.txt to verify the tool works correctly.**  
**Every IOC here has a known expected result so you can confirm the tool is returning accurate data.**

---

## HOW TO USE THIS FILE

1. Copy the IOCs from each section into `samples/sample_iocs.txt`
2. Run: `python main.py --file samples/sample_iocs.txt --output samples/sample_report.md`
3. Compare your tool's output against the expected results listed below
4. If the tool's verdict matches — it is working correctly

---

## SECTION 1 — MALICIOUS IPs (Expected: HIGH or CRITICAL)

| IOC | Type | Why It Should Flag | Expected Score |
|-----|------|--------------------|----------------|
| `185.220.101.1` | IPv4 | Known Tor exit node, heavily reported on AbuseIPDB, appears on Feodo | CRITICAL |
| `185.220.101.34` | IPv4 | Known Tor exit node, high abuse confidence | CRITICAL |
| `194.165.16.11` | IPv4 | Known malware C2, reported extensively | HIGH |
| `45.142.212.100` | IPv4 | Known scanning/attack infrastructure | HIGH |
| `91.92.109.196` | IPv4 | Known brute force source, high AbuseIPDB reports | HIGH |

---

## SECTION 2 — CLEAN IPs (Expected: LOW or CLEAN)

| IOC | Type | Why It Should Be Clean | Expected Score |
|-----|------|------------------------|----------------|
| `8.8.8.8` | IPv4 | Google DNS — completely clean | CLEAN |
| `1.1.1.1` | IPv4 | Cloudflare DNS — completely clean | CLEAN |
| `9.9.9.9` | IPv4 | Quad9 DNS — completely clean | CLEAN |

---

## SECTION 3 — MALICIOUS DOMAINS (Expected: HIGH or CRITICAL)

| IOC | Type | Why It Should Flag | Expected Score |
|-----|------|--------------------|----------------|
| `emotet.com` | Domain | Associated with Emotet malware campaigns | HIGH/CRITICAL |
| `malware-traffic-analysis.net` | Domain | Note: this is a RESEARCH site — tool should return LOW/CLEAN. Use to verify false positive handling. | LOW |

> **Important:** malware-traffic-analysis.net is a legitimate security research site. If your tool flags it as malicious that is a false positive — useful to document in your case study.

---

## SECTION 4 — CLEAN DOMAINS (Expected: LOW or CLEAN)

| IOC | Type | Why It Should Be Clean | Expected Score |
|-----|------|------------------------|----------------|
| `google.com` | Domain | Legitimate, well-known domain | CLEAN |
| `microsoft.com` | Domain | Legitimate, well-known domain | CLEAN |
| `tryhackme.com` | Domain | Legitimate security training platform | CLEAN |
| `github.com` | Domain | Legitimate platform | CLEAN |

---

## SECTION 5 — MALICIOUS FILE HASHES (Expected: HIGH or CRITICAL)

These are publicly documented malware hashes safe to use for testing — the actual files are not present, only the hash values.

| IOC | Type | Malware Family | Expected Score |
|-----|------|----------------|----------------|
| `44d88612fea8a8f36de82e1278abb02f` | MD5 | EICAR test string — every AV flags this, used specifically for testing | CRITICAL |
| `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | SHA256 | EICAR test string SHA256 — same as above | CRITICAL |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | SHA256 | Empty file hash — should return CLEAN | CLEAN |
| `d41d8cd98f00b204e9800998ecf8427e` | MD5 | Empty file MD5 — should return CLEAN | CLEAN |

> **Note on EICAR:** The EICAR test hash is the industry-standard safe test for AV/threat intel tools. VirusTotal will flag it. No actual malware file is needed — the hash alone is enough.

---

## SECTION 6 — EDGE CASES (Expected: handled gracefully, no crashes)

| IOC | Expected Behaviour |
|-----|--------------------|
| `not_an_ioc` | Detected as `unknown` type, skipped gracefully |
| `999.999.999.999` | Invalid IP, detected as `unknown`, no crash |
| `http://` | Incomplete URL, detected as `unknown` or `url` with no results |
| ` ` (blank line) | Skipped silently |
| `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` | 31 chars — not a valid hash, detected as `unknown` |

---

## READY-TO-USE sample_iocs.txt

Copy everything below this line into `samples/sample_iocs.txt`:

```
# Malicious IPs
185.220.101.1
185.220.101.34
194.165.16.11
45.142.212.100
91.92.109.196

# Clean IPs
8.8.8.8
1.1.1.1
9.9.9.9

# Domains
google.com
microsoft.com
malware-traffic-analysis.net

# File Hashes - EICAR test (safe)
44d88612fea8a8f36de82e1278abb02f
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Clean hashes - empty file
d41d8cd98f00b204e9800998ecf8427e
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# Edge cases
not_an_ioc
999.999.999.999
```

---

## EXPECTED SUMMARY OUTPUT

When you run the tool against the full list above, your summary section should look roughly like this:

```
SUMMARY
Total IOCs analysed: 17
Critical : 4
High     : 3
Medium   : 0
Low      : 3
Clean    : 5
Unknown  : 2
```

If your counts are wildly different — recheck the scoring logic in `ioc_intel/scorer.py`.  
If the tool crashes on any IOC — fix the error handling in `ioc_intel/enricher.py` before the final commit.

---

## NOTES

- All malicious IPs listed are publicly documented on AbuseIPDB and are Tor exit nodes or known attack infrastructure. They are not secret — they appear on public blocklists.
- EICAR hashes are the industry-standard test for security tools. Completely safe to use.
- Never paste these IOCs into a browser or attempt to connect to them — analysis only through the tool.
- Scores may vary slightly depending on when you run the tool — threat intel data changes daily.
