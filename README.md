# IOC Threat Intelligence Correlation Engine

A Python tool for analyzing Indicators of Compromise (IOCs) using multiple threat intelligence APIs including VirusTotal, AbuseIPDB, and Shodan.

## Features

- **Multi-IOC Support**: Analyze IP addresses, domains, and file hashes (MD5, SHA1, SHA256)
- **Multiple APIs**: Integrates with VirusTotal, AbuseIPDB, and Shodan
- **Risk Scoring**: Calculates composite risk scores based on all available data
- **Rate Limiting**: Built-in rate limiting to respect API quotas
- **Multiple Output Formats**: Generate reports in Markdown or CSV format
- **Validation**: Automatic IOC format validation and type detection

## Installation

1. Clone or download this repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Before using the tool, you need to configure your API keys in the `app.py` file:

```python
CONFIG = {
    'virustotal_api_key': 'YOUR_VIRUSTOTAL_API_KEY',
    'abuseipdb_api_key': 'YOUR_ABUSEIPDB_API_KEY',
    'shodan_api_key': 'YOUR_SHODAN_API_KEY',
    # ... other settings
}
```

### Getting API Keys

- **VirusTotal**: Sign up at https://www.virustotal.com/
- **AbuseIPDB**: Sign up at https://www.abuseipdb.com/
- **Shodan**: Sign up at https://www.shodan.io/

## Usage

### Basic Usage

```bash
python app.py input_file.txt output_report.md
```

### Check Configuration

```bash
python app.py --config-check input_file.txt output_report.md
```

### Input File Format

Create a text file with one IOC per line:

```
8.8.8.8
google.com
44d88612fea8a8f36de82e1278abb02f
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
# This is a comment and will be ignored
malicious-domain.com
192.168.1.1
```

### Supported IOC Types

- **IP Addresses**: IPv4 addresses (e.g., `192.168.1.1`)
- **Domains**: Domain names (e.g., `example.com`)
- **File Hashes**: 
  - MD5 (32 characters)
  - SHA1 (40 characters)
  - SHA256 (64 characters)

## Output

The tool generates reports with:

- Risk scores (0-100)
- Detection counts from VirusTotal
- Abuse confidence scores from AbuseIPDB
- Open ports and vulnerabilities from Shodan
- Threat categorization
- Country and ISP information

### Sample Output (Markdown)

```markdown
# IOC Threat Intelligence Report

Generated on: 2025-08-11 15:49:15
Total IOCs processed: 2

## 1.2.3.4 (IP)
**Source:** AbuseIPDB
**Risk Score:** 95/100
- Abuse Confidence: 90%
- Total Reports: 25
- Country: US
- ISP: Test ISP
- Last Reported: 2024-01-01
```

## Key Code Implementations

### IOC Validation Logic

```python
def validate_ioc(self, ioc):
    """Determine the type of IOC and validate its format"""
    ioc = ioc.strip()
    
    # Check for IP address
    try:
        ipaddress.ip_address(ioc)
        return ('ip', ioc)
    except ValueError:
        pass
    
    # Check for domain
    domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    if re.match(domain_regex, ioc, re.IGNORECASE):
        return ('domain', ioc)
    
    # Check for file hashes (MD5, SHA1, SHA256)
    hash_lengths = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256'
    }
    clean_ioc = ioc.lower().replace('-', '')
    if len(clean_ioc) in hash_lengths and all(c in '0123456789abcdef' for c in clean_ioc):
        return (hash_lengths[len(clean_ioc)], clean_ioc)
    
    return (None, ioc)
```

This validation method automatically determines the type of IOC (Indicator of Compromise) and validates its format. It uses Python's built-in `ipaddress` module to validate IP addresses, regular expressions to check domain name format, and length-based detection with hexadecimal character verification for file hashes. The method normalizes hash formats by removing hyphens and converting to lowercase, ensuring consistent processing regardless of input format variations.

### Risk Scoring Algorithm

```python
def calculate_risk_score(self, result):
    """Calculate a composite risk score based on all available data"""
    score = 0
    
    if result['source'] == 'VirusTotal':
        malicious = result.get('malicious', 0)
        suspicious = result.get('suspicious', 0)
        
        if malicious >= CONFIG['malicious_threshold']:
            score = 100
        elif malicious > 0:
            score = 60 + (malicious * 5)
        elif suspicious > 0:
            score = 30 + (suspicious * 3)
        
        if 'threat_categories' in result:
            score += len(result['threat_categories']) * 5
    
    elif result['source'] == 'AbuseIPDB':
        confidence = result.get('abuse_confidence', 0)
        reports = result.get('total_reports', 0)
        
        if confidence >= CONFIG['high_abuse_score']:
            score = 90 + (reports * 0.1)
        elif confidence > 0:
            score = 50 + (confidence * 0.4) + (reports * 0.05)
    
    elif result['source'] == 'Shodan':
        if 'vulnerabilities' in result:
            score = len(result['vulnerabilities']) * 10
        
        if 'open_ports' in result:
            risky_ports = {21, 23, 80, 443, 3389, 5900, 8080}
            open_ports = set(result['open_ports'])
            score += len(risky_ports & open_ports) * 5
    
    return min(100, int(score))
```

The risk scoring algorithm creates a unified risk assessment across different threat intelligence sources. For VirusTotal data, it emphasizes malicious detection counts and threat categories, assigning maximum scores for IOCs exceeding the malicious threshold. AbuseIPDB results are scored based on abuse confidence percentages and report frequency, with higher weights for well-documented threats. Shodan data focuses on vulnerability counts and exposed high-risk services, identifying potentially compromised systems. The algorithm ensures all scores remain within a 0-100 range for consistent risk comparison.

### API Request with Rate Limiting

```python
def make_api_request(self, url, headers=None, params=None):
    """Generic API request handler with rate limiting"""
    if self.api_call_count > 0 and CONFIG['rate_limit_delay'] > 0:
        time.sleep(CONFIG['rate_limit_delay'])
    
    try:
        response = requests.get(url, headers=headers, params=params)
        self.api_call_count += 1
        
        # Handle rate limiting
        if response.status_code == 429:
            print(f"Rate limit hit for {url}. Waiting longer...")
            time.sleep(60)  # Wait 1 minute for rate limit
            response = requests.get(url, headers=headers, params=params)
        
        # Handle authentication errors more gracefully
        if response.status_code == 401:
            if 'virustotal.com' in url:
                print(f"[-] VirusTotal API key not configured or invalid")
            elif 'abuseipdb.com' in url:
                print(f"[-] AbuseIPDB API key not configured or invalid")
            elif 'shodan.io' in url:
                print(f"[-] Shodan API key not configured or invalid")
            return None
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        return None
```

This centralized API request handler implements comprehensive rate limiting and error handling for all threat intelligence API calls. It enforces configurable delays between requests to respect API quotas, automatically tracks API usage, and implements intelligent retry logic for rate limit errors (HTTP 429). The method provides graceful error handling with service-specific messages for authentication failures, ensuring users receive clear feedback about configuration issues. By centralizing all API interactions, it maintains consistent behavior across different threat intelligence services while preventing quota exhaustion and providing robust error recovery.

## Configuration Options

You can modify these settings in the `CONFIG` dictionary:

- `rate_limit_delay`: Seconds between API calls (default: 15)
- `malicious_threshold`: Minimum detections to consider malicious (default: 5)
- `high_abuse_score`: AbuseIPDB confidence score for high risk (default: 75)
- `output_format`: 'markdown' or 'csv' (default: 'markdown')

## Error Handling

The tool handles:
- Invalid IOC formats
- API rate limiting
- Authentication errors
- Network connectivity issues
- Missing API keys

## Limitations

- Free tier API limitations apply
- Rate limiting may slow down large batches
- Some APIs may not have data for all IOCs

## Contributing

Feel free to submit issues and enhancement requests!
