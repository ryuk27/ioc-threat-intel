import requests
import json
import time
import argparse
from pathlib import Path
from datetime import datetime
import ipaddress
import hashlib
import re

# Configuration
CONFIG = {
    'virustotal_api_key': 'YOUR_VIRUSTOTAL_API_KEY',
    'abuseipdb_api_key': 'YOUR_ABUSEIPDB_API_KEY',
    'shodan_api_key': 'YOUR_SHODAN_API_KEY',
    'rate_limit_delay': 15,  # seconds between API calls
    'malicious_threshold': 5,  # minimum detections to consider malicious
    'high_abuse_score': 75,  # AbuseIPDB confidence score for high risk
    'output_format': 'markdown'  # or 'csv'
}

class IOCAnalyzer:
    def __init__(self):
        self.results = []
        self.api_call_count = 0
        
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
    
    def check_virustotal(self, ioc_type, ioc_value):
        """Query VirusTotal for hash or domain information"""
        if ioc_type in ['md5', 'sha1', 'sha256']:
            endpoint = 'files'
        elif ioc_type == 'domain':
            endpoint = 'domains'
        else:
            return None
        
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc_value}"
        headers = {'x-apikey': CONFIG['virustotal_api_key']}
        
        data = self.make_api_request(url, headers=headers)
        if not data:
            return None
        
        result = {
            'source': 'VirusTotal',
            'ioc': ioc_value,
            'type': ioc_type
        }
        
        if 'data' in data and 'attributes' in data['data']:
            attrs = data['data']['attributes']
            
            if 'last_analysis_stats' in attrs:
                stats = attrs['last_analysis_stats']
                result['malicious'] = stats.get('malicious', 0)
                result['suspicious'] = stats.get('suspicious', 0)
                result['undetected'] = stats.get('undetected', 0)
                result['harmless'] = stats.get('harmless', 0)
            
            if 'popular_threat_classification' in attrs:
                threats = attrs['popular_threat_classification'].get('popular_threat_category', [])
                if threats:
                    result['threat_categories'] = [t['value'] for t in threats]
            
            if 'names' in attrs and attrs['names']:
                result['names'] = attrs['names'][:3]  # First 3 names
        
        return result
    
    def check_abuseipdb(self, ip):
        """Query AbuseIPDB for IP reputation"""
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': CONFIG['abuseipdb_api_key'],
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        
        data = self.make_api_request(url, headers=headers, params=params)
        if not data:
            return None
        
        result = {
            'source': 'AbuseIPDB',
            'ioc': ip,
            'type': 'ip'
        }
        
        if 'data' in data:
            result['abuse_confidence'] = data['data'].get('abuseConfidenceScore', 0)
            result['country'] = data['data'].get('countryCode', 'Unknown')
            result['isp'] = data['data'].get('isp', 'Unknown')
            result['usage_type'] = data['data'].get('usageType', 'Unknown')
            result['total_reports'] = data['data'].get('totalReports', 0)
            result['last_reported'] = data['data'].get('lastReportedAt', 'Never')
        
        return result
    
    def check_shodan(self, ip):
        """Query Shodan for IP information (free tier)"""
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {
            'key': CONFIG['shodan_api_key']
        }
        
        data = self.make_api_request(url, params=params)
        if not data:
            return None
        
        result = {
            'source': 'Shodan',
            'ioc': ip,
            'type': 'ip'
        }
        
        if 'ports' in data:
            result['open_ports'] = data['ports']
        
        if 'vulns' in data:
            result['vulnerabilities'] = list(data['vulns'].keys())
        
        if 'org' in data:
            result['organization'] = data['org']
        
        if 'os' in data:
            result['operating_system'] = data['os']
        
        return result
    
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
    
    def process_ioc(self, ioc):
        """Process a single IOC through all relevant APIs"""
        ioc_type, ioc_value = self.validate_ioc(ioc)
        
        if not ioc_type:
            print(f"[-] Invalid IOC format: {ioc}")
            return
        
        print(f"[*] Processing {ioc_type.upper()}: {ioc_value}")
        
        # Route to appropriate APIs based on IOC type
        if ioc_type in ['md5', 'sha1', 'sha256', 'domain']:
            result = self.check_virustotal(ioc_type, ioc_value)
            if result:
                result['risk_score'] = self.calculate_risk_score(result)
                self.results.append(result)
        
        elif ioc_type == 'ip':
            # Check all IP-related APIs
            abuse_result = self.check_abuseipdb(ioc_value)
            if abuse_result:
                abuse_result['risk_score'] = self.calculate_risk_score(abuse_result)
                self.results.append(abuse_result)
            
            shodan_result = self.check_shodan(ioc_value)
            if shodan_result:
                shodan_result['risk_score'] = self.calculate_risk_score(shodan_result)
                self.results.append(shodan_result)
    
    def generate_report(self, output_file):
        """Generate a report in the specified format"""
        if not self.results:
            print("No results to report")
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if CONFIG['output_format'] == 'markdown':
            with open(output_file, 'w') as f:
                f.write(f"# IOC Threat Intelligence Report\n\n")
                f.write(f"Generated on: {timestamp}\n")
                f.write(f"Total IOCs processed: {len(self.results)}\n\n")
                
                for result in sorted(self.results, key=lambda x: -x['risk_score']):
                    f.write(f"## {result['ioc']} ({result['type'].upper()})\n")
                    f.write(f"**Source:** {result['source']}\n")
                    f.write(f"**Risk Score:** {result['risk_score']}/100\n")
                    
                    if result['source'] == 'VirusTotal':
                        f.write(f"- Malicious detections: {result.get('malicious', 0)}\n")
                        f.write(f"- Suspicious detections: {result.get('suspicious', 0)}\n")
                        if 'threat_categories' in result:
                            f.write("- Threat categories: " + ", ".join(result['threat_categories']) + "\n")
                        if 'names' in result:
                            f.write("- Associated names: " + ", ".join(result['names']) + "\n")
                    
                    elif result['source'] == 'AbuseIPDB':
                        f.write(f"- Abuse Confidence: {result.get('abuse_confidence', 0)}%\n")
                        f.write(f"- Total Reports: {result.get('total_reports', 0)}\n")
                        f.write(f"- Country: {result.get('country', 'Unknown')}\n")
                        f.write(f"- ISP: {result.get('isp', 'Unknown')}\n")
                        f.write(f"- Last Reported: {result.get('last_reported', 'Never')}\n")
                    
                    elif result['source'] == 'Shodan':
                        if 'open_ports' in result:
                            f.write(f"- Open Ports: {', '.join(map(str, result['open_ports']))}\n")
                        if 'vulnerabilities' in result:
                            f.write(f"- Vulnerabilities: {', '.join(result['vulnerabilities'])}\n")
                        if 'organization' in result:
                            f.write(f"- Organization: {result['organization']}\n")
                    
                    f.write("\n")
        
        elif CONFIG['output_format'] == 'csv':
            import csv
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IOC', 'Type', 'Source', 'Risk Score', 'Details'])
                
                for result in sorted(self.results, key=lambda x: -x['risk_score']):
                    details = []
                    
                    if result['source'] == 'VirusTotal':
                        details.append(f"Malicious: {result.get('malicious', 0)}")
                        details.append(f"Suspicious: {result.get('suspicious', 0)}")
                        if 'threat_categories' in result:
                            details.append("Categories: " + ", ".join(result['threat_categories']))
                    
                    elif result['source'] == 'AbuseIPDB':
                        details.append(f"Confidence: {result.get('abuse_confidence', 0)}%")
                        details.append(f"Reports: {result.get('total_reports', 0)}")
                        details.append(f"Country: {result.get('country', 'Unknown')}")
                    
                    elif result['source'] == 'Shodan':
                        if 'open_ports' in result:
                            details.append(f"Ports: {', '.join(map(str, result['open_ports']))}")
                        if 'vulnerabilities' in result:
                            details.append(f"Vulns: {len(result['vulnerabilities'])}")
                    
                    writer.writerow([
                        result['ioc'],
                        result['type'],
                        result['source'],
                        result['risk_score'],
                        "; ".join(details)
                    ])
        
        print(f"[+] Report generated: {output_file}")

def validate_config():
    """Check if API keys are configured"""
    missing_keys = []
    if CONFIG['virustotal_api_key'] == 'YOUR_VIRUSTOTAL_API_KEY':
        missing_keys.append('VirusTotal')
    if CONFIG['abuseipdb_api_key'] == 'YOUR_ABUSEIPDB_API_KEY':
        missing_keys.append('AbuseIPDB')
    if CONFIG['shodan_api_key'] == 'YOUR_SHODAN_API_KEY':
        missing_keys.append('Shodan')
    
    if missing_keys:
        print("⚠️  Warning: The following API keys are not configured:")
        for key in missing_keys:
            print(f"   - {key}")
        print("   The application will still work but with limited functionality.")
        print("   Please update the CONFIG section in the script with your API keys.\n")

def main():
    parser = argparse.ArgumentParser(description='IOC Threat Intelligence Correlation Engine')
    parser.add_argument('input_file', help='Path to file containing IOCs (one per line)')
    parser.add_argument('output_file', help='Path to save the report')
    parser.add_argument('--config-check', action='store_true', help='Check API configuration and exit')
    args = parser.parse_args()
    
    # Check configuration
    validate_config()
    
    if args.config_check:
        print("Configuration check complete.")
        return
    
    # Verify input file exists
    if not Path(args.input_file).exists():
        print(f"Error: Input file not found - {args.input_file}")
        return
    
    # Initialize analyzer
    analyzer = IOCAnalyzer()
    
    print(f"🔍 Starting IOC analysis...")
    print(f"📁 Input file: {args.input_file}")
    print(f"📄 Output file: {args.output_file}\n")
    
    # Read and process IOCs
    ioc_count = 0
    with open(args.input_file, 'r') as f:
        for line in f:
            ioc = line.strip()
            if ioc and not ioc.startswith('#'):  # Skip empty lines and comments
                analyzer.process_ioc(ioc)
                ioc_count += 1
    
    print(f"\n📊 Processed {ioc_count} IOCs")
    print(f"✅ Found {len(analyzer.results)} results")
    
    # Generate report
    analyzer.generate_report(args.output_file)
    print(f"🎉 Analysis complete!")

if __name__ == '__main__':
    main()
