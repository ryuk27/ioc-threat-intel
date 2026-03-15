"""IOC Enrichment Module — API Integration"""

import requests
import os
import time
from typing import Dict, Any, Optional


def make_api_request(
    url: str,
    headers: Optional[Dict] = None,
    params: Optional[Dict] = None,
    timeout: int = 10
) -> Optional[Dict[str, Any]]:
    """
    Generic API request helper with error handling
    
    Args:
        url: API endpoint URL
        headers: HTTP headers
        params: Query parameters
        timeout: Request timeout in seconds
        
    Returns:
        Dict: API response JSON or None on failure
    """
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        
        if response.status_code == 429:
            print(f"[!] Rate limit hit. Waiting 60 seconds...")
            time.sleep(60)
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
        
        if response.status_code == 401:
            print(f"[-] Authentication failed. Check your API key.")
            return None
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] API request failed: {e}")
        return None


def check_virustotal(ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """
    Query VirusTotal for file hash, domain, IP, or URL information
    
    Args:
        ioc_type: Type of IOC ('ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256')
        ioc_value: The IOC value to check
        
    Returns:
        Dict: Enrichment results
    """
    api_key = os.getenv('VT_API_KEY', '')
    
    if not api_key:
        return {'source': 'VirusTotal', 'error': 'API key not configured'}
    
    # Determine endpoint based on IOC type
    if ioc_type in ['md5', 'sha1', 'sha256', 'sha512']:
        endpoint = 'files'
    elif ioc_type in ['domain', 'url', 'ipv4', 'ipv6']:
        # For simplicity, use domains endpoint for domains
        if ioc_type == 'domain':
            endpoint = 'domains'
        elif ioc_type in ['ipv4', 'ipv6']:
            endpoint = 'ip_addresses'
        else:
            endpoint = 'urls'
    else:
        return {'source': 'VirusTotal', 'error': 'Unsupported IOC type'}
    
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc_value}"
    headers = {'x-apikey': api_key}
    
    data = make_api_request(url, headers=headers)
    
    result = {
        'source': 'VirusTotal',
        'ioc': ioc_value,
        'ioc_type': ioc_type,
        'available': False
    }
    
    if not data:
        return result
    
    result['available'] = True
    
    if 'data' in data and 'attributes' in data['data']:
        attrs = data['data']['attributes']
        
        # Get analysis stats
        if 'last_analysis_stats' in attrs:
            stats = attrs['last_analysis_stats']
            result['malicious'] = stats.get('malicious', 0)
            result['suspicious'] = stats.get('suspicious', 0)
            result['vt_positives'] = stats.get('malicious', 0)  # For scoring
            result['vt_suspicious'] = stats.get('suspicious', 0)
        
        # Get threat categories
        if 'popular_threat_classification' in attrs:
            threats = attrs['popular_threat_classification'].get('popular_threat_category', [])
            if threats:
                result['threat_categories'] = [t['value'] for t in threats]
    
    return result


def check_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB for IP reputation
    
    Args:
        ip: IP address to check
        
    Returns:
        Dict: Enrichment results
    """
    api_key = os.getenv('ABUSEIPDB_API_KEY', '')
    
    if not api_key:
        return {'source': 'AbuseIPDB', 'error': 'API key not configured'}
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    data = make_api_request(url, headers=headers, params=params)
    
    result = {
        'source': 'AbuseIPDB',
        'ioc': ip,
        'ioc_type': 'ipv4',
        'available': False
    }
    
    if not data:
        return result
    
    result['available'] = True
    
    if 'data' in data:
        result['abuse_confidence'] = data['data'].get('abuseConfidenceScore', 0)
        result['country'] = data['data'].get('countryCode', 'Unknown')
        result['isp'] = data['data'].get('isp', 'Unknown')
        result['total_reports'] = data['data'].get('totalReports', 0)
        result['last_reported'] = data['data'].get('lastReportedAt', 'Never')
    
    return result


def check_feodo_tracker(ip: str) -> Dict[str, Any]:
    """
    Check if IP is a known Feodo botnet C2 server
    No API key required - public blocklist
    
    Args:
        ip: IP address to check
        
    Returns:
        Dict: Enrichment results
    """
    result = {
        'source': 'Feodo Tracker',
        'ioc': ip,
        'ioc_type': 'ipv4',
        'listed': False,
        'available': False
    }
    
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        blocklist = response.json()
        result['available'] = True
        
        for entry in blocklist:
            if entry.get('ip_address') == ip:
                result['listed'] = True
                result['feodo_listed'] = True
                result['malware'] = entry.get('malware', 'Unknown')
                result['status'] = entry.get('status', 'Unknown')
                result['first_seen'] = entry.get('first_seen', 'Unknown')
                result['last_online'] = entry.get('last_online', 'Unknown')
                return result
    
    except Exception as e:
        print(f"[!] Feodo Tracker check failed: {e}")
        result['available'] = False
    
    return result


def check_urlhaus(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """
    Check URL or domain against URLhaus malware database
    No API key required - public API
    
    Args:
        ioc: The IOC value (domain, URL, or hash)
        ioc_type: Type of IOC
        
    Returns:
        Dict: Enrichment results
    """
    result = {
        'source': 'URLhaus',
        'ioc': ioc,
        'ioc_type': ioc_type,
        'listed': False,
        'available': False
    }
    
    try:
        api_url = "https://urlhaus.abuse.ch/api/v1/"
        
        if ioc_type == 'url':
            payload = {'url': ioc}
            endpoint = 'url/'
        elif ioc_type == 'domain':
            payload = {'host': ioc}
            endpoint = 'host/'
        elif ioc_type in ['md5', 'sha256']:
            # Note: URLhaus payload endpoint appears to be deprecated
            # Gracefully skip for now
            return result
        else:
            return result
        
        response = requests.post(api_url + endpoint, data=payload, timeout=10)
        response.raise_for_status()
        
        result['available'] = True
        
        # URLhaus API returns plain text "yes" or "no"
        response_text = response.text.strip().lower()
        
        if response_text == 'yes':
            result['listed'] = True
            result['urlhaus_listed'] = True
    
    except Exception as e:
        # URLhaus failures are non-critical - other sources provide better data
        result['available'] = False
    
    return result


def check_otx(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """
    Query AlienVault OTX for threat pulses
    
    Args:
        ioc: The IOC value
        ioc_type: Type of IOC
        
    Returns:
        Dict: Enrichment results
    """
    api_key = os.getenv('OTX_API_KEY', '')
    
    result = {
        'source': 'OTX',
        'ioc': ioc,
        'ioc_type': ioc_type,
        'available': False
    }
    
    if not api_key:
        return result
    
    try:
        # Map IOC type to OTX search field
        if ioc_type in ['ipv4', 'ipv6']:
            search_type = 'IPv4' if ioc_type == 'ipv4' else 'IPv6'
        elif ioc_type == 'domain':
            search_type = 'domain'
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            search_type = 'file'
        else:
            search_type = 'general'
        
        url = f"https://otx.alienvault.com/api/v1/indicators/{search_type}/{ioc}"
        headers = {'X-OTX-API-KEY': api_key}
        
        data = make_api_request(url, headers=headers)
        
        if data:
            result['available'] = True
            result['pulse_count'] = data.get('pulse_info', {}).get('count', 0)
            result['otx_pulse_count'] = result['pulse_count']
    
    except Exception as e:
        print(f"[!] OTX check failed: {e}")
    
    return result


def enrich_ioc(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """
    Run IOC through all available threat intelligence sources
    
    Args:
        ioc: The IOC value
        ioc_type: Type of IOC (from validator.detect_ioc_type)
        
    Returns:
        Dict: Aggregated enrichment results from all sources
    """
    enrichment = {
        'ioc': ioc,
        'ioc_type': ioc_type,
        'sources': {}
    }
    
    # Route to appropriate sources based on IOC type
    if ioc_type in ['md5', 'sha1', 'sha256', 'sha512']:
        # Hash checks
        enrichment['sources']['virustotal'] = check_virustotal(ioc_type, ioc)
        enrichment['sources']['urlhaus'] = check_urlhaus(ioc, ioc_type)
        enrichment['sources']['otx'] = check_otx(ioc, ioc_type)
    
    elif ioc_type == 'domain':
        # Domain checks
        enrichment['sources']['virustotal'] = check_virustotal(ioc_type, ioc)
        enrichment['sources']['urlhaus'] = check_urlhaus(ioc, ioc_type)
        enrichment['sources']['otx'] = check_otx(ioc, ioc_type)
    
    elif ioc_type == 'url':
        # URL checks
        enrichment['sources']['virustotal'] = check_virustotal(ioc_type, ioc)
        enrichment['sources']['urlhaus'] = check_urlhaus(ioc, ioc_type)
        enrichment['sources']['otx'] = check_otx(ioc, ioc_type)
    
    elif ioc_type in ['ipv4', 'ipv6']:
        # IP checks
        enrichment['sources']['virustotal'] = check_virustotal(ioc_type, ioc)
        enrichment['sources']['abuseipdb'] = check_abuseipdb(ioc)
        enrichment['sources']['feodo_tracker'] = check_feodo_tracker(ioc)
        enrichment['sources']['otx'] = check_otx(ioc, ioc_type)
    
    return enrichment
