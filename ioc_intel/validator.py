"""IOC Type Detection and Validation Module"""

import re
import ipaddress
from typing import Tuple, Optional


def is_ipv4(ioc: str) -> bool:
    """Check if IOC is a valid IPv4 address"""
    try:
        ip = ipaddress.ip_address(ioc.strip())
        return ip.version == 4
    except ValueError:
        return False


def is_ipv6(ioc: str) -> bool:
    """Check if IOC is a valid IPv6 address"""
    try:
        ip = ipaddress.ip_address(ioc.strip())
        return ip.version == 6
    except ValueError:
        return False


def is_domain(ioc: str) -> bool:
    """Check if IOC is a valid domain name"""
    ioc = ioc.strip().lower()
    domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    return bool(re.match(domain_regex, ioc))


def is_url(ioc: str) -> bool:
    """Check if IOC is a valid URL"""
    ioc = ioc.strip().lower()
    url_regex = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(url_regex, ioc))


def is_hash(ioc: str) -> Optional[str]:
    """
    Check if IOC is a valid hash (MD5, SHA1, SHA256)
    Returns hash type if valid, None otherwise
    """
    clean_ioc = ioc.strip().lower()
    hash_patterns = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        128: 'sha512'
    }
    
    if len(clean_ioc) in hash_patterns:
        if all(c in '0123456789abcdef' for c in clean_ioc):
            return hash_patterns[len(clean_ioc)]
    
    return None


def detect_ioc_type(ioc: str) -> str:
    """
    Detect the type of IOC and return a standardized type string
    
    Returns:
        str: One of 'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'sha512', 'unknown'
    """
    if not ioc or not isinstance(ioc, str):
        return 'unknown'
    
    ioc = ioc.strip()
    
    if not ioc:
        return 'unknown'
    
    # Check URL first (must come before domain)
    if is_url(ioc):
        return 'url'
    
    # Check IP addresses
    if is_ipv4(ioc):
        return 'ipv4'
    
    if is_ipv6(ioc):
        return 'ipv6'
    
    # Check domain
    if is_domain(ioc):
        return 'domain'
    
    # Check hash
    hash_type = is_hash(ioc)
    if hash_type:
        return hash_type
    
    return 'unknown'
