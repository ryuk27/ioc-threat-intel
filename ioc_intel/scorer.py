"""IOC Risk Scoring Module"""

from typing import Dict, Any


def calculate_score(enrichment_data: Dict[str, Any]) -> int:
    """
    Calculate a composite risk score (0-100) based on enrichment data
    
    Args:
        enrichment_data: Dictionary containing threat intelligence data
        
    Returns:
        int: Risk score from 0-100
    """
    score = 0
    
    # VirusTotal scoring
    if 'vt_positives' in enrichment_data:
        positives = enrichment_data['vt_positives']
        if positives >= 5:
            score += 80
        elif positives >= 3:
            score += 60
        elif positives >= 1:
            score += 30
    
    if 'vt_suspicious' in enrichment_data:
        suspicious = enrichment_data['vt_suspicious']
        score += min(suspicious * 2, 20)
    
    # AbuseIPDB scoring
    if 'abuse_confidence' in enrichment_data:
        confidence = enrichment_data['abuse_confidence']
        score += int(confidence * 0.8)
    
    if 'total_reports' in enrichment_data:
        reports = enrichment_data['total_reports']
        score += min(reports * 0.5, 20)
    
    # Feodo Tracker scoring
    if enrichment_data.get('feodo_listed', False):
        score += 30
    
    # URLhaus scoring
    if enrichment_data.get('urlhaus_listed', False):
        score += 25
    
    # OTX scoring
    if 'otx_pulse_count' in enrichment_data:
        otx_pulses = enrichment_data['otx_pulse_count']
        score += min(otx_pulses * 5, 30)
    
    # Shodan scoring
    if 'shodan_vulnerabilities' in enrichment_data:
        vulns = enrichment_data['shodan_vulnerabilities']
        score += min(len(vulns) * 10, 25)
    
    # Cap at 100
    return min(100, int(score))


def get_risk_level(score: int) -> str:
    """
    Convert risk score to severity level
    
    Args:
        score: Risk score from 0-100
        
    Returns:
        str: One of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'
    """
    if score >= 80:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    elif score >= 15:
        return 'LOW'
    else:
        return 'CLEAN'
