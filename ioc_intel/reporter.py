"""Report Generation and Formatting Module"""

from datetime import datetime
from typing import Dict, Any, List
from .scorer import get_risk_level


def generate_report(
    results: List[Dict[str, Any]],
    output_file: str,
    timestamp: bool = True
) -> None:
    """
    Generate a professional markdown report from IOC enrichment results
    
    Args:
        results: List of IOC enrichment results
        output_file: Path to save the report
        timestamp: Include timestamp in report (default: True)
    """
    if not results:
        print("[!] No results to report")
        return
    
    with open(output_file, 'w') as f:
        # Header
        f.write("# IOC Threat Intelligence Report\n")
        f.write("=" * 80 + "\n\n")
        
        if timestamp:
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        
        # Aggregate results and calculate scores
        ioc_summaries = _aggregate_ioc_results(results)
        
        # Process each IOC
        for idx, ioc_summary in enumerate(ioc_summaries, 1):
            _write_ioc_section(f, idx, ioc_summary)
        
        # Summary section
        _write_summary_section(f, ioc_summaries)
    
    print(f"[+] Report generated: {output_file}")


def _aggregate_ioc_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Aggregate results by IOC and calculate composite scores
    
    Args:
        results: Raw enrichment results
        
    Returns:
        List of aggregated IOC summaries
    """
    ioc_map = {}
    
    for result in results:
        ioc = result.get('ioc', 'unknown')
        ioc_type = result.get('ioc_type', 'unknown')
        
        if ioc not in ioc_map:
            ioc_map[ioc] = {
                'ioc': ioc,
                'ioc_type': ioc_type,
                'sources': {},
                'risk_score': 0,
                'risk_level': 'CLEAN'
            }
        
        # Store source results
        source = result.get('source', 'unknown')
        ioc_map[ioc]['sources'][source] = result
    
    # Calculate risk scores
    for ioc_data in ioc_map.values():
        score = _calculate_composite_score(ioc_data['sources'])
        ioc_data['risk_score'] = score
        ioc_data['risk_level'] = get_risk_level(score)
    
    # Sort by risk score (highest first)
    return sorted(ioc_map.values(), key=lambda x: -x['risk_score'])


def _calculate_composite_score(sources: Dict[str, Dict[str, Any]]) -> int:
    """
    Calculate composite risk score from multiple sources
    
    Args:
        sources: Dictionary of source results
        
    Returns:
        int: Composite risk score 0-100
    """
    score = 0
    
    # VirusTotal
    vt = sources.get('VirusTotal', {})
    if vt.get('available'):
        malicious = vt.get('malicious', 0)
        suspicious = vt.get('suspicious', 0)
        
        if malicious >= 5:
            score += 75
        elif malicious >= 3:
            score += 50
        elif malicious >= 1:
            score += 25
        
        score += min(suspicious * 2, 15)
    
    # AbuseIPDB
    abuse = sources.get('AbuseIPDB', {})
    if abuse.get('available'):
        confidence = abuse.get('abuse_confidence', 0)
        score += int(confidence * 0.6)
    
    # Feodo Tracker
    if sources.get('Feodo Tracker', {}).get('listed'):
        score += 30
    
    # URLhaus
    if sources.get('URLhaus', {}).get('listed'):
        score += 25
    
    # Cap at 100
    return min(100, score)


def _write_ioc_section(f, idx: int, ioc_summary: Dict[str, Any]) -> None:
    """Write a single IOC analysis section to the report"""
    f.write(f"## [{idx}] IOC: {ioc_summary['ioc']}\n\n")
    f.write(f"**Type:** {ioc_summary['ioc_type'].upper()}\n\n")
    f.write(f"**Risk Score:** {ioc_summary['risk_score']}/100 — **{ioc_summary['risk_level']}**\n\n")
    
    f.write("### Threat Intelligence\n\n")
    
    # VirusTotal
    vt = ioc_summary['sources'].get('VirusTotal', {})
    if vt.get('available'):
        f.write("**VirusTotal:**\n")
        f.write(f"- Malicious: {vt.get('malicious', 0)}/72\n")
        f.write(f"- Suspicious: {vt.get('suspicious', 0)}/72\n")
        if vt.get('threat_categories'):
            f.write(f"- Categories: {', '.join(vt['threat_categories'])}\n")
        f.write("\n")
    
    # AbuseIPDB
    abuse = ioc_summary['sources'].get('AbuseIPDB', {})
    if abuse.get('available'):
        f.write("**AbuseIPDB:**\n")
        f.write(f"- Confidence Score: {abuse.get('abuse_confidence', 0)}%\n")
        f.write(f"- Total Reports: {abuse.get('total_reports', 0)}\n")
        f.write(f"- Country: {abuse.get('country', 'Unknown')}\n")
        f.write(f"- ISP: {abuse.get('isp', 'Unknown')}\n")
        f.write("\n")
    
    # Feodo Tracker
    feodo = ioc_summary['sources'].get('Feodo Tracker', {})
    if feodo.get('available'):
        if feodo.get('listed'):
            f.write("**Feodo Tracker:**\n")
            f.write(f"- [!] LISTED -- Known Botnet C2\n")
            f.write(f"- Malware: {feodo.get('malware', 'Unknown')}\n")
            f.write(f"- Status: {feodo.get('status', 'Unknown')}\n")
            f.write("\n")
    
    # URLhaus
    urlhaus = ioc_summary['sources'].get('URLhaus', {})
    if urlhaus.get('available'):
        if urlhaus.get('listed'):
            f.write("**URLhaus:**\n")
            f.write(f"- [!] LISTED -- Malware Infrastructure\n")
            f.write(f"- URL Count: {urlhaus.get('url_count', 0)}\n")
            if urlhaus.get('tags'):
                f.write(f"- Tags: {', '.join(urlhaus['tags'])}\n")
            f.write("\n")
    
    # OTX
    otx = ioc_summary['sources'].get('OTX', {})
    if otx.get('available') and otx.get('pulse_count', 0) > 0:
        f.write("**AlienVault OTX:**\n")
        f.write(f"- Pulse Count: {otx.get('pulse_count', 0)}\n")
        f.write("\n")
    
    f.write("---\n\n")


def _write_summary_section(f, ioc_summaries: List[Dict[str, Any]]) -> None:
    """Write the summary section at the end of the report"""
    f.write("# Summary\n\n")
    f.write(f"**Total IOCs Analyzed:** {len(ioc_summaries)}\n\n")
    
    # Risk level breakdown
    critical = sum(1 for x in ioc_summaries if x['risk_level'] == 'CRITICAL')
    high = sum(1 for x in ioc_summaries if x['risk_level'] == 'HIGH')
    medium = sum(1 for x in ioc_summaries if x['risk_level'] == 'MEDIUM')
    low = sum(1 for x in ioc_summaries if x['risk_level'] == 'LOW')
    clean = sum(1 for x in ioc_summaries if x['risk_level'] == 'CLEAN')
    
    f.write("**Risk Level Breakdown:**\n\n")
    f.write(f"| Level | Count |\n")
    f.write(f"|-------|-------|\n")
    f.write(f"| CRITICAL | {critical} |\n")
    f.write(f"| HIGH | {high} |\n")
    f.write(f"| MEDIUM | {medium} |\n")
    f.write(f"| LOW | {low} |\n")
    f.write(f"| CLEAN | {clean} |\n\n")
    
    # Recommendations
    f.write("## Recommendations\n\n")
    
    if critical > 0 or high > 0:
        f.write("[!] IMMEDIATE ACTION REQUIRED\n")
        f.write("- Block detected malicious IOCs at perimeter\n")
        f.write("- Alert security team for incident response\n")
        f.write("- Isolate affected endpoints\n\n")
    
    if medium > 0:
        f.write("[*] ELEVATED MONITORING\n")
        f.write("- Increase logging for medium-risk IOCs\n")
        f.write("- Investigate potential indicators of compromise\n\n")
    
    if clean > 0 and (critical > 0 or high > 0):
        f.write("[+] APPROVED IOCs\n")
        f.write("- Clean IOCs can be trusted for normal operations\n\n")


def generate_summary_stats(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate summary statistics from results
    
    Args:
        results: List of IOC enrichment results
        
    Returns:
        Dict with summary statistics
    """
    ioc_summaries = _aggregate_ioc_results(results)
    
    risk_levels = {}
    for summary in ioc_summaries:
        level = summary['risk_level']
        risk_levels[level] = risk_levels.get(level, 0) + 1
    
    return {
        'total_iocs': len(ioc_summaries),
        'risk_breakdown': risk_levels,
        'avg_risk_score': sum(x['risk_score'] for x in ioc_summaries) / len(ioc_summaries) if ioc_summaries else 0,
        'max_risk_score': max((x['risk_score'] for x in ioc_summaries), default=0),
        'min_risk_score': min((x['risk_score'] for x in ioc_summaries), default=0),
    }
