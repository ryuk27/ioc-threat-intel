"""
IOC Threat Intelligence Engine — Main Entry Point

Analyzes IPs, domains, URLs, and file hashes against multiple threat intelligence sources
with automatic IOC type detection, risk scoring, and MITRE ATT&CK mapping.
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
from ioc_intel.validator import detect_ioc_type
from ioc_intel.enricher import enrich_ioc
from ioc_intel.scorer import calculate_score, get_risk_level
from ioc_intel.mitre_mapper import map_to_mitre
from ioc_intel.reporter import generate_report, generate_summary_stats


def print_banner():
    """Print application banner"""
    print("\n" + "=" * 80)
    print("  IOC THREAT INTELLIGENCE ENGINE")
    print("  Automated Multi-Source Threat Analysis and MITRE ATT&CK Mapping")
    print("=" * 80 + "\n")


def process_single_ioc(ioc: str, output_to_screen: bool = True) -> dict:
    """
    Process a single IOC and return enriched data
    
    Args:
        ioc: IOC value to analyze
        output_to_screen: Print results to console
        
    Returns:
        Dict with enrichment results
    """
    # Detect IOC type
    ioc_type = detect_ioc_type(ioc)
    
    if ioc_type == 'unknown':
        if output_to_screen:
            print(f"[-] Invalid IOC: {ioc} (unable to detect type)")
        return None
    
    if output_to_screen:
        print(f"[*] Analyzing: {ioc} ({ioc_type})")
    
    # Enrich the IOC
    enrichment = enrich_ioc(ioc, ioc_type)
    
    # Extract all enrichment data for scoring
    enrichment_data = {}
    for source, data in enrichment.get('sources', {}).items():
        for key, value in data.items():
            if key not in ['source', 'ioc', 'ioc_type', 'available', 'error']:
                enrichment_data[key] = value
    
    # Calculate risk score
    risk_score = calculate_score(enrichment_data)
    risk_level = get_risk_level(risk_score)
    
    # Map to MITRE technique
    mitre_mapping = map_to_mitre(ioc_type, enrichment_data)
    
    # Compile result
    result = {
        'ioc': ioc,
        'ioc_type': ioc_type,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'mitre': mitre_mapping,
        'enrichment': enrichment,
        'sources': enrichment.get('sources', {})
    }
    
    if output_to_screen:
        print_ioc_result(result)
    
    return result


def print_ioc_result(result: dict):
    """Print a formatted IOC analysis result to console"""
    print(f"\n  IOC: {result['ioc']}")
    print(f"  Type: {result['ioc_type'].upper()}")
    print(f"  Risk Score: {result['risk_score']}/100 -- {result['risk_level']}")
    
    print(f"\n  Threat Intelligence:")
    
    # VirusTotal
    vt = result['sources'].get('VirusTotal', {})
    if vt.get('available'):
        print(f"    [+] VirusTotal: {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious")
    
    # AbuseIPDB
    abuse = result['sources'].get('AbuseIPDB', {})
    if abuse.get('available'):
        print(f"    [+] AbuseIPDB: Confidence {abuse.get('abuse_confidence', 0)}%, {abuse.get('total_reports', 0)} reports")
    
    # Feodo Tracker
    feodo = result['sources'].get('Feodo Tracker', {})
    if feodo.get('listed'):
        print(f"    [!] Feodo Tracker: LISTED -- Known Botnet C2 ({feodo.get('malware', 'Unknown')})")
    
    # URLhaus
    urlhaus = result['sources'].get('URLhaus', {})
    if urlhaus.get('listed'):
        print(f"    [!] URLhaus: LISTED -- Malware Infrastructure ({urlhaus.get('url_count', 0)} URLs)")
    
    # MITRE
    mitre = result['mitre']
    print(f"\n  MITRE ATT&CK:")
    print(f"    Technique: {mitre['technique_id']} -- {mitre['technique_name']}")
    print(f"    Tactic: {mitre['tactic']}")
    
    # Verdict
    if result['risk_level'] in ['CRITICAL', 'HIGH']:
        verdict = "[!] MALICIOUS -- Recommend immediate block"
    elif result['risk_level'] == 'MEDIUM':
        verdict = "[*] SUSPICIOUS -- Recommend investigation"
    elif result['risk_level'] == 'LOW':
        verdict = "[i] LOW RISK -- Monitor for updates"
    else:
        verdict = "[+] CLEAN -- No immediate action recommended"
    
    print(f"\n  Verdict: {verdict}\n")


def main():
    """Main entry point with command-line argument handling"""
    parser = argparse.ArgumentParser(
        description='IOC Threat Intelligence Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --ioc 8.8.8.8
  python main.py --file iocs.txt --output report.md
  python main.py --file iocs.txt --output report.md --quiet
        """
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--ioc', help='Single IOC to analyze')
    input_group.add_argument('--file', help='File containing IOCs (one per line)')
    
    parser.add_argument(
        '--output',
        help='Output file for report (default: stdout)',
        default=None
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress console output during processing'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='IOC Threat Intel Engine v1.0'
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print_banner()
    
    # Process IOCs
    results = []
    
    if args.ioc:
        # Single IOC
        result = process_single_ioc(args.ioc, output_to_screen=not args.quiet)
        if result:
            results.append(result)
    
    else:
        # File input
        input_file = Path(args.file)
        
        if not input_file.exists():
            print(f"❌ Error: Input file not found — {args.file}")
            sys.exit(1)
        
        if not args.quiet:
            print(f"[*] Processing file: {args.file}\n")
        
        with open(input_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                ioc = line.strip()
                
                # Skip empty lines and comments
                if not ioc or ioc.startswith('#'):
                    continue
                
                result = process_single_ioc(ioc, output_to_screen=not args.quiet)
                if result:
                    results.append(result)
    
    # Generate report if output file specified
    if args.output and results:
        generate_report(results, args.output)
        
        if not args.quiet:
            # Print summary statistics
            stats = generate_summary_stats(results)
            print(f"\n[*] Summary Statistics:")
            print(f"  Total IOCs: {stats['total_iocs']}")
            print(f"  Average Risk Score: {stats['avg_risk_score']:.1f}/100")
            print(f"  Risk Breakdown: {stats['risk_breakdown']}\n")
    
    elif not args.output and not args.quiet:
        print(f"\n[i] Tip: Use --output flag to save results to a file")


if __name__ == '__main__':
    main()
