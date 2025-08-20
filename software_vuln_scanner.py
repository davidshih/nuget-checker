#!/usr/bin/env python3
"""
General Software Vulnerability Scanner
Searches for vulnerabilities in various software products using multiple databases.
Supports software like Adobe, Microsoft, Cisco, etc.
"""

import argparse
import sys
import requests
import json
import csv
import time
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

class Colors:
    """Terminal color definitions using ANSI escape codes"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def error(text: str) -> str:
        return f"{Colors.RED}{Colors.BOLD}{text}{Colors.RESET}"
    
    @staticmethod
    def success(text: str) -> str:
        return f"{Colors.GREEN}{Colors.BOLD}{text}{Colors.RESET}"
    
    @staticmethod
    def warning(text: str) -> str:
        return f"{Colors.YELLOW}{text}{Colors.RESET}"
    
    @staticmethod
    def info(text: str) -> str:
        return f"{Colors.CYAN}{text}{Colors.RESET}"

class SoftwareVulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Software-Vulnerability-Scanner/1.0'
        })
        
        # Common vendor mappings
        self.vendor_mappings = {
            'adobe': ['adobe', 'adobe_systems'],
            'microsoft': ['microsoft'],
            'cisco': ['cisco'],
            'canonical': ['canonical'],
            'citrix': ['citrix'],
            'veeam': ['veeam'],
            'nmap': ['nmap', 'insecure.org'],
            'ip blue': ['ip_blue', 'ipblue'],
            'simon tatham': ['simon_tatham', 'putty'],
            'codetwo': ['codetwo', 'code_two'],
            'sharevault': ['sharevault', 'share_vault']
        }
    
    def parse_software_string(self, software_string: str) -> Tuple[str, str, str]:
        """
        Parse software string to extract vendor, product, and version
        Example: "Adobe Creative Cloud desktop app 6 (6.7)" -> ("Adobe", "Creative Cloud desktop app", "6.7")
        """
        # Remove leading/trailing whitespace
        software_string = software_string.strip()
        
        # Common patterns
        patterns = [
            # Pattern: "Vendor Product Major (Full.Version)"
            r'^(.+?)\s+(\d+)\s*\((\d+(?:\.\d+)*)\)$',
            # Pattern: "Vendor Product (Version)"
            r'^(.+?)\s*\((\d+(?:\.\d+)*)\)$',
            # Pattern: "Vendor Product Version"
            r'^(.+?)\s+(\d+(?:\.\d+)*)$'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, software_string)
            if match:
                if len(match.groups()) == 3:
                    # Pattern with major version and full version
                    product_with_vendor = match.group(1)
                    version = match.group(3)  # Use full version
                else:
                    # Pattern without major version
                    product_with_vendor = match.group(1)
                    version = match.group(2)
                
                # Split vendor and product
                # Common vendor names
                vendor_keywords = ['Adobe', 'Microsoft', 'Cisco', 'Canonical', 'Citrix', 
                                 'Veeam', 'Nmap', 'IP blue', 'Simon Tatham', 'CodeTwo', 
                                 'ShareVault']
                
                vendor = ""
                product = product_with_vendor
                
                for vk in vendor_keywords:
                    if product_with_vendor.lower().startswith(vk.lower()):
                        vendor = vk
                        product = product_with_vendor[len(vk):].strip()
                        break
                
                if not vendor:
                    # Try to extract vendor from first word
                    parts = product_with_vendor.split(' ', 1)
                    if len(parts) > 1:
                        vendor = parts[0]
                        product = parts[1]
                    else:
                        vendor = "Unknown"
                        product = product_with_vendor
                
                return vendor, product, version
        
        # If no pattern matches, return as is
        return "Unknown", software_string, "Unknown"
    
    def search_nvd(self, vendor: str, product: str, version: str) -> List[Dict]:
        """Search NVD (National Vulnerability Database)"""
        vulnerabilities = []
        
        try:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Try different search strategies
            search_queries = [
                f"{vendor} {product}",
                product,
                f"{vendor} {product} {version}"
            ]
            
            for query in search_queries:
                params = {
                    'keywordSearch': query,
                    'resultsPerPage': 50
                }
                
                response = self.session.get(base_url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    
                    for item in data.get('vulnerabilities', []):
                        cve_data = item.get('cve', {})
                        
                        # Check if this CVE is relevant to our software
                        if self._is_relevant_cve(cve_data, vendor, product, version):
                            # Extract CVSS score
                            cvss_score = 0.0
                            severity = "UNKNOWN"
                            
                            metrics = cve_data.get('metrics', {})
                            if 'cvssMetricV31' in metrics:
                                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 0.0)
                                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                            elif 'cvssMetricV30' in metrics:
                                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 0.0)
                                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                            elif 'cvssMetricV2' in metrics:
                                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 0.0)
                                severity = self._convert_cvss_v2_severity(cvss_score)
                            
                            # Extract affected versions
                            affected_versions = self._extract_affected_versions(cve_data)
                            
                            vulnerabilities.append({
                                'source': 'NVD',
                                'cve_id': cve_data.get('id', 'N/A'),
                                'cvss_score': cvss_score,
                                'severity': severity,
                                'description': cve_data.get('descriptions', [{}])[0].get('value', 'N/A'),
                                'link': f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id', '')}",
                                'affected_versions': affected_versions,
                                'vendor': vendor,
                                'product': product,
                                'version': version
                            })
                
                # Rate limiting
                time.sleep(0.5)
                
                # If we found vulnerabilities, don't try other queries
                if vulnerabilities:
                    break
                    
        except Exception as e:
            print(f"  ❌ NVD search error: {e}")
        
        return vulnerabilities
    
    def _is_relevant_cve(self, cve_data: Dict, vendor: str, product: str, version: str) -> bool:
        """Check if CVE is relevant to the software"""
        description = cve_data.get('descriptions', [{}])[0].get('value', '').lower()
        
        # Check vendor and product in description
        vendor_lower = vendor.lower()
        product_lower = product.lower()
        
        # Check vendor aliases
        vendor_aliases = self.vendor_mappings.get(vendor_lower, [vendor_lower])
        
        vendor_found = any(alias in description for alias in vendor_aliases)
        
        # Check product (be flexible with product name matching)
        product_keywords = product_lower.split()
        product_found = any(keyword in description for keyword in product_keywords if len(keyword) > 3)
        
        # Check configurations for CPE matches
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_match = node.get('cpeMatch', [])
                for cpe in cpe_match:
                    criteria = cpe.get('criteria', '').lower()
                    # Check if vendor and product appear in CPE
                    if any(alias in criteria for alias in vendor_aliases):
                        # Check version if specified
                        if self._check_version_in_cpe(cpe, version):
                            return True
        
        return vendor_found and product_found
    
    def _check_version_in_cpe(self, cpe_entry: Dict, version: str) -> bool:
        """Check if version matches CPE entry"""
        if version == "Unknown":
            return True  # If no version specified, consider it a match
        
        # Extract version from CPE criteria
        criteria = cpe_entry.get('criteria', '')
        cpe_parts = criteria.split(':')
        
        if len(cpe_parts) >= 6:
            cpe_version = cpe_parts[5]
            if cpe_version == version or cpe_version == '*':
                return True
        
        # Check version ranges
        version_start = cpe_entry.get('versionStartIncluding')
        version_end = cpe_entry.get('versionEndIncluding')
        version_end_excl = cpe_entry.get('versionEndExcluding')
        
        try:
            # Simple version comparison (may need more sophisticated logic)
            if version_start and version >= version_start:
                if version_end and version <= version_end:
                    return True
                elif version_end_excl and version < version_end_excl:
                    return True
                elif not version_end and not version_end_excl:
                    return True
        except:
            # If version comparison fails, be conservative
            return True
        
        return False
    
    def _extract_affected_versions(self, cve_data: Dict) -> str:
        """Extract affected versions from CVE data"""
        affected_versions = []
        
        # Check configurations
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_match = node.get('cpeMatch', [])
                for cpe in cpe_match:
                    version_info = []
                    
                    if cpe.get('versionStartIncluding'):
                        version_info.append(f">= {cpe.get('versionStartIncluding')}")
                    if cpe.get('versionEndIncluding'):
                        version_info.append(f"<= {cpe.get('versionEndIncluding')}")
                    if cpe.get('versionEndExcluding'):
                        version_info.append(f"< {cpe.get('versionEndExcluding')}")
                    
                    if version_info:
                        affected_versions.append(" ".join(version_info))
        
        # Also check description for version information
        description = cve_data.get('descriptions', [{}])[0].get('value', '')
        version_patterns = [
            r'before\s+(?:version\s+)?(\d+(?:\.\d+)*)',
            r'prior\s+to\s+(?:version\s+)?(\d+(?:\.\d+)*)',
            r'versions?\s+(\d+(?:\.\d+)*)\s+and\s+(?:earlier|before)',
            r'through\s+(?:version\s+)?(\d+(?:\.\d+)*)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            for match in matches:
                affected_versions.append(f"< {match}")
        
        return ", ".join(affected_versions) if affected_versions else "Check CVE details"
    
    def _convert_cvss_v2_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity level"""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def search_mitre(self, vendor: str, product: str, version: str) -> List[Dict]:
        """Search MITRE CVE database"""
        vulnerabilities = []
        
        try:
            # MITRE search is typically done through NVD
            # This is a placeholder for MITRE-specific searches if needed
            pass
        except Exception as e:
            print(f"  ❌ MITRE search error: {e}")
        
        return vulnerabilities
    
    def check_software_vulnerabilities(self, software_list: List[str]) -> List[Dict]:
        """Check vulnerabilities for a list of software"""
        all_vulnerabilities = []
        
        print(f"\n{Colors.info('🔍 Starting software vulnerability scan...')}")
        print(f"{Colors.info('━' * 60)}\n")
        
        for software in software_list:
            software = software.strip()
            if not software:
                continue
            
            # Parse software string
            vendor, product, version = self.parse_software_string(software)
            
            print(f"{Colors.BOLD}📦 Checking: {software}{Colors.RESET}")
            print(f"   Vendor: {vendor}")
            print(f"   Product: {product}")
            print(f"   Version: {version}")
            
            # Search for vulnerabilities
            vulnerabilities = self.search_nvd(vendor, product, version)
            
            if vulnerabilities:
                print(f"   {Colors.error(f'⚠️  Found {len(vulnerabilities)} vulnerabilities')}")
            else:
                print(f"   {Colors.success('✅ No vulnerabilities found')}")
            
            all_vulnerabilities.extend(vulnerabilities)
            print()
        
        # Sort by CVSS score (high to low)
        all_vulnerabilities.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        return all_vulnerabilities
    
    def display_results(self, vulnerabilities: List[Dict], detailed: bool = False):
        """Display vulnerability results"""
        if not vulnerabilities:
            print(Colors.success("\n✅ No vulnerabilities found in the scanned software!"))
            return
        
        print(f"\n{Colors.error('🚨 VULNERABILITIES FOUND')}")
        print("=" * 80)
        
        # Group by software
        software_groups = {}
        for vuln in vulnerabilities:
            key = f"{vuln['vendor']} {vuln['product']} {vuln['version']}"
            if key not in software_groups:
                software_groups[key] = []
            software_groups[key].append(vuln)
        
        for software, vulns in software_groups.items():
            print(f"\n{Colors.BOLD}{Colors.CYAN}📦 {software}{Colors.RESET}")
            print(f"   {Colors.BOLD}Found {len(vulns)} vulnerabilities{Colors.RESET}")
            print("   " + "-" * 60)
            
            for i, vuln in enumerate(vulns, 1):
                severity_color = self._get_severity_color(vuln['severity'])
                
                print(f"\n   [{i}] {Colors.BOLD}{vuln['cve_id']}{Colors.RESET}")
                print(f"       {Colors.BOLD}CVSS Score:{Colors.RESET} {vuln['cvss_score']}")
                print(f"       {Colors.BOLD}Severity:{Colors.RESET} {severity_color}{vuln['severity']}{Colors.RESET}")
                print(f"       {Colors.BOLD}Affected Versions:{Colors.RESET} {vuln['affected_versions']}")
                
                if detailed:
                    desc = vuln['description']
                    if len(desc) > 200:
                        desc = desc[:200] + "..."
                    print(f"       {Colors.BOLD}Summary:{Colors.RESET} {desc}")
                
                print(f"       {Colors.BOLD}Link:{Colors.RESET} {Colors.CYAN}{vuln['link']}{Colors.RESET}")
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color based on severity"""
        severity_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.MAGENTA,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'UNKNOWN': Colors.CYAN
        }
        return severity_colors.get(severity.upper(), Colors.WHITE)
    
    def export_results(self, vulnerabilities: List[Dict], output_file: str, format_type: str = 'json'):
        """Export results to file"""
        try:
            if format_type.lower() == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        'scan_time': datetime.now().isoformat(),
                        'total_vulnerabilities': len(vulnerabilities),
                        'vulnerabilities': vulnerabilities
                    }, f, indent=2, ensure_ascii=False)
            
            elif format_type.lower() == 'csv':
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    if vulnerabilities:
                        fieldnames = ['vendor', 'product', 'version', 'cve_id', 'cvss_score', 
                                    'severity', 'affected_versions', 'description', 'link']
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        for vuln in vulnerabilities:
                            row = {k: vuln.get(k, '') for k in fieldnames}
                            writer.writerow(row)
            
            elif format_type.lower() == 'html':
                html_content = self._generate_html_report(vulnerabilities)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            
            print(Colors.success(f"\n✅ Results exported to: {output_file}"))
            
        except Exception as e:
            print(Colors.error(f"\n❌ Export failed: {e}"))
    
    def _generate_html_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Software Vulnerability Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .header h1 {{ color: #2c3e50; margin-bottom: 10px; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .vulnerability {{ border: 1px solid #ddd; margin-bottom: 20px; border-radius: 5px; overflow: hidden; }}
        .vuln-header {{ padding: 15px; font-weight: bold; background: #f8f9fa; }}
        .vuln-body {{ padding: 20px; }}
        .critical {{ border-left: 5px solid #dc3545; }}
        .high {{ border-left: 5px solid #fd7e14; }}
        .medium {{ border-left: 5px solid #ffc107; }}
        .low {{ border-left: 5px solid #28a745; }}
        .severity-critical {{ background-color: #dc3545; color: white; }}
        .severity-high {{ background-color: #fd7e14; color: white; }}
        .severity-medium {{ background-color: #ffc107; color: black; }}
        .severity-low {{ background-color: #28a745; color: white; }}
        .badge {{ padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 10px; }}
        .software-group {{ margin-bottom: 30px; }}
        .software-title {{ background: #343a40; color: white; padding: 10px 15px; margin: 0; font-size: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Software Vulnerability Scan Report</h1>
            <p>Generated on: {scan_time}</p>
        </div>
        
        <div class="summary">
            <h3>📊 Scan Summary</h3>
            <p><strong>Total Vulnerabilities Found:</strong> {total_vulns}</p>
            <p><strong>Affected Software:</strong> {affected_software}</p>
            <p><strong>Severity Distribution:</strong> {severity_dist}</p>
        </div>
        
        <div class="vulnerabilities">
            <h3>🚨 Vulnerability Details</h3>
            {vulnerability_content}
        </div>
    </div>
</body>
</html>
"""
        
        # Group vulnerabilities by software
        software_groups = {}
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        
        for vuln in vulnerabilities:
            key = f"{vuln['vendor']} {vuln['product']} {vuln['version']}"
            if key not in software_groups:
                software_groups[key] = []
            software_groups[key].append(vuln)
            severity_counts[vuln.get('severity', 'UNKNOWN')] += 1
        
        # Generate vulnerability content
        vuln_html = ""
        for software, vulns in software_groups.items():
            vuln_html += f"""
            <div class="software-group">
                <h4 class="software-title">📦 {software}</h4>
                <table>
                    <tr>
                        <th>CVE ID</th>
                        <th>CVSS Score</th>
                        <th>Severity</th>
                        <th>Affected Versions</th>
                        <th>Link</th>
                    </tr>
            """
            
            for vuln in vulns:
                severity = vuln.get('severity', 'UNKNOWN').lower()
                vuln_html += f"""
                    <tr>
                        <td><strong>{vuln['cve_id']}</strong></td>
                        <td>{vuln['cvss_score']}</td>
                        <td><span class="badge severity-{severity}">{vuln['severity']}</span></td>
                        <td>{vuln['affected_versions']}</td>
                        <td><a href="{vuln['link']}" target="_blank">View Details</a></td>
                    </tr>
                """
            
            vuln_html += "</table></div>"
        
        # Generate severity distribution
        severity_dist = ", ".join([f"{k}: {v}" for k, v in severity_counts.items() if v > 0])
        
        return html_template.format(
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulns=len(vulnerabilities),
            affected_software=len(software_groups),
            severity_dist=severity_dist,
            vulnerability_content=vuln_html
        )

def main():
    parser = argparse.ArgumentParser(
        description='Software Vulnerability Scanner - Check for CVEs in various software products',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -s "Adobe Creative Cloud desktop app 6 (6.7),Microsoft Edge 134 (134.0)"
  %(prog)s -f software_list.txt -o report.html --format html
  %(prog)s --test  # Run with test examples
  
Supported Input Formats:
  - Comma-separated: "Software1 Version,Software2 Version"
  - File with one software per line
  - Software format: "Vendor Product Major (Full.Version)" or "Vendor Product Version"
        """
    )
    
    parser.add_argument('-s', '--software', 
                       help='Software list, comma-separated')
    parser.add_argument('-f', '--file', 
                       help='Read software list from file (one per line)')
    parser.add_argument('-o', '--output', 
                       help='Output file path')
    parser.add_argument('--format', 
                       choices=['json', 'csv', 'html'],
                       default='json',
                       help='Output format (default: json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed vulnerability information')
    parser.add_argument('--test', action='store_true',
                       help='Run with test examples')
    
    args = parser.parse_args()
    
    # Collect software list
    software_list = []
    
    if args.test:
        # Use provided test examples
        software_list = [
            "Adobe Creative Cloud desktop app 6 (6.7)",
            "CodeTwo Active Directory Photos 1 (1.4)",
            "IP blue Software Solutions VTGO-PC Lite 2 (2.15)",
            "Microsoft Edge 134 (134.0)",
            "Microsoft SQL Server Integration Services Projects 3 (3.16)",
            "Microsoft Windows Performance Toolkit 10 (10.1)",
            "Nmap Npcap 1 (1.60)",
            "ShareVault Reader 5 (5.0)",
            "Simon Tatham PuTTY O.x (0.76)",
            "Veeam Agent for Microsoft Windows 6 (6.3)",
            "Adobe Creative Cloud desktop app 5 (5.8)",
            "Adobe Media Encoder CC 2023 (23.2)",
            "Adobe Photoshop CC 2023 (24.6)",
            "Canonical Ubuntu 20 (20.04)",
            "Cisco AnyConnect Secure Mobility Client 4 (4.10)",
            "Cisco Universal Forwarder 9 (9.1)",
            "Citrix Workspace app for Windows 24 (24.5)",
            "Microsoft ADO.Net Entity Framework Tools 6.2",
            "Microsoft Office 32-bit Components 2016 (16.0)"
        ]
        print(Colors.info("🧪 Running with test examples..."))
    elif args.software:
        # Parse comma-separated list
        software_list = [s.strip() for s in args.software.split(',') if s.strip()]
    elif args.file:
        # Read from file
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        software_list.append(line)
        except Exception as e:
            print(Colors.error(f"❌ Failed to read file: {e}"))
            sys.exit(1)
    else:
        print(Colors.error("❌ No input specified. Use -s, -f, or --test"))
        parser.print_help()
        sys.exit(1)
    
    if not software_list:
        print(Colors.error("❌ No software to scan"))
        sys.exit(1)
    
    # Print banner
    print(Colors.CYAN + Colors.BOLD)
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║           Software Vulnerability Scanner v1.0                ║")
    print("║              CVE Security Assessment Tool                    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(Colors.RESET)
    
    print(f"📋 Scanning {len(software_list)} software products...")
    
    # Create scanner and check vulnerabilities
    scanner = SoftwareVulnerabilityScanner()
    vulnerabilities = scanner.check_software_vulnerabilities(software_list)
    
    # Display results
    scanner.display_results(vulnerabilities, detailed=args.verbose)
    
    # Export results if requested
    if args.output:
        scanner.export_results(vulnerabilities, args.output, args.format)
    
    # Summary
    print(f"\n{Colors.info('━' * 60)}")
    print(f"{Colors.BOLD}📊 SCAN COMPLETE{Colors.RESET}")
    print(f"   Total software scanned: {len(software_list)}")
    print(f"   Total vulnerabilities found: {len(vulnerabilities)}")
    
    if vulnerabilities:
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"   Severity breakdown:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            if severity_counts.get(sev, 0) > 0:
                print(f"     - {sev}: {severity_counts[sev]}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Colors.warning("\n⚠️  Scan interrupted by user"))
        sys.exit(130)
    except Exception as e:
        print(Colors.error(f"\n❌ Fatal error: {e}"))
        sys.exit(1)