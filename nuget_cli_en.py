#!/usr/bin/env python3
"""
NuGet Package Vulnerability Scanner - Command Line Interface
Supports multiple input formats and output options
"""

import argparse
import sys
import os
import json
import csv
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests
from vulnerability_checker import VulnerabilityChecker

class Colors:
    """Terminal color definitions"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class EnhancedVulnerabilityChecker(VulnerabilityChecker):
    """Enhanced vulnerability checker that collects all findings from all sources"""
    
    def check_vulnerabilities_comprehensive(self, packages: List[str]) -> List[Dict]:
        """Check vulnerabilities from all sources and return comprehensive results"""
        all_vulnerabilities = []
        
        for package in packages:
            package = package.strip()
            if not package:
                continue
            
            name, version = self.parse_package_name(package)
            print(f"Checking package: {name} (version: {version or 'unspecified'})")
            
            # Check each source individually and collect all results
            sources_results = {}
            
            # NVD
            try:
                nvd_results = self.search_nvd(name, version)
                sources_results['NVD'] = nvd_results
                print(f"  NVD: Found {len(nvd_results)} vulnerabilities")
            except Exception as e:
                print(f"  NVD: Error - {e}")
                sources_results['NVD'] = []
            
            # OSV
            try:
                osv_results = self.search_osv(name, version)
                sources_results['OSV'] = osv_results
                print(f"  OSV: Found {len(osv_results)} vulnerabilities")
            except Exception as e:
                print(f"  OSV: Error - {e}")
                sources_results['OSV'] = []
            
            # GitHub Advisory
            try:
                github_results = self.search_github_advisory(name, version)
                sources_results['GitHub'] = github_results
                print(f"  GitHub Advisory: Found {len(github_results)} vulnerabilities")
            except Exception as e:
                print(f"  GitHub Advisory: Error - {e}")
                sources_results['GitHub'] = []
            
            # Snyk
            try:
                snyk_results = self.search_snyk(name, version)
                sources_results['Snyk'] = snyk_results
                print(f"  Snyk: Found {len(snyk_results)} vulnerabilities")
            except Exception as e:
                print(f"  Snyk: Error - {e}")
                sources_results['Snyk'] = []
            
            # Combine all results
            for source, results in sources_results.items():
                for vuln in results:
                    vuln['package'] = name
                    vuln['package_version'] = version
                    vuln['source'] = source
                    all_vulnerabilities.append(vuln)
        
        # Remove duplicates based on CVE ID and package
        seen = set()
        unique_vulnerabilities = []
        for vuln in all_vulnerabilities:
            key = (vuln.get('package'), vuln.get('cve_id'), vuln.get('source'))
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        # Sort by CVSS score (high to low)
        unique_vulnerabilities.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        return unique_vulnerabilities

class NuGetCLI:
    def __init__(self):
        self.checker = EnhancedVulnerabilityChecker()
        self.start_time = None
        
    def print_banner(self):
        """Display program banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                  NuGet Vulnerability Scanner CLI            ║
║                     Security Assessment Tool v1.0           ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
    
    def print_colored(self, text: str, color: str = Colors.WHITE, bold: bool = False):
        """Print colored text"""
        style = f"{color}{Colors.BOLD if bold else ''}"
        print(f"{style}{text}{Colors.END}")
    
    def get_severity_color(self, severity: str) -> str:
        """Get color based on severity level"""
        severity_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.MAGENTA,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'UNKNOWN': Colors.CYAN
        }
        return severity_colors.get(severity.upper(), Colors.WHITE)
    
    def parse_packages_from_file(self, file_path: str) -> List[str]:
        """Parse package list from file"""
        packages = []
        path_obj = Path(file_path)
        
        if not path_obj.exists():
            self.print_colored(f"❌ File not found: {file_path}", Colors.RED, bold=True)
            return packages
        
        try:
            if path_obj.suffix.lower() == '.json':
                # Parse packages.json or similar format
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Support multiple JSON formats
                if 'dependencies' in data:
                    # package.json format
                    for name, version in data['dependencies'].items():
                        packages.append(f"{name}.{version}")
                elif 'packages' in data:
                    # Custom format
                    packages.extend(data['packages'])
                elif isinstance(data, list):
                    # Simple array format
                    packages.extend(data)
                    
            elif path_obj.suffix.lower() == '.csv':
                # Parse CSV file
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row and not row[0].startswith('#'):  # Skip comments
                            packages.append(row[0].strip())
                            
            else:
                # Plain text file, one package per line
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):  # Skip empty lines and comments
                            packages.append(line)
                            
        except Exception as e:
            self.print_colored(f"❌ Failed to read file: {e}", Colors.RED, bold=True)
            
        return packages
    
    def scan_directory_for_packages(self, directory: str) -> List[str]:
        """Scan directory for NuGet package files"""
        packages = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            self.print_colored(f"❌ Directory not found: {directory}", Colors.RED, bold=True)
            return packages
        
        # Find .nupkg files
        nupkg_files = list(dir_path.rglob("*.nupkg"))
        packages.extend([f.name for f in nupkg_files])
        
        # Find packages.config
        config_files = list(dir_path.rglob("packages.config"))
        for config_file in config_files:
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(config_file)
                root = tree.getroot()
                
                for package in root.findall('.//package'):
                    name = package.get('id')
                    version = package.get('version')
                    if name and version:
                        packages.append(f"{name}.{version}")
                        
            except Exception as e:
                self.print_colored(f"⚠️  Failed to parse {config_file}: {e}", Colors.YELLOW)
        
        # Find .csproj files with PackageReference
        csproj_files = list(dir_path.rglob("*.csproj"))
        for csproj_file in csproj_files:
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(csproj_file)
                root = tree.getroot()
                
                for package_ref in root.findall('.//PackageReference'):
                    name = package_ref.get('Include')
                    version = package_ref.get('Version')
                    if name and version:
                        packages.append(f"{name}.{version}")
                        
            except Exception as e:
                self.print_colored(f"⚠️  Failed to parse {csproj_file}: {e}", Colors.YELLOW)
        
        return packages
    
    def display_summary(self, vulnerabilities: List[Dict], packages_count: int):
        """Display scan summary"""
        print("\n" + "="*80)
        self.print_colored("📊 SCAN SUMMARY", Colors.CYAN, bold=True)
        print("="*80)
        
        # Statistics
        total_vulns = len(vulnerabilities)
        severity_counts = {}
        sources = set()
        packages_with_vulns = set()
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            sources.add(vuln.get('source', 'Unknown'))
            packages_with_vulns.add(vuln.get('package', 'Unknown'))
        
        # Basic statistics
        print(f"📦 Packages scanned: {Colors.BOLD}{packages_count}{Colors.END}")
        print(f"🔍 Vulnerabilities found: {Colors.BOLD}{total_vulns}{Colors.END}")
        print(f"⚠️  Affected packages: {Colors.BOLD}{len(packages_with_vulns)}{Colors.END}")
        print(f"🌐 Data sources: {Colors.BOLD}{', '.join(sorted(sources))}{Colors.END}")
        
        # Severity distribution
        if severity_counts:
            print(f"\n🚨 Severity distribution:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = self.get_severity_color(severity)
                    print(f"  {color}● {severity}: {count}{Colors.END}")
        
        # Risk assessment
        risk_level = "LOW"
        risk_color = Colors.GREEN
        
        if severity_counts.get('CRITICAL', 0) > 0:
            risk_level = "CRITICAL"
            risk_color = Colors.RED
        elif severity_counts.get('HIGH', 0) > 0:
            risk_level = "HIGH"
            risk_color = Colors.MAGENTA
        elif severity_counts.get('MEDIUM', 0) > 0:
            risk_level = "MEDIUM"
            risk_color = Colors.YELLOW
        
        print(f"\n⚡ Overall risk level: {risk_color}{Colors.BOLD}{risk_level}{Colors.END}")
        
        # Execution time
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"⏱️  Scan duration: {Colors.BOLD}{duration:.2f} seconds{Colors.END}")
    
    def display_vulnerabilities(self, vulnerabilities: List[Dict], detailed: bool = False):
        """Display vulnerability details"""
        if not vulnerabilities:
            self.print_colored("✅ No known vulnerabilities found!", Colors.GREEN, bold=True)
            return
        
        print("\n" + "="*80)
        self.print_colored("🔍 VULNERABILITIES FOUND", Colors.RED, bold=True)
        print("="*80)
        
        current_package = None
        vuln_count = 0
        
        for vuln in vulnerabilities:
            package_name = vuln.get('package', 'Unknown')
            
            # Group by package
            if package_name != current_package:
                if current_package is not None:
                    print()
                current_package = package_name
                self.print_colored(f"\n📦 Package: {package_name} (v{vuln.get('package_version', 'N/A')})", 
                                 Colors.BLUE, bold=True)
                print("-" * 60)
            
            vuln_count += 1
            severity_color = self.get_severity_color(vuln.get('severity', 'UNKNOWN'))
            
            print(f"\n  [{vuln_count}] {Colors.BOLD}{vuln.get('cve_id', 'N/A')}{Colors.END}")
            print(f"      🚨 Severity: {severity_color}{Colors.BOLD}{vuln.get('severity', 'UNKNOWN')}{Colors.END}")
            print(f"      📊 CVSS Score: {Colors.BOLD}{vuln.get('cvss_score', 'N/A')}{Colors.END}")
            print(f"      🌐 Source: {Colors.BLUE}{vuln.get('source', 'Unknown')}{Colors.END}")
            
            if detailed:
                description = vuln.get('description', 'N/A')
                if len(description) > 150:
                    description = description[:150] + "..."
                print(f"      📝 Description: {description}")
            
            link = vuln.get('link', 'N/A')
            if link != 'N/A':
                print(f"      🔗 Details: {Colors.UNDERLINE}{link}{Colors.END}")
            
            print(f"      {'-'*50}")
    
    def export_results(self, vulnerabilities: List[Dict], output_file: str, format_type: str):
        """Export results to file"""
        try:
            output_path = Path(output_file)
            
            if format_type.lower() == 'json':
                # JSON format
                export_data = {
                    'scan_metadata': {
                        'scan_time': datetime.now().isoformat(),
                        'total_vulnerabilities': len(vulnerabilities),
                        'scanner_version': '1.0.0'
                    },
                    'vulnerabilities': vulnerabilities
                }
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, ensure_ascii=False, indent=2)
                    
            elif format_type.lower() == 'csv':
                # CSV format
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    if vulnerabilities:
                        writer = csv.DictWriter(f, fieldnames=vulnerabilities[0].keys())
                        writer.writeheader()
                        writer.writerows(vulnerabilities)
                        
            elif format_type.lower() == 'html':
                # HTML report
                html_content = self.generate_html_report(vulnerabilities)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                    
            self.print_colored(f"✅ Results exported to: {output_path}", Colors.GREEN, bold=True)
            
        except Exception as e:
            self.print_colored(f"❌ Export failed: {e}", Colors.RED, bold=True)
    
    def generate_html_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NuGet Vulnerability Scan Report</title>
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
        .source-badge {{ background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #6c757d; font-size: 14px; }}
        .link {{ color: #007bff; text-decoration: none; }}
        .link:hover {{ text-decoration: underline; }}
        .package-group {{ margin-bottom: 30px; }}
        .package-title {{ background: #343a40; color: white; padding: 10px 15px; margin: 0; font-size: 18px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-item {{ text-align: center; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #007bff; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NuGet Vulnerability Scan Report</h1>
            <p>Generated on: {scan_time}</p>
        </div>
        
        <div class="summary">
            <h3>📊 Scan Summary</h3>
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-number">{total_vulns}</div>
                    <div>Vulnerabilities</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{affected_packages}</div>
                    <div>Affected Packages</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{data_sources}</div>
                    <div>Data Sources</div>
                </div>
            </div>
            <p><strong>Severity Distribution:</strong> {severity_distribution}</p>
            <p><strong>Data Sources:</strong> {sources_list}</p>
        </div>
        
        <div class="vulnerabilities">
            <h3>🚨 Vulnerability Details</h3>
            {vulnerability_list}
        </div>
        
        <div class="footer">
            <p>This report was generated by NuGet Vulnerability Scanner CLI v1.0</p>
            <p>For more information, visit the project repository</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Generate vulnerability list HTML
        vuln_html = ""
        severity_counts = {}
        sources = set()
        packages = {}
        
        # Group vulnerabilities by package
        for vuln in vulnerabilities:
            package = vuln.get('package', 'Unknown')
            if package not in packages:
                packages[package] = []
            packages[package].append(vuln)
            
            severity = vuln.get('severity', 'UNKNOWN').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            sources.add(vuln.get('source', 'Unknown'))
        
        # Generate HTML for each package
        for package_name, package_vulns in packages.items():
            vuln_html += f"""
            <div class="package-group">
                <h4 class="package-title">📦 {package_name} (v{package_vulns[0].get('package_version', 'N/A')})</h4>
            """
            
            for vuln in package_vulns:
                severity = vuln.get('severity', 'UNKNOWN').lower()
                vuln_html += f"""
                <div class="vulnerability {severity}">
                    <div class="vuln-header">
                        <span class="badge severity-{severity}">{vuln.get('severity', 'UNKNOWN')}</span>
                        <span class="source-badge">{vuln.get('source', 'Unknown')}</span>
                        {vuln.get('cve_id', 'N/A')}
                    </div>
                    <div class="vuln-body">
                        <p><strong>CVSS Score:</strong> {vuln.get('cvss_score', 'N/A')}</p>
                        <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
                        <p><strong>Reference:</strong> <a href="{vuln.get('link', '#')}" target="_blank" class="link">View Details</a></p>
                    </div>
                </div>
                """
            
            vuln_html += "</div>"
        
        # Generate severity distribution string
        severity_dist = ", ".join([f"{k.upper()}: {v}" for k, v in severity_counts.items()])
        sources_list = ", ".join(sorted(sources))
        
        return html_template.format(
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulns=len(vulnerabilities),
            affected_packages=len(packages),
            data_sources=len(sources),
            severity_distribution=severity_dist,
            sources_list=sources_list,
            vulnerability_list=vuln_html
        )
    
    def run(self, args):
        """Execute main program"""
        self.start_time = time.time()
        
        if not args.quiet:
            self.print_banner()
        
        # Collect package list
        packages = []
        
        # From command line arguments
        if args.packages:
            packages.extend([pkg.strip() for pkg in args.packages.split(',')])
        
        # From file
        if args.file:
            file_packages = self.parse_packages_from_file(args.file)
            packages.extend(file_packages)
            if not args.quiet:
                self.print_colored(f"📁 Loaded {len(file_packages)} packages from file", Colors.BLUE)
        
        # From directory scan
        if args.scan_dir:
            dir_packages = self.scan_directory_for_packages(args.scan_dir)
            packages.extend(dir_packages)
            if not args.quiet:
                self.print_colored(f"📂 Found {len(dir_packages)} packages in directory", Colors.BLUE)
        
        # Remove duplicates
        packages = list(set(packages))
        
        if not packages:
            self.print_colored("❌ No packages specified for checking", Colors.RED, bold=True)
            self.print_colored("💡 Use --help to see usage instructions", Colors.YELLOW)
            return 1
        
        if not args.quiet:
            self.print_colored(f"🚀 Starting scan of {len(packages)} packages...", Colors.GREEN, bold=True)
            if args.verbose:
                print("Package list:")
                for pkg in packages:
                    print(f"  • {pkg}")
        
        # Execute vulnerability check
        try:
            vulnerabilities = self.checker.check_vulnerabilities_comprehensive(packages)
            
            # Display results
            if not args.quiet:
                self.display_vulnerabilities(vulnerabilities, detailed=args.verbose)
                self.display_summary(vulnerabilities, len(packages))
            
            # Export results
            if args.output:
                format_type = args.format or 'json'
                self.export_results(vulnerabilities, args.output, format_type)
            
            # Set exit code based on vulnerabilities found
            if args.fail_on_vuln and vulnerabilities:
                return 1
            
            return 0
            
        except KeyboardInterrupt:
            self.print_colored("\n⚠️  Scan interrupted by user", Colors.YELLOW, bold=True)
            return 130
        except Exception as e:
            self.print_colored(f"❌ Error during scan: {e}", Colors.RED, bold=True)
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

def create_sample_files():
    """Create sample files"""
    # Sample package list
    sample_packages = [
        "serilog.4.3.0",
        "newtonsoft.json.13.0.1", 
        "microsoft.aspnetcore.app.2.1.0",
        "system.text.json.6.0.0",
        "log4net.2.0.8",
        "nlog.4.7.0"
    ]
    
    # Create sample text file
    with open('sample_packages_en.txt', 'w', encoding='utf-8') as f:
        f.write("# NuGet Package List Sample\n")
        f.write("# One package per line, comments supported\n\n")
        for pkg in sample_packages:
            f.write(f"{pkg}\n")
    
    # Create sample JSON file
    sample_json = {
        "packages": sample_packages,
        "description": "Sample NuGet package list for vulnerability scanning"
    }
    
    with open('sample_packages_en.json', 'w', encoding='utf-8') as f:
        json.dump(sample_json, f, ensure_ascii=False, indent=2)
    
    print("✅ Sample files created:")
    print("  • sample_packages_en.txt")
    print("  • sample_packages_en.json")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='NuGet Package Vulnerability Scanner - Command Line Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  %(prog)s -p "serilog.4.3.0,newtonsoft.json.13.0.1"
  %(prog)s -f packages.txt -o report.json
  %(prog)s --scan-dir ./MyProject -v --format html -o report.html
  %(prog)s -p "serilog.4.3.0" --fail-on-vuln
  
Supported File Formats:
  • .txt - One package name per line
  • .json - JSON formatted package list
  • .csv - CSV formatted package list
  
Output Formats:
  • json - JSON format report
  • csv - CSV format report  
  • html - HTML format report
        """
    )
    
    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument('-p', '--packages', 
                           help='Package list, comma separated (e.g., "pkg1.1.0,pkg2.2.0")')
    input_group.add_argument('-f', '--file', 
                           help='Read package list from file (.txt, .json, .csv)')
    input_group.add_argument('--scan-dir', 
                           help='Scan directory for NuGet package files')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', 
                            help='Output file path')
    output_group.add_argument('--format', choices=['json', 'csv', 'html'],
                            help='Output format (default: json)')
    output_group.add_argument('-v', '--verbose', action='store_true',
                            help='Show detailed information')
    output_group.add_argument('-q', '--quiet', action='store_true',
                            help='Quiet mode, only show results')
    
    # Behavior options
    behavior_group = parser.add_argument_group('Behavior Options')
    behavior_group.add_argument('--fail-on-vuln', action='store_true',
                              help='Exit with non-zero code when vulnerabilities found')
    behavior_group.add_argument('--create-samples', action='store_true',
                              help='Create sample files')
    
    args = parser.parse_args()
    
    # Create sample files
    if args.create_samples:
        create_sample_files()
        return 0
    
    # Check if any input is provided
    if not any([args.packages, args.file, args.scan_dir]):
        parser.print_help()
        return 1
    
    # Execute scan
    cli = NuGetCLI()
    return cli.run(args)

if __name__ == "__main__":
    sys.exit(main())
