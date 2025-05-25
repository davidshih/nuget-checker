#!/usr/bin/env python3
"""
NuGet Package Vulnerability Scanner - Enhanced Command Line Interface
Supports multiple input formats, caching, and advanced output options
"""

import argparse
import sys
import os
import json
import csv
import time
import ast
import re
import threading
import hashlib
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from functools import lru_cache
import configparser
import sqlite3
from contextlib import contextmanager

try:
    import requests
    from tqdm import tqdm
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install: pip install requests tqdm colorama")
    sys.exit(1)

from vulnerability_checker_en import VulnerabilityChecker

@dataclass
class Config:
    """Configuration settings"""
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    max_workers: int = 5
    timeout: int = 30
    retry_attempts: int = 3
    retry_delay: float = 1.0
    proxy: Optional[str] = None
    fail_on_severity: Optional[str] = None
    exclude_sources: List[str] = None
    verbose: bool = False
    quiet: bool = False
    
    def __post_init__(self):
        if self.exclude_sources is None:
            self.exclude_sources = []

class Colors:
    """Enhanced terminal color definitions with Colorama"""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BOLD = Style.BRIGHT
    DIM = Style.DIM
    RESET = Style.RESET_ALL
    
    @staticmethod
    def error(text: str) -> str:
        return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def success(text: str) -> str:
        return f"{Fore.GREEN}{Style.BRIGHT}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def warning(text: str) -> str:
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def info(text: str) -> str:
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}"

class CacheManager:
    """SQLite-based cache manager for vulnerability data"""
    
    def __init__(self, cache_dir: Path = None, ttl_hours: int = 24):
        self.cache_dir = cache_dir or Path.home() / '.nuget-cli' / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / 'vulnerabilities.db'
        self.ttl = timedelta(hours=ttl_hours)
        self._init_db()
    
    def _init_db(self):
        """Initialize cache database"""
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    data BLOB,
                    timestamp REAL
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON cache(timestamp)')
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached data if not expired"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                'SELECT data, timestamp FROM cache WHERE key = ?',
                (key,)
            )
            row = cursor.fetchone()
            
            if row:
                data, timestamp = row
                if datetime.fromtimestamp(timestamp) + self.ttl > datetime.now():
                    return pickle.loads(data)
                else:
                    # Clean up expired entry
                    conn.execute('DELETE FROM cache WHERE key = ?', (key,))
        
        return None
    
    def set(self, key: str, data: Any):
        """Store data in cache"""
        with self._get_connection() as conn:
            conn.execute(
                'INSERT OR REPLACE INTO cache (key, data, timestamp) VALUES (?, ?, ?)',
                (key, pickle.dumps(data), datetime.now().timestamp())
            )
    
    def clear(self):
        """Clear all cache entries"""
        with self._get_connection() as conn:
            conn.execute('DELETE FROM cache')
    
    def cleanup_expired(self):
        """Remove expired cache entries"""
        cutoff = (datetime.now() - self.ttl).timestamp()
        with self._get_connection() as conn:
            conn.execute('DELETE FROM cache WHERE timestamp < ?', (cutoff,))

class RetryHandler:
    """Handle retries with exponential backoff"""
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
    
    def execute(self, func, *args, **kwargs):
        """Execute function with retry logic"""
        last_exception = None
        
        for attempt in range(self.max_attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.max_attempts - 1:
                    delay = self.base_delay * (2 ** attempt)
                    time.sleep(delay)
                continue
        
        raise last_exception

class EnhancedNuGetCLI:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.checker = VulnerabilityChecker()
        self.cache = CacheManager(ttl_hours=self.config.cache_ttl_hours) if self.config.cache_enabled else None
        self.retry_handler = RetryHandler(self.config.retry_attempts, self.config.retry_delay)
        self.start_time = None
        self._setup_proxy()
    
    def _setup_proxy(self):
        """Setup proxy configuration"""
        if self.config.proxy:
            proxies = {
                'http': self.config.proxy,
                'https': self.config.proxy
            }
            self.checker.session.proxies.update(proxies)
    
    def print_banner(self):
        """Display enhanced program banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║           NuGet Vulnerability Scanner CLI Pro v2.0          ║
║              Enhanced Security Assessment Tool              ║
╚══════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)
    
    def load_config_file(self, config_path: Path) -> Config:
        """Load configuration from file"""
        config = configparser.ConfigParser()
        config.read(config_path)
        
        if 'settings' in config:
            settings = config['settings']
            return Config(
                cache_enabled=settings.getboolean('cache_enabled', True),
                cache_ttl_hours=settings.getint('cache_ttl_hours', 24),
                max_workers=settings.getint('max_workers', 5),
                timeout=settings.getint('timeout', 30),
                retry_attempts=settings.getint('retry_attempts', 3),
                retry_delay=settings.getfloat('retry_delay', 1.0),
                proxy=settings.get('proxy', None),
                fail_on_severity=settings.get('fail_on_severity', None),
                exclude_sources=settings.get('exclude_sources', '').split(',') if settings.get('exclude_sources') else [],
                verbose=settings.getboolean('verbose', False),
                quiet=settings.getboolean('quiet', False)
            )
        
        return Config()
    
    def parse_solution_file(self, sln_path: str) -> List[str]:
        """Parse .NET solution file for package references"""
        packages = []
        sln_path = Path(sln_path)
        
        if not sln_path.exists():
            print(Colors.error(f"Solution file not found: {sln_path}"))
            return packages
        
        try:
            # Parse solution file to find project files
            with open(sln_path, 'r', encoding='utf-8-sig') as f:
                content = f.read()
                
            # Find all project references
            project_pattern = r'Project\([^)]+\)\s*=\s*"[^"]+",\s*"([^"]+\.csproj)"'
            project_files = re.findall(project_pattern, content)
            
            # Process each project file
            for proj_file in project_files:
                proj_path = sln_path.parent / proj_file
                if proj_path.exists():
                    packages.extend(self.scan_project_file(str(proj_path)))
        
        except Exception as e:
            print(Colors.warning(f"Error parsing solution file: {e}"))
        
        return packages
    
    def scan_project_file(self, proj_path: str) -> List[str]:
        """Scan a single project file for package references"""
        packages = []
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(proj_path)
            root = tree.getroot()
            
            # Find PackageReference elements
            for package_ref in root.findall('.//PackageReference'):
                name = package_ref.get('Include')
                version = package_ref.get('Version')
                if name and version:
                    packages.append(f"{name}.{version}")
        
        except Exception as e:
            print(Colors.warning(f"Error parsing project file {proj_path}: {e}"))
        
        return packages
    
    def check_with_cache(self, package: str) -> List[Dict]:
        """Check vulnerabilities with caching support"""
        if self.cache:
            cache_key = hashlib.md5(package.encode()).hexdigest()
            cached_result = self.cache.get(cache_key)
            
            if cached_result is not None:
                return cached_result
        
        # If not in cache or cache disabled, fetch from API
        # The VulnerabilityChecker returns a list for a single package
        result = self.retry_handler.execute(
            self.checker.check_vulnerabilities, [package]
        )
        
        if self.cache and result is not None:
            self.cache.set(cache_key, result)
        
        return result
    
    def scan_packages_parallel(self, packages: List[str]) -> List[Dict]:
        """Scan packages in parallel with progress bar"""
        vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            future_to_package = {
                executor.submit(self.check_with_cache, pkg): pkg 
                for pkg in packages
            }
            
            # Process results with progress bar
            if not self.config.quiet:
                progress_bar = tqdm(
                    total=len(packages),
                    desc="Scanning packages",
                    unit="pkg",
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
                )
            
            for future in as_completed(future_to_package):
                package = future_to_package[future]
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.extend(result)
                except Exception as e:
                    print(Colors.error(f"Error scanning {package}: {e}"))
                
                if not self.config.quiet:
                    progress_bar.update(1)
            
            if not self.config.quiet:
                progress_bar.close()
        
        return vulnerabilities
    
    def filter_vulnerabilities(self, vulnerabilities: List[Dict], 
                             severity_filter: Optional[str] = None,
                             cve_filter: Optional[str] = None,
                             date_after: Optional[datetime] = None) -> List[Dict]:
        """Filter vulnerabilities based on criteria"""
        filtered = vulnerabilities
        
        # Filter by severity
        if severity_filter:
            severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            min_severity_index = severity_levels.index(severity_filter.upper())
            filtered = [
                v for v in filtered 
                if severity_levels.index(v.get('severity', 'UNKNOWN').upper()) >= min_severity_index
            ]
        
        # Filter by CVE pattern
        if cve_filter:
            pattern = re.compile(cve_filter, re.IGNORECASE)
            filtered = [
                v for v in filtered
                if pattern.search(v.get('cve_id', ''))
            ]
        
        # Filter by date
        if date_after:
            filtered = [
                v for v in filtered
                if self._parse_vuln_date(v) >= date_after
            ]
        
        # Exclude sources
        if self.config.exclude_sources:
            filtered = [
                v for v in filtered
                if v.get('source', '') not in self.config.exclude_sources
            ]
        
        return filtered
    
    def _parse_vuln_date(self, vuln: Dict) -> datetime:
        """Parse vulnerability date"""
        # This is a simplified implementation
        # In real scenario, you'd parse the actual date from vulnerability data
        return datetime.now()
    
    def generate_markdown_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate Markdown format report"""
        md_content = f"""# NuGet Vulnerability Scan Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Total Vulnerabilities:** {len(vulnerabilities)}

## Summary

"""
        # Group by severity
        severity_groups = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        # Summary table
        md_content += "| Severity | Count |\n|----------|-------|\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = len(severity_groups.get(severity, []))
            if count > 0:
                md_content += f"| {severity} | {count} |\n"
        
        md_content += "\n## Detailed Findings\n\n"
        
        # Detailed vulnerabilities
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            vulns = severity_groups.get(severity, [])
            if vulns:
                md_content += f"### {severity} Severity\n\n"
                for vuln in vulns:
                    md_content += f"#### {vuln.get('cve_id', 'N/A')}\n\n"
                    md_content += f"- **Package:** {vuln.get('package', 'Unknown')}\n"
                    md_content += f"- **Version:** {vuln.get('package_version', 'N/A')}\n"
                    md_content += f"- **CVSS Score:** {vuln.get('cvss_score', 'N/A')}\n"
                    md_content += f"- **Source:** {vuln.get('source', 'Unknown')}\n"
                    md_content += f"- **Description:** {vuln.get('description', 'N/A')}\n"
                    md_content += f"- **Reference:** [{vuln.get('link', 'N/A')}]({vuln.get('link', '#')})\n\n"
        
        return md_content
    
    def interactive_mode(self, packages: List[str]) -> List[str]:
        """Interactive package selection mode"""
        print(Colors.info("\n📋 Interactive Package Selection Mode"))
        print("Select packages to scan (space to toggle, enter to confirm):\n")
        
        selected = set()
        current_index = 0
        
        # Simple implementation without curses
        for i, pkg in enumerate(packages):
            print(f"[ ] {i+1}. {pkg}")
        
        print(Colors.info("\nEnter package numbers to scan (comma-separated), or 'all' for all packages:"))
        selection = input("> ").strip()
        
        if selection.lower() == 'all':
            return packages
        
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            return [packages[i] for i in indices if 0 <= i < len(packages)]
        except (ValueError, IndexError):
            print(Colors.warning("Invalid selection. Scanning all packages."))
            return packages
    
    def parse_package_list_format(self, list_string: str) -> List[str]:
        """Parse Python list format package list"""
        packages = []
        
        try:
            # Clean input string, remove extra whitespace and newlines
            cleaned_string = re.sub(r'\s+', ' ', list_string.strip())
            
            # Try to parse directly as Python list
            try:
                parsed_list = ast.literal_eval(cleaned_string)
                if isinstance(parsed_list, list):
                    packages = [str(pkg).strip() for pkg in parsed_list if pkg]
                    print(Colors.success(f"✅ Successfully parsed Python list format, found {len(packages)} packages"))
                    return packages
            except (ValueError, SyntaxError):
                pass
            
            # If direct parsing fails, try to extract list content
            # Look for [...] format
            list_match = re.search(r'\[(.*?)\]', cleaned_string, re.DOTALL)
            if list_match:
                list_content = list_match.group(1)
                
                # Split items, support single quotes, double quotes or no quotes
                items = re.findall(r"['\"]([^'\"]+)['\"]|([^,\s]+)", list_content)
                
                for item in items:
                    # item is a tuple, take the non-empty part
                    pkg = item[0] if item[0] else item[1]
                    if pkg and pkg.strip():
                        packages.append(pkg.strip())
                
                if packages:
                    print(Colors.success(f"✅ Successfully parsed list format, found {len(packages)} packages"))
                    return packages
            
            # If still fails, try splitting by comma
            if ',' in cleaned_string:
                # Remove brackets
                content = re.sub(r'[\[\]]', '', cleaned_string)
                # Split and clean
                items = [item.strip().strip('\'"') for item in content.split(',')]
                packages = [item for item in items if item and not item.isspace()]
                
                if packages:
                    print(Colors.success(f"✅ Parsed by comma separation, found {len(packages)} packages"))
                    return packages
            
            # Last attempt: assume it's a single package
            cleaned = re.sub(r'[\[\]\'""]', '', cleaned_string).strip()
            if cleaned:
                packages = [cleaned]
                print(Colors.success(f"✅ Parsed as single package: {cleaned}"))
                return packages
                
        except Exception as e:
            print(Colors.warning(f"⚠️  Error parsing list format: {e}"))
        
        return packages
    
    def parse_packages_from_file(self, file_path: str) -> List[str]:
        """Parse package list from file"""
        packages = []
        path_obj = Path(file_path)
        
        if not path_obj.exists():
            print(Colors.error(f"❌ File not found: {file_path}"))
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
            print(Colors.error(f"❌ Failed to read file: {e}"))
            
        return packages
    
    def scan_directory_for_packages(self, directory: str) -> List[str]:
        """Scan directory for NuGet package files"""
        packages = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            print(Colors.error(f"❌ Directory not found: {directory}"))
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
                print(Colors.warning(f"⚠️  Failed to parse {config_file}: {e}"))
        
        # Find .csproj files with PackageReference
        csproj_files = list(dir_path.rglob("*.csproj"))
        for csproj_file in csproj_files:
            packages.extend(self.scan_project_file(str(csproj_file)))
        
        return packages
    
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
    
    def display_summary(self, vulnerabilities: List[Dict], packages_count: int):
        """Display scan summary"""
        print("\n" + "="*80)
        print(Colors.info(Colors.BOLD + "📊 SCAN SUMMARY"))
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
        print(f"📦 Packages scanned: {Colors.BOLD}{packages_count}{Colors.RESET}")
        print(f"🔍 Vulnerabilities found: {Colors.BOLD}{total_vulns}{Colors.RESET}")
        print(f"⚠️  Affected packages: {Colors.BOLD}{len(packages_with_vulns)}{Colors.RESET}")
        print(f"🌐 Data sources: {Colors.BOLD}{', '.join(sorted(sources))}{Colors.RESET}")
        
        # Severity distribution
        if severity_counts:
            print(f"\n🚨 Severity distribution:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = self.get_severity_color(severity)
                    print(f"  {color}● {severity}: {count}{Colors.RESET}")
        
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
        
        print(f"\n⚡ Overall risk level: {risk_color}{Colors.BOLD}{risk_level}{Colors.RESET}")
        
        # Execution time
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"⏱️  Scan duration: {Colors.BOLD}{duration:.2f} seconds{Colors.RESET}")
    
    def display_vulnerabilities(self, vulnerabilities: List[Dict], detailed: bool = False):
        """Display vulnerability details"""
        if not vulnerabilities:
            print(Colors.success(Colors.BOLD + "✅ No known vulnerabilities found!"))
            return
        
        print("\n" + "="*80)
        print(Colors.error(Colors.BOLD + "🔍 VULNERABILITIES FOUND"))
        print("="*80)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = self.get_severity_color(vuln.get('severity', 'UNKNOWN'))
            is_conservative = vuln.get('is_conservative_match', False)
            
            print(f"\n{Colors.BOLD}[{i}] {vuln.get('package', 'Unknown')}{Colors.RESET}")
            print(f"    🆔 CVE ID: {Colors.CYAN}{vuln.get('cve_id', 'N/A')}{Colors.RESET}")
            print(f"    📊 CVSS Score: {Colors.BOLD}{vuln.get('cvss_score', 'N/A')}{Colors.RESET}")
            print(f"    🚨 Severity: {severity_color}{Colors.BOLD}{vuln.get('severity', 'UNKNOWN')}{Colors.RESET}")
            print(f"    📦 Package Version: {Colors.YELLOW}{vuln.get('package_version', 'N/A')}{Colors.RESET}")
            print(f"    🌐 Data Source: {Colors.BLUE}{Colors.BOLD}{vuln.get('source', 'Unknown')}{Colors.RESET}")
            
            # Highlight conservative judgment cases
            if is_conservative:
                print(f"    {Colors.YELLOW}{Colors.BOLD}⚠️  Note: Package name matches but no specific version range found, using conservative judgment{Colors.RESET}")
            
            if detailed:
                description = vuln.get('description', 'N/A')
                if len(description) > 100:
                    description = description[:100] + "..."
                print(f"    📝 Description: {description}")
                # Highlight links
                print(f"    🔗 Link: {Colors.CYAN}{Colors.BOLD}{vuln.get('link', 'N/A')}{Colors.RESET}")
            else:
                # Show highlighted links even in non-detailed mode
                print(f"    🔗 Link: {Colors.CYAN}{Colors.BOLD}{vuln.get('link', 'N/A')}{Colors.RESET}")
            
            print(f"    {'-'*60}")
    
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
                        'scanner_version': '2.0.0'
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
            
            elif format_type.lower() == 'markdown':
                # Markdown report
                md_content = self.generate_markdown_report(vulnerabilities)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(md_content)
                    
            print(Colors.success(f"✅ Results exported to: {output_path}"))
            
        except Exception as e:
            print(Colors.error(f"❌ Export failed: {e}"))
    
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
        .conservative-warning {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px; }}
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
            <p>This report was generated by NuGet Vulnerability Scanner CLI Pro v2.0</p>
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
                is_conservative = vuln.get('is_conservative_match', False)
                
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
                """
                
                if is_conservative:
                    vuln_html += """
                        <div class="conservative-warning">
                            ⚠️ <strong>Conservative Match:</strong> Package name matches but no specific version range found. This vulnerability may not affect your version.
                        </div>
                    """
                
                vuln_html += """
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
        """Execute enhanced main program"""
        self.start_time = time.time()
        
        # Load config file if specified
        if args.config:
            config_path = Path(args.config)
            if config_path.exists():
                self.config = self.load_config_file(config_path)
        
        # Override config with command line arguments
        if args.verbose:
            self.config.verbose = True
        if args.quiet:
            self.config.quiet = True
        
        if not self.config.quiet:
            self.print_banner()
        
        # Clean up expired cache entries
        if self.cache:
            self.cache.cleanup_expired()
        
        # Collect package list
        packages = []
        
        # From command line arguments
        if args.packages:
            packages.extend([pkg.strip() for pkg in args.packages.split(',')])
        
        # From solution file
        if args.solution:
            sln_packages = self.parse_solution_file(args.solution)
            packages.extend(sln_packages)
            if not self.config.quiet:
                print(Colors.info(f"📋 Found {len(sln_packages)} packages in solution file"))
        
        # From Python list format
        if args.list_format:
            list_packages = self.parse_package_list_format(args.list_format)
            packages.extend(list_packages)
            if not self.config.quiet:
                print(Colors.info(f"📋 Loaded {len(list_packages)} packages from list format"))
        
        # From file
        if args.file:
            file_packages = self.parse_packages_from_file(args.file)
            packages.extend(file_packages)
            if not self.config.quiet:
                print(Colors.info(f"📁 Loaded {len(file_packages)} packages from file"))
        
        # From directory scan
        if args.scan_dir:
            dir_packages = self.scan_directory_for_packages(args.scan_dir)
            packages.extend(dir_packages)
            if not self.config.quiet:
                print(Colors.info(f"📂 Found {len(dir_packages)} packages in directory"))
        
        # Remove duplicates
        packages = list(set(packages))
        
        if not packages:
            print(Colors.error("❌ No packages specified for checking"))
            print(Colors.warning("💡 Use --help to see usage instructions"))
            return 1
        
        # Interactive mode
        if args.interactive:
            packages = self.interactive_mode(packages)
        
        if not self.config.quiet:
            print(Colors.success(f"🚀 Starting scan of {len(packages)} packages..."))
            if self.config.verbose:
                print("Package list:")
                for pkg in packages:
                    print(f"  • {pkg}")
        
        # Execute vulnerability check
        try:
            vulnerabilities = self.scan_packages_parallel(packages)
            
            # Apply filters
            if args.filter_severity or args.filter_cve:
                vulnerabilities = self.filter_vulnerabilities(
                    vulnerabilities,
                    severity_filter=args.filter_severity,
                    cve_filter=args.filter_cve
                )
            
            # Display results
            if not self.config.quiet:
                self.display_vulnerabilities(vulnerabilities, detailed=self.config.verbose)
                self.display_summary(vulnerabilities, len(packages))
            
            # Export results
            if args.output:
                format_type = args.format or 'json'
                self.export_results(vulnerabilities, args.output, format_type)
            
            # Check exit conditions
            if args.fail_on_vuln and vulnerabilities:
                return 1
            
            if self.config.fail_on_severity:
                severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                min_severity_index = severity_levels.index(self.config.fail_on_severity.upper())
                
                for vuln in vulnerabilities:
                    vuln_severity = vuln.get('severity', 'UNKNOWN').upper()
                    if vuln_severity in severity_levels:
                        if severity_levels.index(vuln_severity) >= min_severity_index:
                            return 1
            
            return 0
            
        except KeyboardInterrupt:
            print(Colors.warning("\n⚠️  Scan interrupted by user"))
            return 130
        except Exception as e:
            print(Colors.error(f"❌ Error during scan: {e}"))
            if self.config.verbose:
                import traceback
                traceback.print_exc()
            return 1

def create_sample_config():
    """Create sample configuration file"""
    config_content = """[settings]
# Cache settings
cache_enabled = true
cache_ttl_hours = 24

# Performance settings
max_workers = 5
timeout = 30

# Retry settings
retry_attempts = 3
retry_delay = 1.0

# Proxy settings (uncomment to use)
# proxy = http://proxy.example.com:8080

# Fail on severity level (CRITICAL, HIGH, MEDIUM, LOW)
# fail_on_severity = HIGH

# Exclude vulnerability sources (comma-separated)
# exclude_sources = source1,source2

# Output settings
verbose = false
quiet = false
"""
    
    with open('.nugetcli.config', 'w') as f:
        f.write(config_content)
    
    print(Colors.success("✅ Sample configuration file created: .nugetcli.config"))

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
    """Enhanced main function"""
    parser = argparse.ArgumentParser(
        description='NuGet Package Vulnerability Scanner - Enhanced CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Enhanced Features:
  • Caching support for faster repeated scans
  • Parallel scanning with progress bars
  • Solution file (.sln) support
  • Advanced filtering options
  • Configuration file support
  • Retry logic with exponential backoff
  • Interactive package selection mode
  • Multiple export formats including Markdown

Usage Examples:
  %(prog)s -p "serilog.4.3.0,newtonsoft.json.13.0.1"
  %(prog)s --solution MyProject.sln -o report.md --format markdown
  %(prog)s -f packages.txt --filter-severity HIGH --fail-on-severity CRITICAL
  %(prog)s --scan-dir ./src --interactive --config .nugetcli.config
  %(prog)s -p "log4net.2.0.8" --no-cache --workers 10
        """
    )
    
    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument('-p', '--packages', 
                           help='Package list, comma-separated')
    input_group.add_argument('--solution', 
                           help='Path to .NET solution file (.sln)')
    input_group.add_argument('--list', dest='list_format',
                           help='Python list format package list')
    input_group.add_argument('-f', '--file', 
                           help='Read package list from file')
    input_group.add_argument('--scan-dir', 
                           help='Scan directory for NuGet packages')
    input_group.add_argument('-i', '--interactive', action='store_true',
                           help='Interactive package selection mode')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', 
                            help='Output file path')
    output_group.add_argument('--format', 
                            choices=['json', 'csv', 'html', 'markdown'],
                            help='Output format (default: json)')
    output_group.add_argument('-v', '--verbose', action='store_true',
                            help='Show detailed information')
    output_group.add_argument('-q', '--quiet', action='store_true',
                            help='Quiet mode')
    
    # Filter options
    filter_group = parser.add_argument_group('Filter Options')
    filter_group.add_argument('--filter-severity',
                            choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                            help='Filter by minimum severity level')
    filter_group.add_argument('--filter-cve',
                            help='Filter by CVE pattern (regex)')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('--workers', type=int,
                          help='Number of parallel workers (default: 5)')
    perf_group.add_argument('--no-cache', action='store_true',
                          help='Disable caching')
    perf_group.add_argument('--clear-cache', action='store_true',
                          help='Clear cache and exit')
    
    # Configuration options
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument('--config',
                            help='Configuration file path')
    config_group.add_argument('--create-config', action='store_true',
                            help='Create sample configuration file')
    config_group.add_argument('--fail-on-severity',
                            choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                            help='Exit with error if vulnerabilities found at or above this level')
    
    # Behavior options
    behavior_group = parser.add_argument_group('Behavior Options')
    behavior_group.add_argument('--fail-on-vuln', action='store_true',
                              help='Exit with non-zero code when vulnerabilities found')
    behavior_group.add_argument('--create-samples', action='store_true',
                              help='Create sample files')
    
    args = parser.parse_args()
    
    # Handle special commands
    if args.create_config:
        create_sample_config()
        return 0
    
    if args.create_samples:
        create_sample_files()
        return 0
    
    if args.clear_cache:
        cache = CacheManager()
        cache.clear()
        print(Colors.success("✅ Cache cleared successfully"))
        return 0
    
    # Create config object
    config = Config(
        cache_enabled=not args.no_cache,
        max_workers=args.workers or 5,
        verbose=args.verbose,
        quiet=args.quiet,
        fail_on_severity=args.fail_on_severity
    )
    
    # Check if any input is provided
    if not any([args.packages, args.solution, args.list_format, args.file, args.scan_dir]):
        parser.print_help()
        return 1
    
    # Execute scan
    cli = EnhancedNuGetCLI(config)
    return cli.run(args)

if __name__ == "__main__":
    sys.exit(main())