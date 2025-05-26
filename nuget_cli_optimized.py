#!/usr/bin/env python3
"""
NuGet Package Vulnerability Scanner - Optimized CLI
Minimal dependencies, enhanced UI design, and optimized performance

Features:
- Zero external dependencies beyond standard library + requests
- Built-in progress indication and enhanced terminal UI
- SQLite caching for performance
- Parallel processing with standard library threading
- Solution file (.sln) and project scanning
- Multiple export formats
- Interactive package selection
- Configuration file support
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
import signal
import platform
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import configparser
import sqlite3
from contextlib import contextmanager

# Only require requests - everything else is standard library
try:
    import requests
except ImportError:
    print("❌ Missing required dependency: requests")
    print("💡 Install with: pip install requests")
    sys.exit(1)

# Import the vulnerability checker
try:
    from vulnerability_checker_en import VulnerabilityChecker
except ImportError:
    print("❌ Could not import vulnerability_checker_en module")
    print("💡 Ensure vulnerability_checker_en.py is in the same directory")
    sys.exit(1)


@dataclass
class Config:
    """Lightweight configuration settings"""
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
        # Auto-detect optimal worker count
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        if self.max_workers > cpu_count * 2:
            self.max_workers = min(cpu_count * 2, 10)


class Colors:
    """Cross-platform terminal colors using only ANSI codes"""
    # Check if terminal supports color
    _supports_color = (
        hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() and
        os.environ.get('TERM') != 'dumb' and
        platform.system() != 'Windows' or os.environ.get('ANSICON')
    )
    
    if _supports_color:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        DIM = '\033[2m'
        RESET = '\033[0m'
        UNDERLINE = '\033[4m'
    else:
        # Fallback for terminals that don't support color
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''
        BOLD = DIM = RESET = UNDERLINE = ''
    
    @classmethod
    def error(cls, text: str) -> str:
        return f"{cls.RED}{cls.BOLD}{text}{cls.RESET}"
    
    @classmethod
    def success(cls, text: str) -> str:
        return f"{cls.GREEN}{cls.BOLD}{text}{cls.RESET}"
    
    @classmethod
    def warning(cls, text: str) -> str:
        return f"{cls.YELLOW}{text}{cls.RESET}"
    
    @classmethod
    def info(cls, text: str) -> str:
        return f"{cls.CYAN}{text}{cls.RESET}"
    
    @classmethod
    def highlight(cls, text: str) -> str:
        return f"{cls.BOLD}{cls.UNDERLINE}{text}{cls.RESET}"


class ProgressBar:
    """Lightweight progress bar implementation using only standard library"""
    
    def __init__(self, total: int, description: str = "Progress", width: int = 40):
        self.total = total
        self.current = 0
        self.description = description
        self.width = width
        self.start_time = time.time()
        self._lock = threading.Lock()
        
    def update(self, amount: int = 1):
        with self._lock:
            self.current = min(self.current + amount, self.total)
            self._display()
    
    def _display(self):
        if self.total == 0:
            return
            
        percent = self.current / self.total
        filled_width = int(self.width * percent)
        bar = '█' * filled_width + '░' * (self.width - filled_width)
        
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0
        eta = (self.total - self.current) / rate if rate > 0 else 0
        
        # Format time
        def format_time(seconds):
            if seconds < 60:
                return f"{seconds:.0f}s"
            elif seconds < 3600:
                return f"{seconds//60:.0f}m{seconds%60:.0f}s"
            else:
                return f"{seconds//3600:.0f}h{(seconds%3600)//60:.0f}m"
        
        print(f"\r{Colors.CYAN}{self.description}{Colors.RESET} "
              f"{bar} {self.current}/{self.total} "
              f"({percent:.1%}) "
              f"[{format_time(elapsed)}<{format_time(eta)}, {rate:.1f}it/s]", 
              end='', flush=True)
        
        if self.current == self.total:
            print()  # New line when complete
    
    def close(self):
        if self.current < self.total:
            print()  # New line if interrupted


class CacheManager:
    """Optimized SQLite cache with minimal overhead"""
    
    def __init__(self, cache_dir: Path = None, ttl_hours: int = 24):
        self.cache_dir = cache_dir or Path.home() / '.nuget-cli'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / 'vulnerabilities.db'
        self.ttl = timedelta(hours=ttl_hours)
        self._lock = threading.Lock()
        self._init_db()
        self.stats = {'hits': 0, 'misses': 0}
    
    def _init_db(self):
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
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute(
                        'SELECT data, timestamp FROM cache WHERE key = ?', (key,)
                    )
                    row = cursor.fetchone()
                    
                    if row:
                        data, timestamp = row
                        if datetime.fromtimestamp(timestamp) + self.ttl > datetime.now():
                            self.stats['hits'] += 1
                            return pickle.loads(data)
                        else:
                            conn.execute('DELETE FROM cache WHERE key = ?', (key,))
                    
                    self.stats['misses'] += 1
                    return None
            except Exception:
                self.stats['misses'] += 1
                return None
    
    def set(self, key: str, data: Any):
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        'INSERT OR REPLACE INTO cache (key, data, timestamp) VALUES (?, ?, ?)',
                        (key, pickle.dumps(data), datetime.now().timestamp())
                    )
            except Exception:
                pass  # Silently fail on cache write errors
    
    def cleanup_expired(self):
        try:
            cutoff = (datetime.now() - self.ttl).timestamp()
            with self._get_connection() as conn:
                cursor = conn.execute('SELECT COUNT(*) FROM cache WHERE timestamp < ?', (cutoff,))
                expired_count = cursor.fetchone()[0]
                if expired_count > 0:
                    conn.execute('DELETE FROM cache WHERE timestamp < ?', (cutoff,))
        except Exception:
            pass
    
    def clear(self):
        try:
            with self._get_connection() as conn:
                conn.execute('DELETE FROM cache')
        except Exception:
            pass
    
    def get_stats(self) -> Dict[str, Any]:
        total_requests = self.stats['hits'] + self.stats['misses']
        hit_rate = self.stats['hits'] / total_requests if total_requests > 0 else 0
        return {
            'hit_rate': hit_rate,
            'total_requests': total_requests,
            **self.stats
        }


class OptimizedNuGetCLI:
    """Optimized NuGet CLI with minimal dependencies and enhanced UI"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.checker = VulnerabilityChecker()
        self.cache = CacheManager(ttl_hours=self.config.cache_ttl_hours) if self.config.cache_enabled else None
        self.start_time = None
        self._interrupted = False
        self._setup_proxy()
        self._setup_signal_handlers()
    
    def _setup_proxy(self):
        if self.config.proxy:
            self.checker.session.proxies.update({
                'http': self.config.proxy,
                'https': self.config.proxy
            })
    
    def _setup_signal_handlers(self):
        def signal_handler(signum, frame):
            self._interrupted = True
            print(f"\n{Colors.warning('⚠️  Scan interrupted. Cleaning up...')}")
        
        signal.signal(signal.SIGINT, signal_handler)
        if platform.system() != 'Windows':
            signal.signal(signal.SIGTERM, signal_handler)
    
    def print_banner(self):
        """Enhanced banner with terminal width detection"""
        try:
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 80
        
        width = min(terminal_width - 4, 80)
        
        banner = f"""
{Colors.CYAN}{Colors.BOLD}{'═' * width}
║{' ' * ((width - 50) // 2)}🔍 NuGet Vulnerability Scanner - Optimized CLI{' ' * ((width - 50) // 2)}║
║{' ' * ((width - 30) // 2)}Enhanced Security Assessment Tool{' ' * ((width - 30) // 2)}║
{'═' * width}{Colors.RESET}
"""
        print(banner)
    
    def load_config_file(self, config_path: Path) -> Config:
        """Load configuration from file"""
        config_parser = configparser.ConfigParser()
        config_parser.read(config_path)
        
        if 'settings' in config_parser:
            settings = config_parser['settings']
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
        """Parse .NET solution file for projects"""
        packages = []
        sln_path = Path(sln_path)
        
        if not sln_path.exists():
            print(Colors.error(f"Solution file not found: {sln_path}"))
            return packages
        
        try:
            with open(sln_path, 'r', encoding='utf-8-sig') as f:
                content = f.read()
            
            # Find project files
            project_pattern = r'Project\([^)]+\)\s*=\s*"[^"]+",\s*"([^"]+\.csproj)"'
            project_files = re.findall(project_pattern, content)
            
            for proj_file in project_files:
                proj_path = sln_path.parent / proj_file
                if proj_path.exists():
                    packages.extend(self._scan_project_file(str(proj_path)))
        
        except Exception as e:
            print(Colors.warning(f"Error parsing solution file: {e}"))
        
        return packages
    
    def _scan_project_file(self, proj_path: str) -> List[str]:
        """Scan project file for package references"""
        packages = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(proj_path)
            root = tree.getroot()
            
            for package_ref in root.findall('.//PackageReference'):
                name = package_ref.get('Include')
                version = package_ref.get('Version')
                if name and version:
                    packages.append(f"{name}.{version}")
        
        except Exception as e:
            print(Colors.warning(f"Error parsing {proj_path}: {e}"))
        
        return packages
    
    def parse_packages_from_file(self, file_path: str) -> List[str]:
        """Parse package list from various file formats"""
        packages = []
        path_obj = Path(file_path)
        
        if not path_obj.exists():
            print(Colors.error(f"File not found: {file_path}"))
            return packages
        
        try:
            if path_obj.suffix.lower() == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if 'dependencies' in data:
                    for name, version in data['dependencies'].items():
                        packages.append(f"{name}.{version}")
                elif 'packages' in data:
                    packages.extend(data['packages'])
                elif isinstance(data, list):
                    packages.extend(data)
                    
            elif path_obj.suffix.lower() == '.csv':
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row and not row[0].startswith('#'):
                            packages.append(row[0].strip())
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            packages.append(line)
                            
        except Exception as e:
            print(Colors.error(f"Failed to read file: {e}"))
            
        return packages
    
    def scan_directory_for_packages(self, directory: str) -> List[str]:
        """Scan directory for NuGet package files"""
        packages = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            print(Colors.error(f"Directory not found: {directory}"))
            return packages
        
        # Find .nupkg files
        packages.extend([f.name for f in dir_path.rglob("*.nupkg")])
        
        # Find packages.config files
        for config_file in dir_path.rglob("packages.config"):
            packages.extend(self._parse_packages_config(config_file))
        
        # Find .csproj files
        for csproj_file in dir_path.rglob("*.csproj"):
            packages.extend(self._scan_project_file(str(csproj_file)))
        
        return packages
    
    def _parse_packages_config(self, config_file: Path) -> List[str]:
        """Parse packages.config file"""
        packages = []
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
            print(Colors.warning(f"Failed to parse {config_file}: {e}"))
        
        return packages
    
    def check_with_cache(self, package: str) -> List[Dict]:
        """Check vulnerabilities with caching"""
        if self.cache:
            cache_key = hashlib.md5(package.encode('utf-8')).hexdigest()
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                return cached_result
        
        if self._interrupted:
            return []
        
        # Retry logic
        for attempt in range(self.config.retry_attempts):
            try:
                result = self.checker.check_vulnerabilities([package])
                if self.cache and result is not None:
                    cache_key = hashlib.md5(package.encode('utf-8')).hexdigest()
                    self.cache.set(cache_key, result)
                time.sleep(0.1)  # Small delay to respect rate limits
                return result
            except Exception as e:
                if attempt == self.config.retry_attempts - 1:
                    if not self.config.quiet:
                        print(Colors.error(f"Error checking {package}: {e}"))
                    return []
                time.sleep(self.config.retry_delay * (2 ** attempt))
        
        return []
    
    def scan_packages_parallel(self, packages: List[str]) -> List[Dict]:
        """Scan packages in parallel with built-in progress bar"""
        vulnerabilities = []
        failed_packages = []
        
        progress = None
        if not self.config.quiet:
            progress = ProgressBar(len(packages), "🔍 Scanning packages")
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_package = {
                executor.submit(self.check_with_cache, pkg): pkg 
                for pkg in packages
            }
            
            for future in as_completed(future_to_package):
                if self._interrupted:
                    break
                
                package = future_to_package[future]
                try:
                    result = future.result(timeout=self.config.timeout)
                    if result:
                        vulnerabilities.extend(result)
                except Exception as e:
                    failed_packages.append(package)
                    if self.config.verbose:
                        print(Colors.error(f"Failed to scan {package}: {e}"))
                
                if progress:
                    progress.update()
        
        if progress:
            progress.close()
        
        if failed_packages and not self.config.quiet:
            print(Colors.warning(f"⚠️  Failed to scan {len(failed_packages)} packages"))
        
        return vulnerabilities
    
    def get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.MAGENTA,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'UNKNOWN': Colors.CYAN
        }
        return colors.get(severity.upper(), Colors.WHITE)
    
    def display_vulnerabilities(self, vulnerabilities: List[Dict], detailed: bool = False):
        """Enhanced vulnerability display with better formatting"""
        if not vulnerabilities:
            print(f"\n{Colors.success('✅ No known vulnerabilities found!')}")
            return
        
        # Group by package for better organization
        packages = {}
        for vuln in vulnerabilities:
            pkg = vuln.get('package', 'Unknown')
            if pkg not in packages:
                packages[pkg] = []
            packages[pkg].append(vuln)
        
        print(f"\n{Colors.RED}{Colors.BOLD}🚨 VULNERABILITIES FOUND{Colors.RESET}")
        print("=" * 70)
        
        for pkg_name, pkg_vulns in packages.items():
            print(f"\n{Colors.BOLD}📦 {pkg_name}{Colors.RESET}")
            print("-" * 50)
            
            for i, vuln in enumerate(pkg_vulns, 1):
                severity = vuln.get('severity', 'UNKNOWN')
                severity_color = self.get_severity_color(severity)
                
                print(f"\n  {Colors.BOLD}[{i}]{Colors.RESET} {vuln.get('cve_id', 'N/A')}")
                print(f"      🚨 Severity: {severity_color}{severity}{Colors.RESET}")
                print(f"      📊 CVSS: {vuln.get('cvss_score', 'N/A')}")
                print(f"      🌐 Source: {Colors.BLUE}{vuln.get('source', 'Unknown')}{Colors.RESET}")
                
                if detailed:
                    desc = vuln.get('description', 'N/A')
                    if len(desc) > 100:
                        desc = desc[:100] + "..."
                    print(f"      📝 Description: {desc}")
                
                if vuln.get('link'):
                    print(f"      🔗 Details: {Colors.highlight(vuln['link'])}")
                
                if vuln.get('is_conservative_match'):
                    print(f"      {Colors.warning('⚠️  Conservative match - verify manually')}")
    
    def display_summary(self, vulnerabilities: List[Dict], packages_count: int):
        """Enhanced summary with visual improvements"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}📊 SCAN SUMMARY{Colors.RESET}")
        print("=" * 50)
        
        # Calculate statistics
        total_vulns = len(vulnerabilities)
        severity_counts = {}
        sources = set()
        affected_packages = set()
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            sources.add(vuln.get('source', 'Unknown'))
            affected_packages.add(vuln.get('package', 'Unknown'))
        
        # Basic stats with visual indicators
        safe_count = packages_count - len(affected_packages)
        print(f"📦 Total packages scanned: {Colors.BOLD}{packages_count}{Colors.RESET}")
        print(f"✅ Safe packages: {Colors.GREEN}{Colors.BOLD}{safe_count}{Colors.RESET}")
        print(f"⚠️  Vulnerable packages: {Colors.RED}{Colors.BOLD}{len(affected_packages)}{Colors.RESET}")
        print(f"🔍 Total vulnerabilities: {Colors.BOLD}{total_vulns}{Colors.RESET}")
        
        # Severity distribution with visual bars
        if severity_counts:
            print(f"\n🚨 Severity distribution:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = self.get_severity_color(severity)
                    percentage = (count / total_vulns) * 100
                    bar_length = int(percentage / 5)  # Scale bar
                    bar = '█' * bar_length + '░' * (20 - bar_length)
                    print(f"  {color}{severity:8}{Colors.RESET} {bar} {count} ({percentage:.1f}%)")
        
        # Risk assessment with recommendations
        risk_level = "LOW"
        risk_color = Colors.GREEN
        recommendations = []
        
        if severity_counts.get('CRITICAL', 0) > 0:
            risk_level = "CRITICAL"
            risk_color = Colors.RED
            recommendations.append("🚨 Immediate action required for CRITICAL vulnerabilities")
        elif severity_counts.get('HIGH', 0) > 0:
            risk_level = "HIGH"
            risk_color = Colors.MAGENTA
            recommendations.append("⚡ Prioritize HIGH severity vulnerabilities")
        elif severity_counts.get('MEDIUM', 0) > 0:
            risk_level = "MEDIUM"
            risk_color = Colors.YELLOW
            recommendations.append("📝 Schedule MEDIUM severity vulnerabilities for maintenance")
        
        print(f"\n⚡ Overall risk: {risk_color}{Colors.BOLD}{risk_level}{Colors.RESET}")
        
        if recommendations:
            print(f"\n💡 Recommendations:")
            for rec in recommendations:
                print(f"   {rec}")
        
        # Performance stats
        if self.cache:
            cache_stats = self.cache.get_stats()
            print(f"\n📈 Performance:")
            print(f"   💾 Cache hit rate: {cache_stats['hit_rate']:.1%}")
            print(f"   ⚡ Total requests: {cache_stats['total_requests']}")
        
        if self.start_time:
            duration = time.time() - self.start_time
            rate = packages_count / duration if duration > 0 else 0
            print(f"   ⏱️  Duration: {duration:.2f}s ({rate:.1f} pkg/s)")
    
    def export_results(self, vulnerabilities: List[Dict], output_file: str, format_type: str):
        """Export results to various formats"""
        try:
            output_path = Path(output_file)
            
            if format_type.lower() == 'json':
                export_data = {
                    'scan_metadata': {
                        'scan_time': datetime.now().isoformat(),
                        'total_vulnerabilities': len(vulnerabilities),
                        'scanner_version': 'optimized-2.0'
                    },
                    'vulnerabilities': vulnerabilities
                }
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, ensure_ascii=False, indent=2)
                    
            elif format_type.lower() == 'csv':
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    if vulnerabilities:
                        writer = csv.DictWriter(f, fieldnames=vulnerabilities[0].keys())
                        writer.writeheader()
                        writer.writerows(vulnerabilities)
                        
            elif format_type.lower() == 'html':
                html_content = self._generate_html_report(vulnerabilities)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            
            elif format_type.lower() == 'markdown':
                md_content = self._generate_markdown_report(vulnerabilities)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(md_content)
                    
            print(Colors.success(f"✅ Results exported to: {output_path}"))
            
        except Exception as e:
            print(Colors.error(f"❌ Export failed: {e}"))
    
    def _generate_markdown_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate Markdown report"""
        md_content = f"""# 🔍 NuGet Vulnerability Scan Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Total Vulnerabilities:** {len(vulnerabilities)}

## 📊 Summary

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
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'}.get(severity, '⚪')
                md_content += f"| {icon} {severity} | {count} |\n"
        
        md_content += "\n## 🚨 Detailed Findings\n\n"
        
        # Detailed vulnerabilities
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            vulns = severity_groups.get(severity, [])
            if vulns:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'}.get(severity, '⚪')
                md_content += f"### {icon} {severity} Severity\n\n"
                for vuln in vulns:
                    md_content += f"#### {vuln.get('cve_id', 'N/A')}\n\n"
                    md_content += f"- **📦 Package:** {vuln.get('package', 'Unknown')}\n"
                    md_content += f"- **🏷️ Version:** {vuln.get('package_version', 'N/A')}\n"
                    md_content += f"- **📊 CVSS Score:** {vuln.get('cvss_score', 'N/A')}\n"
                    md_content += f"- **🌐 Source:** {vuln.get('source', 'Unknown')}\n"
                    md_content += f"- **📝 Description:** {vuln.get('description', 'N/A')}\n"
                    md_content += f"- **🔗 Reference:** [{vuln.get('link', 'N/A')}]({vuln.get('link', '#')})\n\n"
        
        return md_content
    
    def _generate_html_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML report with modern styling"""
        # Simplified HTML template focused on readability
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NuGet Vulnerability Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f7fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .summary { padding: 30px; background: #f8f9fa; border-bottom: 1px solid #e9ecef; }
        .vuln { margin: 20px 30px; padding: 20px; border-radius: 8px; border-left: 4px solid; }
        .critical { border-color: #dc3545; background: #fff5f5; }
        .high { border-color: #fd7e14; background: #fff8f0; }
        .medium { border-color: #ffc107; background: #fffbf0; }
        .low { border-color: #28a745; background: #f0fff4; }
        .badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }
        .badge-critical { background: #dc3545; }
        .badge-high { background: #fd7e14; }
        .badge-medium { background: #ffc107; color: black; }
        .badge-low { background: #28a745; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NuGet Vulnerability Report</h1>
            <p>Generated on {scan_time}</p>
        </div>
        <div class="summary">
            <h2>📊 Summary</h2>
            <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
            <p><strong>Affected Packages:</strong> {affected_packages}</p>
        </div>
        {vulnerability_list}
    </div>
</body>
</html>"""
        
        # Generate vulnerability HTML
        vuln_html = ""
        packages = {}
        
        for vuln in vulnerabilities:
            package = vuln.get('package', 'Unknown')
            if package not in packages:
                packages[package] = []
            packages[package].append(vuln)
        
        for package_name, package_vulns in packages.items():
            for vuln in package_vulns:
                severity = vuln.get('severity', 'UNKNOWN').lower()
                vuln_html += f"""
                <div class="vuln {severity}">
                    <h3>
                        <span class="badge badge-{severity}">{vuln.get('severity', 'UNKNOWN')}</span>
                        {vuln.get('cve_id', 'N/A')} - {package_name}
                    </h3>
                    <p><strong>CVSS Score:</strong> {vuln.get('cvss_score', 'N/A')}</p>
                    <p><strong>Source:</strong> {vuln.get('source', 'Unknown')}</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
                    <p><strong>Reference:</strong> <a href="{vuln.get('link', '#')}" target="_blank">View Details</a></p>
                </div>
                """
        
        return html_template.format(
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_vulns=len(vulnerabilities),
            affected_packages=len(packages),
            vulnerability_list=vuln_html
        )
    
    def interactive_mode(self, packages: List[str]) -> List[str]:
        """Simple interactive package selection"""
        print(f"\n{Colors.info('📋 Interactive Package Selection')}")
        print("Available packages:")
        
        for i, pkg in enumerate(packages, 1):
            print(f"  {i:2d}. {pkg}")
        
        try:
            selection = input(f"\n{Colors.BOLD}Enter package numbers (comma-separated) or 'all':{Colors.RESET} ").strip()
            
            if selection.lower() == 'all':
                return packages
            
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            selected = [packages[i] for i in indices if 0 <= i < len(packages)]
            
            print(f"{Colors.success(f'Selected {len(selected)} packages')}")
            return selected
            
        except (ValueError, IndexError, KeyboardInterrupt):
            print(f"{Colors.warning('Invalid selection or cancelled. Using all packages.')}")
            return packages
    
    def run(self, args):
        """Execute optimized main program"""
        self.start_time = time.time()
        
        try:
            # Load configuration
            if args.config:
                config_path = Path(args.config)
                if config_path.exists():
                    self.config = self.load_config_file(config_path)
                    if not self.config.quiet:
                        print(Colors.info(f"📁 Loaded config from {config_path}"))
            
            # Override with command line args
            if args.verbose:
                self.config.verbose = True
            if args.quiet:
                self.config.quiet = True
            if args.workers:
                self.config.max_workers = args.workers
            
            if not self.config.quiet:
                self.print_banner()
                print(Colors.info(f"⚙️  Workers: {self.config.max_workers}, Cache: {'ON' if self.config.cache_enabled else 'OFF'}"))
            
            # Clean cache if needed
            if self.cache:
                self.cache.cleanup_expired()
            
            # Collect packages
            packages = []
            
            if args.packages:
                packages.extend([pkg.strip() for pkg in args.packages.split(',')])
            
            if args.solution:
                sln_packages = self.parse_solution_file(args.solution)
                packages.extend(sln_packages)
                if not self.config.quiet:
                    print(Colors.info(f"📋 Found {len(sln_packages)} packages in solution"))
            
            if args.file:
                file_packages = self.parse_packages_from_file(args.file)
                packages.extend(file_packages)
                if not self.config.quiet:
                    print(Colors.info(f"📁 Loaded {len(file_packages)} packages from file"))
            
            if args.scan_dir:
                dir_packages = self.scan_directory_for_packages(args.scan_dir)
                packages.extend(dir_packages)
                if not self.config.quiet:
                    print(Colors.info(f"📂 Found {len(dir_packages)} packages in directory"))
            
            packages = list(set(packages))  # Remove duplicates
            
            if not packages:
                print(Colors.error("❌ No packages specified"))
                print(Colors.info("💡 Use --help for usage examples"))
                return 1
            
            # Interactive selection
            if args.interactive:
                packages = self.interactive_mode(packages)
            
            if not self.config.quiet:
                print(Colors.success(f"🚀 Starting scan of {len(packages)} packages..."))
            
            # Scan packages
            vulnerabilities = self.scan_packages_parallel(packages)
            
            # Display results
            if not self.config.quiet:
                self.display_vulnerabilities(vulnerabilities, detailed=self.config.verbose)
                self.display_summary(vulnerabilities, len(packages))
            
            # Export if requested
            if args.output:
                format_type = args.format or 'json'
                self.export_results(vulnerabilities, args.output, format_type)
            
            # Check exit conditions
            if args.fail_on_vuln and vulnerabilities:
                if not self.config.quiet:
                    print(Colors.error("🚫 Exiting with error due to vulnerabilities found"))
                return 1
            
            if not self.config.quiet:
                if vulnerabilities:
                    print(Colors.warning(f"\n⚠️  Scan completed with {len(vulnerabilities)} vulnerabilities"))
                else:
                    print(Colors.success("\n✅ Scan completed successfully - no vulnerabilities found!"))
            
            return 0
            
        except KeyboardInterrupt:
            self._interrupted = True
            print(Colors.warning("\n⚠️  Scan interrupted by user"))
            return 130
        except Exception as e:
            print(Colors.error(f"❌ Unexpected error: {e}"))
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

# Output settings
verbose = false
quiet = false
"""
    
    with open('.nugetcli.config', 'w') as f:
        f.write(config_content)
    
    print(Colors.success("✅ Sample configuration created: .nugetcli.config"))


def create_sample_files():
    """Create sample package files"""
    sample_packages = [
        "serilog.4.3.0",
        "newtonsoft.json.13.0.1", 
        "microsoft.aspnetcore.app.2.1.0",
        "system.text.json.6.0.0",
        "log4net.2.0.8"
    ]
    
    # Text file
    with open('sample_packages.txt', 'w') as f:
        f.write("# Sample NuGet package list\n")
        for pkg in sample_packages:
            f.write(f"{pkg}\n")
    
    # JSON file
    with open('sample_packages.json', 'w') as f:
        json.dump({"packages": sample_packages}, f, indent=2)
    
    print("✅ Sample files created:")
    print("  • sample_packages.txt")
    print("  • sample_packages.json")


def main():
    """Optimized main function"""
    parser = argparse.ArgumentParser(
        description='🔍 NuGet Vulnerability Scanner - Optimized CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🚀 Optimized Features:
  • Minimal dependencies (only requests + standard library)
  • Enhanced terminal UI with built-in progress bars
  • SQLite caching for faster repeated scans
  • Parallel processing with automatic worker optimization
  • Solution file (.sln) and project scanning
  • Interactive package selection
  • Multiple export formats: JSON, CSV, HTML, Markdown
  • Cross-platform color support with fallbacks

📋 Usage Examples:
  %(prog)s -p "serilog.4.3.0,newtonsoft.json.13.0.1"
  %(prog)s --solution MyProject.sln -o report.html --format html
  %(prog)s -f packages.txt --interactive -v
  %(prog)s --scan-dir ./src --workers 10 -o results.json
  %(prog)s --clear-cache  # Clear cached data
  %(prog)s --create-config  # Generate sample config
        """
    )
    
    # Input options
    input_group = parser.add_argument_group('📥 Input Options')
    input_group.add_argument('-p', '--packages', help='Comma-separated package list')
    input_group.add_argument('--solution', help='Path to .NET solution file (.sln)')
    input_group.add_argument('-f', '--file', help='Read package list from file')
    input_group.add_argument('--scan-dir', help='Scan directory for packages')
    input_group.add_argument('-i', '--interactive', action='store_true', help='Interactive package selection')
    
    # Output options
    output_group = parser.add_argument_group('📤 Output Options')
    output_group.add_argument('-o', '--output', help='Output file path')
    output_group.add_argument('--format', choices=['json', 'csv', 'html', 'markdown'], help='Output format')
    output_group.add_argument('-v', '--verbose', action='store_true', help='Detailed output')
    output_group.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    
    # Performance options
    perf_group = parser.add_argument_group('⚡ Performance Options')
    perf_group.add_argument('--workers', type=int, help='Number of parallel workers')
    perf_group.add_argument('--no-cache', action='store_true', help='Disable caching')
    perf_group.add_argument('--clear-cache', action='store_true', help='Clear cache and exit')
    
    # Configuration options
    config_group = parser.add_argument_group('⚙️  Configuration Options')
    config_group.add_argument('--config', help='Configuration file path')
    config_group.add_argument('--create-config', action='store_true', help='Create sample config')
    config_group.add_argument('--fail-on-vuln', action='store_true', help='Exit with error if vulnerabilities found')
    config_group.add_argument('--create-samples', action='store_true', help='Create sample files')
    
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
        print(Colors.success("✅ Cache cleared"))
        return 0
    
    # Validate input
    if not any([args.packages, args.solution, args.file, args.scan_dir]):
        print(Colors.error("❌ No input specified"))
        print(Colors.info("💡 Use --help for usage examples"))
        return 1
    
    # Create config
    config = Config(
        cache_enabled=not args.no_cache,
        max_workers=args.workers or 5,
        verbose=args.verbose,
        quiet=args.quiet
    )
    
    # Support environment variables for proxy
    if not config.proxy:
        config.proxy = os.environ.get('HTTP_PROXY') or os.environ.get('HTTPS_PROXY')
    
    # Execute scan
    try:
        cli = OptimizedNuGetCLI(config)
        return cli.run(args)
    except Exception as e:
        print(Colors.error(f"❌ Failed to initialize: {e}"))
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.warning('⚠️  Interrupted by user')}")
        sys.exit(130)
    except Exception as e:
        print(Colors.error(f"❌ Fatal error: {e}"))
        sys.exit(1)