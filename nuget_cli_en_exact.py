#!/usr/bin/env python3
"""
NuGet Package Vulnerability Scanner - Exact Version Matching CLI
This version only checks for exact version matches, no fuzzy or conservative matching.

Features:
- SQLite-based caching for faster repeated scans
- Parallel processing with configurable worker threads
- Solution file (.sln) scanning support
- Advanced filtering by severity, CVE patterns, and date ranges
- Configuration file support with .nugetcli.config
- Interactive package selection mode
- Multiple export formats: JSON, CSV, HTML, Markdown
- Retry logic with exponential backoff
- Progress bars and enhanced terminal output
- Proxy support for enterprise environments
- EXACT VERSION MATCHING ONLY - no conservative/fuzzy matching
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
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from functools import lru_cache
import configparser
import sqlite3
from contextlib import contextmanager

# Import verification and package listing
print("🔍 Loading NuGet Vulnerability Scanner CLI (Exact Version Matching)...")
print("📦 Imported packages:")
imported_packages = []

# Standard library imports
imported_packages.extend([
    'argparse', 'sys', 'os', 'json', 'csv', 'time', 'ast', 're', 'threading',
    'hashlib', 'pickle', 'signal', 'platform', 'datetime', 'pathlib', 'typing',
    'concurrent.futures', 'dataclasses', 'functools', 'configparser', 'sqlite3',
    'contextlib', 'xml.etree.ElementTree', 'random', 'multiprocessing', 'traceback'
])

# Third-party imports
try:
    import requests
    imported_packages.append('requests')
except ImportError as e:
    print(f"❌ Missing required dependency: {e}")
    print("Please install: pip install requests")
    sys.exit(1)

# Display imported packages
for pkg in sorted(imported_packages):
    print(f"  ✓ {pkg}")

# Display vulnerability checking URLs
print("\n🌐 Vulnerability sources to be checked:")
print("  • NVD (National Vulnerability Database)")
print("    └─ API: https://services.nvd.nist.gov/rest/json/cves/2.0")
print("  • OSV (Open Source Vulnerabilities)")
print("    └─ API: https://api.osv.dev/v1/query")
print("  • GitHub Advisory Database")
print("    └─ GraphQL API: https://api.github.com/graphql")
print("    └─ Search API: https://api.github.com/search/repositories")
print("  • Snyk Vulnerability Database")
print("    └─ Web scraping: https://security.snyk.io/package/nuget/{package_name}")
print("\n⚠️  NOTE: This version uses EXACT VERSION MATCHING ONLY")
print()

# Import the exact version vulnerability checker
from vulnerability_checker_en_exact import VulnerabilityCheckerExact

@dataclass
class Config:
    """Configuration settings for the vulnerability scanner"""
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
    rate_limit_delay: float = 0.1
    max_concurrent_requests: int = 10
    enable_progress_bar: bool = True
    
    def __post_init__(self):
        if self.exclude_sources is None:
            self.exclude_sources = []
        # Validate worker count based on system capabilities
        import multiprocessing
        max_cpus = multiprocessing.cpu_count()
        if self.max_workers > max_cpus * 2:
            self.max_workers = max_cpus * 2
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """Create config from dictionary"""
        return cls(**data)

class Colors:
    """Terminal color definitions using ANSI escape codes"""
    # ANSI color codes
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

class SimpleProgressBar:
    """Simple progress bar implementation without external dependencies"""
    
    def __init__(self, total: int, desc: str = "Progress", width: int = 50):
        self.total = total
        self.desc = desc
        self.width = width
        self.current = 0
        self.start_time = time.time()
        self._last_update_time = 0
        self._update_interval = 0.1  # Update at most every 100ms
        
    def update(self, current: int, **kwargs):
        """Update progress bar with current value and optional stats"""
        self.current = current
        current_time = time.time()
        
        # Rate limit updates to avoid excessive console output
        if current_time - self._last_update_time < self._update_interval:
            return
            
        self._last_update_time = current_time
        self._render(kwargs)
    
    def _render(self, stats: dict):
        """Render the progress bar to console"""
        if self.total == 0:
            percent = 100
        else:
            percent = int(100 * self.current / self.total)
        
        filled = int(self.width * self.current / max(self.total, 1))
        bar = '█' * filled + '░' * (self.width - filled)
        
        elapsed = time.time() - self.start_time
        if self.current > 0 and elapsed > 0:
            rate = self.current / elapsed
            eta = (self.total - self.current) / rate if rate > 0 else 0
            eta_str = self._format_time(eta)
        else:
            eta_str = "--:--"
        
        # Build status line with optional stats
        status_parts = [f"{self.current}/{self.total}"]
        if 'vulns' in stats:
            status_parts.append(f"{Colors.RED}vulns: {stats['vulns']}{Colors.RESET}")
        if 'failed' in stats:
            status_parts.append(f"{Colors.YELLOW}failed: {stats['failed']}{Colors.RESET}")
        
        status = " | ".join(status_parts)
        
        # Clear line and print progress
        sys.stdout.write('\r\033[K')  # Clear line
        sys.stdout.write(
            f"{self.desc} |{Colors.CYAN}{bar}{Colors.RESET}| "
            f"{percent}% {status} ETA: {eta_str}"
        )
        sys.stdout.flush()
    
    def finish(self):
        """Complete the progress bar"""
        self.current = self.total
        self._render({})
        sys.stdout.write('\n')
        sys.stdout.flush()
    
    def _format_time(self, seconds: float) -> str:
        """Format seconds into human-readable time"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds/60)}m {int(seconds%60)}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

class CacheManager:
    """Enhanced SQLite-based cache manager for vulnerability data"""
    
    def __init__(self, cache_dir: Path = None, ttl_hours: int = 24):
        self.cache_dir = cache_dir or Path.home() / '.nuget-cli' / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / 'vulnerabilities_exact.db'
        self.ttl = timedelta(hours=ttl_hours)
        self._lock = threading.Lock()
        self._init_db()
        self._stats = {'hits': 0, 'misses': 0, 'errors': 0}
    
    def _init_db(self):
        """Initialize cache database with enhanced schema"""
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    package_name TEXT,
                    data BLOB,
                    timestamp REAL,
                    access_count INTEGER DEFAULT 1,
                    last_accessed REAL DEFAULT (strftime('%s', 'now'))
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON cache(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_package ON cache(package_name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_access ON cache(last_accessed)')
            
            # Create metadata table for cache statistics
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            
            # Initialize version info
            conn.execute(
                'INSERT OR IGNORE INTO cache_metadata (key, value) VALUES (?, ?)',
                ('version', '2.0-exact')
            )
    
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
        """Get cached data if not expired with enhanced tracking"""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute(
                        'SELECT data, timestamp FROM cache WHERE key = ?',
                        (key,)
                    )
                    row = cursor.fetchone()
                    
                    if row:
                        data, timestamp = row
                        if datetime.fromtimestamp(timestamp) + self.ttl > datetime.now():
                            # Update access statistics
                            conn.execute(
                                'UPDATE cache SET access_count = access_count + 1, last_accessed = ? WHERE key = ?',
                                (datetime.now().timestamp(), key)
                            )
                            self._stats['hits'] += 1
                            return pickle.loads(data)
                        else:
                            # Clean up expired entry
                            conn.execute('DELETE FROM cache WHERE key = ?', (key,))
                    
                    self._stats['misses'] += 1
                    return None
            except Exception as e:
                self._stats['errors'] += 1
                print(Colors.warning(f"Cache error: {e}"))
                return None
    
    def set(self, key: str, data: Any, package_name: str = None):
        """Store data in cache with enhanced metadata"""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        'INSERT OR REPLACE INTO cache (key, package_name, data, timestamp) VALUES (?, ?, ?, ?)',
                        (key, package_name or 'unknown', pickle.dumps(data), datetime.now().timestamp())
                    )
            except Exception as e:
                self._stats['errors'] += 1
                print(Colors.warning(f"Cache write error: {e}"))
    
    def clear(self):
        """Clear all cache entries"""
        with self._get_connection() as conn:
            conn.execute('DELETE FROM cache')
    
    def cleanup_expired(self):
        """Remove expired cache entries with statistics"""
        cutoff = (datetime.now() - self.ttl).timestamp()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute('SELECT COUNT(*) FROM cache WHERE timestamp < ?', (cutoff,))
                    expired_count = cursor.fetchone()[0]
                    
                    conn.execute('DELETE FROM cache WHERE timestamp < ?', (cutoff,))
                    
                    if expired_count > 0:
                        print(Colors.info(f"🧹 Cleaned up {expired_count} expired cache entries"))
            except Exception as e:
                print(Colors.warning(f"Cache cleanup error: {e}"))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._get_connection() as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM cache')
            total_entries = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM cache WHERE timestamp > ?', 
                                ((datetime.now() - self.ttl).timestamp(),))
            valid_entries = cursor.fetchone()[0]
        
        return {
            'total_entries': total_entries,
            'valid_entries': valid_entries,
            'expired_entries': total_entries - valid_entries,
            'hit_rate': self._stats['hits'] / (self._stats['hits'] + self._stats['misses']) if (self._stats['hits'] + self._stats['misses']) > 0 else 0,
            **self._stats
        }
    
    def get_size_mb(self) -> float:
        """Get cache size in MB"""
        try:
            return self.db_path.stat().st_size / (1024 * 1024)
        except:
            return 0.0

class RetryHandler:
    """Enhanced retry handler with exponential backoff and jitter"""
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 60.0):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self._retry_stats = {'total_attempts': 0, 'total_retries': 0, 'failures': 0}
    
    def execute(self, func, *args, **kwargs):
        """Execute function with enhanced retry logic"""
        last_exception = None
        
        for attempt in range(self.max_attempts):
            self._retry_stats['total_attempts'] += 1
            try:
                result = func(*args, **kwargs)
                if attempt > 0:
                    self._retry_stats['total_retries'] += attempt
                return result
            except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
                last_exception = e
                if attempt < self.max_attempts - 1:
                    # Exponential backoff with jitter
                    import random
                    delay = min(self.base_delay * (2 ** attempt), self.max_delay)
                    jitter = random.uniform(0.1, 0.3) * delay
                    total_delay = delay + jitter
                    
                    print(Colors.warning(f"⚠️  Request failed (attempt {attempt + 1}/{self.max_attempts}), retrying in {total_delay:.1f}s..."))
                    time.sleep(total_delay)
                    continue
                else:
                    self._retry_stats['failures'] += 1
            except Exception as e:
                # Non-network errors shouldn't be retried
                last_exception = e
                self._retry_stats['failures'] += 1
                break
        
        raise last_exception
    
    def get_stats(self) -> Dict[str, int]:
        """Get retry statistics"""
        return self._retry_stats.copy()

class ExactNuGetCLI:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.checker = VulnerabilityCheckerExact()
        self.cache = CacheManager(ttl_hours=self.config.cache_ttl_hours) if self.config.cache_enabled else None
        self.retry_handler = RetryHandler(self.config.retry_attempts, self.config.retry_delay)
        self.start_time = None
        self._interrupted = False
        self._setup_proxy()
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self._interrupted = True
            print(Colors.warning("\n⚠️  Scan interrupted by user. Cleaning up..."))
            if self.cache:
                print(Colors.info("💾 Saving cache state..."))
        
        signal.signal(signal.SIGINT, signal_handler)
        if platform.system() != 'Windows':
            signal.signal(signal.SIGTERM, signal_handler)
    
    def _setup_proxy(self):
        """Setup proxy configuration"""
        if self.config.proxy:
            proxies = {
                'http': self.config.proxy,
                'https': self.config.proxy
            }
            self.checker.session.proxies.update(proxies)
    
    def fetch_package_dependencies(self, package_name: str, version: str) -> List[Dict[str, str]]:
        """Fetch dependencies for a NuGet package from NuGet.org API"""
        try:
            # NuGet V3 API endpoint for package metadata
            api_url = f"https://api.nuget.org/v3-flatcontainer/{package_name.lower()}/{version}/{package_name.lower()}.nuspec"
            
            response = self.checker.session.get(api_url, timeout=10)
            if response.status_code == 404:
                # Try alternative API endpoint
                catalog_url = f"https://api.nuget.org/v3/registration5-semver1/{package_name.lower()}/{version}.json"
                response = self.checker.session.get(catalog_url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    dependencies = []
                    
                    # Extract dependencies from catalog data
                    if 'catalogEntry' in data and 'dependencyGroups' in data['catalogEntry']:
                        for group in data['catalogEntry']['dependencyGroups']:
                            if 'dependencies' in group:
                                for dep in group['dependencies']:
                                    dep_name = dep.get('id', '')
                                    dep_range = dep.get('range', '')
                                    # Parse version range and get a specific version
                                    dep_version = self._parse_version_range(dep_range)
                                    if dep_name and dep_version:
                                        dependencies.append({
                                            'name': dep_name,
                                            'version': dep_version
                                        })
                    return dependencies
                    
            elif response.status_code == 200:
                # Parse nuspec XML
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.content)
                
                # Handle XML namespaces
                ns = {'ns': 'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'}
                if not root.find('.//ns:dependencies', ns):
                    ns = {'ns': 'http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd'}
                if not root.find('.//ns:dependencies', ns):
                    ns = {'ns': 'http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd'}
                
                dependencies = []
                for dep in root.findall('.//ns:dependency', ns):
                    dep_id = dep.get('id')
                    dep_version = dep.get('version', '')
                    
                    if dep_id:
                        # Parse version range
                        parsed_version = self._parse_version_range(dep_version)
                        if parsed_version:
                            dependencies.append({
                                'name': dep_id,
                                'version': parsed_version
                            })
                
                return dependencies
                
        except Exception as e:
            if not self.config.quiet:
                print(Colors.warning(f"⚠️  Could not fetch dependencies for {package_name}: {e}"))
        
        return []
    
    def _parse_version_range(self, version_range: str) -> Optional[str]:
        """Parse NuGet version range and return a specific version"""
        if not version_range:
            return None
            
        # Remove whitespace
        version_range = version_range.strip()
        
        # Handle exact version
        if not any(c in version_range for c in ['[', '(', ',', ')']):
            return version_range
            
        # Handle version ranges like [1.0.0, 2.0.0)
        if version_range.startswith('[') and ',' in version_range:
            # Extract minimum version
            min_version = version_range.split(',')[0].strip('[').strip()
            return min_version
            
        # Handle minimum version like (>= 1.0.0)
        if version_range.startswith('(') or version_range.startswith('['):
            version = version_range.strip('()[]').strip()
            if version.startswith('>='):
                return version[2:].strip()
            elif version.startswith('>'):
                return version[1:].strip()
                
        # Default: try to extract any version number
        import re
        match = re.search(r'(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)', version_range)
        if match:
            return match.group(1)
            
        return None
    
    def print_banner(self):
        """Display enhanced program banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║    NuGet Vulnerability Scanner CLI - Exact Version Only     ║
║              Precise Security Assessment Tool               ║
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
        """Check vulnerabilities with enhanced caching support"""
        package_name = package.split('.')[0] if '.' in package else package
        
        if self.cache:
            cache_key = hashlib.md5(package.encode('utf-8')).hexdigest()
            cached_result = self.cache.get(cache_key)
            
            if cached_result is not None:
                if not self.config.quiet:
                    print(Colors.info(f"💾 Using cached result for {package_name}"))
                return cached_result
        
        # Check for interruption
        if self._interrupted:
            return []
        
        # If not in cache or cache disabled, fetch from API
        try:
            result = self.retry_handler.execute(
                self.checker.check_vulnerabilities, [package]
            )
            
            if self.cache and result is not None:
                self.cache.set(cache_key, result, package_name)
            
            # Add small delay to respect rate limits
            time.sleep(self.config.rate_limit_delay)
            
            return result
        except Exception as e:
            if not self.config.quiet:
                print(Colors.error(f"❌ Error checking {package_name}: {e}"))
            return []
    
    def scan_packages_parallel(self, packages: List[str], scan_dependencies: bool = True) -> Tuple[List[Dict], Dict[str, Any]]:
        """Enhanced parallel package scanning with dependency checking"""
        all_vulnerabilities = []
        failed_packages = []
        start_time = time.time()
        
        # Track scanned packages to avoid duplicates
        scanned_packages = set()
        packages_to_scan = list(packages)
        dependency_map = {}  # Track package -> dependencies
        
        # Statistics tracking
        stats = {
            'total_packages': 0,
            'total_dependencies': 0,
            'vulnerable_packages': set(),
            'vulnerable_dependencies': set(),
            'safe_packages': set(),
            'safe_dependencies': set(),
            'failed_packages': [],
            'scan_time': 0,
            'dependency_depth': {}
        }
        
        # Process packages including dependencies
        while packages_to_scan:
            current_batch = []
            
            # Get next batch of unscanned packages
            for pkg in packages_to_scan[:]:
                if pkg not in scanned_packages:
                    current_batch.append(pkg)
                    scanned_packages.add(pkg)
                    packages_to_scan.remove(pkg)
            
            if not current_batch:
                break
            
            # Progress message
            if not self.config.quiet:
                if len(scanned_packages) > len(packages):
                    print(Colors.info(f"📦 Scanning {len(current_batch)} packages (including dependencies)..."))
            
            # Scan current batch
            batch_vulns, batch_failed = self._scan_batch_parallel(current_batch, scanned_packages)
            all_vulnerabilities.extend(batch_vulns)
            failed_packages.extend(batch_failed)
            
            # Fetch dependencies if enabled
            if scan_dependencies and not self._interrupted:
                for pkg in current_batch:
                    if pkg in batch_failed:
                        continue
                        
                    # Parse package name and version
                    package_name, version = self._parse_package_string(pkg)
                    if package_name and version:
                        deps = self.fetch_package_dependencies(package_name, version)
                        if deps:
                            dependency_map[pkg] = []
                            for dep in deps:
                                dep_string = f"{dep['name']}.{dep['version']}"
                                dependency_map[pkg].append(dep_string)
                                if dep_string not in scanned_packages:
                                    packages_to_scan.append(dep_string)
                                    if not self.config.quiet and self.config.verbose:
                                        print(Colors.info(f"  → Found dependency: {dep_string}"))
        
        # Calculate statistics
        stats['total_packages'] = len(packages)
        stats['total_dependencies'] = len(scanned_packages) - len(packages)
        stats['failed_packages'] = failed_packages
        stats['scan_time'] = time.time() - start_time
        
        # Categorize packages
        vuln_packages = set()
        for v in all_vulnerabilities:
            # Extract base package name without version for matching
            pkg_full = v.get('package', '')
            vuln_packages.add(pkg_full)
            # Also try to match with version
            if '.' in pkg_full:
                parts = pkg_full.split('.')
                if parts[-1].replace('.', '').isdigit():
                    base_name = '.'.join(parts[:-1])
                    vuln_packages.add(base_name)
        
        for pkg in packages:
            # Check if this package has any vulnerabilities
            has_vulns = False
            for v in all_vulnerabilities:
                vuln_pkg = v.get('package', '').lower()
                pkg_name = pkg.split('.')[0].lower() if '.' in pkg else pkg.lower()
                if vuln_pkg == pkg_name:
                    has_vulns = True
                    break
            
            if has_vulns:
                stats['vulnerable_packages'].add(pkg)
            elif pkg not in failed_packages:
                stats['safe_packages'].add(pkg)
        
        # Categorize dependencies
        for pkg in scanned_packages:
            if pkg not in packages and pkg not in failed_packages:
                # Check if this dependency has any vulnerabilities
                has_vulns = False
                for v in all_vulnerabilities:
                    vuln_pkg = v.get('package', '').lower()
                    pkg_name = pkg.split('.')[0].lower() if '.' in pkg else pkg.lower()
                    if vuln_pkg == pkg_name:
                        has_vulns = True
                        break
                
                if has_vulns:
                    stats['vulnerable_dependencies'].add(pkg)
                else:
                    stats['safe_dependencies'].add(pkg)
        
        # Summary
        if not self.config.quiet:
            print(Colors.info(f"⚙️  Total scan completed in {stats['scan_time']:.2f}s"))
            print(Colors.info(f"📊 Scanned {len(scanned_packages)} total packages ({stats['total_packages']} main + {stats['total_dependencies']} dependencies)"))
            
            if failed_packages:
                print(Colors.warning(f"⚠️  Failed to scan {len(failed_packages)} packages"))
        
        return all_vulnerabilities, stats
    
    def _scan_batch_parallel(self, packages: List[str], scanned_packages: set) -> Tuple[List[Dict], List[str]]:
        """Scan a batch of packages in parallel"""
        vulnerabilities = []
        failed_packages = []
        
        # Limit concurrent requests
        max_workers = min(self.config.max_workers, self.config.max_concurrent_requests)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_package = {
                executor.submit(self.check_with_cache, pkg): pkg 
                for pkg in packages
            }
            
            # Setup progress tracking
            progress_bar = None
            if not self.config.quiet and self.config.enable_progress_bar and len(packages) > 1:
                progress_bar = SimpleProgressBar(
                    total=len(packages),
                    desc="🔍 Scanning batch"
                )
            
            completed_count = 0
            for future in as_completed(future_to_package):
                if self._interrupted:
                    for f in future_to_package:
                        f.cancel()
                    break
                
                package = future_to_package[future]
                completed_count += 1
                
                try:
                    result = future.result(timeout=self.config.timeout)
                    if result:
                        vulnerabilities.extend(result)
                except Exception as e:
                    failed_packages.append(package)
                    if not self.config.quiet:
                        print(Colors.error(f"❌ Error scanning {package}: {e}"))
                
                if progress_bar:
                    progress_bar.update(
                        completed_count,
                        vulns=len(vulnerabilities),
                        failed=len(failed_packages)
                    )
            
            if progress_bar:
                progress_bar.finish()
        
        return vulnerabilities, failed_packages
    
    def _parse_package_string(self, package_string: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse package string to extract name and version"""
        # Handle various formats: package.version, package-version, package/version
        patterns = [
            r'^(.+?)\.(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)$',  # package.version
            r'^(.+?)-(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)$',   # package-version
            r'^(.+?)/(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)$',   # package/version
        ]
        
        for pattern in patterns:
            match = re.match(pattern, package_string)
            if match:
                return match.group(1), match.group(2)
        
        return None, None
    
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
        """Generate Markdown format report with package grouping"""
        # Group vulnerabilities by package
        package_groups = {}
        for vuln in vulnerabilities:
            pkg_key = f"{vuln.get('package', 'Unknown')} v{vuln.get('package_version', 'N/A')}"
            if pkg_key not in package_groups:
                package_groups[pkg_key] = []
            package_groups[pkg_key].append(vuln)
        
        # Generate report
        md_content = f"""# NuGet Vulnerability Scan Report (Exact Version Matching)

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Total Vulnerabilities:** {len(vulnerabilities)}  
**Affected Packages:** {len(package_groups)}  
**Matching Mode:** Exact Version Only

## Summary

### Severity Distribution

"""
        # Group by severity for summary
        severity_groups = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        # Summary table
        md_content += "| Severity | Count | Percentage |\n|----------|-------|------------|\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = len(severity_groups.get(severity, []))
            if count > 0:
                percentage = (count / len(vulnerabilities)) * 100
                md_content += f"| {severity} | {count} | {percentage:.1f}% |\n"
        
        # Affected packages summary
        md_content += "\n### Affected Packages\n\n"
        md_content += "| Package | Version | Vulnerabilities |\n|---------|---------|----------------|\n"
        for pkg_key, vulns in sorted(package_groups.items()):
            pkg_name = vulns[0].get('package', 'Unknown')
            pkg_version = vulns[0].get('package_version', 'N/A')
            md_content += f"| {pkg_name} | {pkg_version} | {len(vulns)} |\n"
        
        md_content += "\n## Detailed Findings\n\n"
        
        # Detailed vulnerabilities grouped by package
        for pkg_idx, (pkg_key, vulns) in enumerate(sorted(package_groups.items()), 1):
            md_content += f"### [{pkg_idx}] {pkg_key}\n\n"
            
            # Package severity summary
            pkg_sev_counts = {}
            for v in vulns:
                sev = v.get('severity', 'UNKNOWN')
                pkg_sev_counts[sev] = pkg_sev_counts.get(sev, 0) + 1
            
            sev_summary = " | ".join([f"**{sev}**: {count}" for sev, count in sorted(pkg_sev_counts.items())])
            md_content += f"**Severity Breakdown:** {sev_summary}\n\n"
            
            # List vulnerabilities
            for vuln in vulns:
                md_content += f"#### {vuln.get('cve_id', 'N/A')}\n\n"
                md_content += f"- **Severity:** {vuln.get('severity', 'UNKNOWN')}\n"
                md_content += f"- **CVSS Score:** {vuln.get('cvss_score', 'N/A')}\n"
                md_content += f"- **Source:** {vuln.get('source', 'Unknown')}\n"
                
                desc = vuln.get('description', 'N/A')
                if len(desc) > 200:
                    desc = desc[:200] + "..."
                md_content += f"- **Description:** {desc}\n"
                md_content += f"- **Reference:** [{vuln.get('link', 'N/A')}]({vuln.get('link', '#')})\n\n"
            
            md_content += "---\n\n"
        
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
    
    def display_summary(self, vulnerabilities: List[Dict], scan_stats: Dict[str, Any]):
        """Enhanced display scan summary with detailed statistics"""
        print("\n" + "="*80)
        print(Colors.info(Colors.BOLD + "📊 COMPREHENSIVE SCAN SUMMARY (EXACT VERSION MATCHING)"))
        print("="*80)
        
        # Extract statistics
        total_vulns = len(vulnerabilities)
        severity_counts = {}
        sources = set()
        cve_years = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            sources.add(vuln.get('source', 'Unknown'))
            
            # Extract year from CVE ID
            cve_id = vuln.get('cve_id', '')
            if cve_id.startswith('CVE-'):
                try:
                    year = cve_id.split('-')[1]
                    cve_years[year] = cve_years.get(year, 0) + 1
                except:
                    pass
        
        # Display main statistics table
        print(f"\n{Colors.BOLD}📋 PACKAGE STATISTICS{Colors.RESET}")
        print("┌─────────────────────────────┬──────────┬──────────────┬─────────────┐")
        print("│ Category                    │   Count  │ Vulnerable   │    Safe     │")
        print("├─────────────────────────────┼──────────┼──────────────┼─────────────┤")
        print(f"│ Main Packages              │    {scan_stats['total_packages']:>5} │ {Colors.RED}{len(scan_stats['vulnerable_packages']):>11}{Colors.RESET}  │ {Colors.GREEN}{len(scan_stats['safe_packages']):>11}{Colors.RESET} │")
        print(f"│ Dependencies               │    {scan_stats['total_dependencies']:>5} │ {Colors.RED}{len(scan_stats['vulnerable_dependencies']):>11}{Colors.RESET}  │ {Colors.GREEN}{len(scan_stats['safe_dependencies']):>11}{Colors.RESET} │")
        print("├─────────────────────────────┼──────────┼──────────────┼─────────────┤")
        total_scanned = scan_stats['total_packages'] + scan_stats['total_dependencies']
        total_vulnerable = len(scan_stats['vulnerable_packages']) + len(scan_stats['vulnerable_dependencies'])
        total_safe = len(scan_stats['safe_packages']) + len(scan_stats['safe_dependencies'])
        print(f"│ {Colors.BOLD}TOTAL{Colors.RESET}                       │ {Colors.BOLD}{total_scanned:>8}{Colors.RESET} │ {Colors.RED}{Colors.BOLD}{total_vulnerable:>11}{Colors.RESET}  │ {Colors.GREEN}{Colors.BOLD}{total_safe:>11}{Colors.RESET} │")
        print("└─────────────────────────────┴──────────┴──────────────┴─────────────┘")
        
        # Display vulnerable packages list if any
        if scan_stats['vulnerable_packages'] or scan_stats['vulnerable_dependencies']:
            print(f"\n{Colors.BOLD}⚠️  VULNERABLE PACKAGES{Colors.RESET}")
            if scan_stats['vulnerable_packages']:
                print(f"\n{Colors.RED}Main Packages:{Colors.RESET}")
                for pkg in sorted(scan_stats['vulnerable_packages']):
                    # Count vulnerabilities for this package
                    pkg_vuln_count = sum(1 for v in vulnerabilities if v.get('package', '').lower() == pkg.split('.')[0].lower())
                    print(f"  • {pkg} ({pkg_vuln_count} vulnerabilities)")
            
            if scan_stats['vulnerable_dependencies']:
                print(f"\n{Colors.RED}Dependencies:{Colors.RESET}")
                for pkg in sorted(scan_stats['vulnerable_dependencies']):
                    # Count vulnerabilities for this package
                    pkg_vuln_count = sum(1 for v in vulnerabilities if v.get('package', '').lower() == pkg.split('.')[0].lower())
                    print(f"  • {pkg} ({pkg_vuln_count} vulnerabilities)")
        
        # Display vulnerability statistics
        if total_vulns > 0:
            print(f"\n{Colors.BOLD}🚨 VULNERABILITY BREAKDOWN{Colors.RESET}")
            print("┌─────────────────────────────┬──────────┬─────────────────────────┐")
            print("│ Severity                    │   Count  │       Percentage        │")
            print("├─────────────────────────────┼──────────┼─────────────────────────┤")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    percentage = (count / total_vulns) * 100
                    color = self.get_severity_color(severity)
                    bar_length = int(percentage / 5)  # Max 20 chars for 100%
                    bar = '█' * bar_length + '░' * (20 - bar_length)
                    print(f"│ {color}{severity:<27}{Colors.RESET} │ {count:>8} │ {bar} {percentage:>5.1f}% │")
            print("├─────────────────────────────┼──────────┼─────────────────────────┤")
            print(f"│ {Colors.BOLD}TOTAL VULNERABILITIES{Colors.RESET}       │ {Colors.BOLD}{total_vulns:>8}{Colors.RESET} │                         │")
            print("└─────────────────────────────┴──────────┴─────────────────────────┘")
        
        # Data sources
        print(f"\n🌐 Data sources used: {Colors.BOLD}{', '.join(sorted(sources)) if sources else 'None'}{Colors.RESET}")
        print(f"🎯 Matching mode: {Colors.BOLD}EXACT VERSION ONLY{Colors.RESET}")
        
        # Severity distribution with percentages
        if severity_counts:
            print(f"\n🚨 Severity distribution:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    percentage = (count / total_vulns) * 100
                    color = self.get_severity_color(severity)
                    print(f"  {color}● {severity}: {count} ({percentage:.1f}%){Colors.RESET}")
        
        # CVE year distribution (top 5)
        if cve_years:
            print(f"\n📅 CVE year distribution (recent):")
            sorted_years = sorted(cve_years.items(), key=lambda x: x[0], reverse=True)[:5]
            for year, count in sorted_years:
                print(f"  📆 {year}: {count} vulnerabilities")
        
        # Risk assessment with recommendations
        risk_level = "LOW"
        risk_color = Colors.GREEN
        recommendations = []
        
        if severity_counts.get('CRITICAL', 0) > 0:
            risk_level = "CRITICAL"
            risk_color = Colors.RED
            recommendations.append("🚨 Immediate action required for CRITICAL vulnerabilities")
            recommendations.append("📋 Consider emergency patching or temporary mitigations")
        elif severity_counts.get('HIGH', 0) > 0:
            risk_level = "HIGH"
            risk_color = Colors.MAGENTA
            recommendations.append("⚡ Prioritize HIGH severity vulnerabilities for patching")
            recommendations.append("📅 Plan remediation within 30 days")
        elif severity_counts.get('MEDIUM', 0) > 0:
            risk_level = "MEDIUM"
            risk_color = Colors.YELLOW
            recommendations.append("📝 Schedule MEDIUM severity vulnerabilities for next maintenance window")
        else:
            recommendations.append("✅ No high-priority vulnerabilities found")
        
        print(f"\n⚡ Overall risk level: {risk_color}{Colors.BOLD}{risk_level}{Colors.RESET}")
        
        if recommendations:
            print(f"\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  {rec}")
        
        # Performance and cache statistics
        if self.cache:
            cache_stats = self.cache.get_stats()
            cache_size = self.cache.get_size_mb()
            print(f"\n📊 Performance Statistics:")
            print(f"  💾 Cache hit rate: {cache_stats['hit_rate']:.1%}")
            print(f"  📁 Cache size: {cache_size:.1f} MB")
            print(f"  🗃️  Cache entries: {cache_stats['valid_entries']}/{cache_stats['total_entries']}")
        
        # Execution time with performance metrics
        if self.start_time:
            duration = time.time() - self.start_time
            total_scanned = scan_stats['total_packages'] + scan_stats['total_dependencies']
            packages_per_second = total_scanned / duration if duration > 0 else 0
            print(f"\n⏱️  Performance:")
            print(f"  🕐 Scan duration: {Colors.BOLD}{duration:.2f} seconds{Colors.RESET}")
            print(f"  🚀 Throughput: {Colors.BOLD}{packages_per_second:.1f} packages/second{Colors.RESET}")
        
        # Retry statistics
        retry_stats = self.retry_handler.get_stats()
        if retry_stats['total_retries'] > 0:
            print(f"  🔄 Network retries: {retry_stats['total_retries']}/{retry_stats['total_attempts']} ({retry_stats['failures']} failures)")
    
    def display_vulnerabilities(self, vulnerabilities: List[Dict], detailed: bool = False):
        """Display vulnerability details grouped by package"""
        if not vulnerabilities:
            print(Colors.success(Colors.BOLD + "✅ No known vulnerabilities found!"))
            return
        
        print("\n" + "="*80)
        print(Colors.error(Colors.BOLD + "🔍 VULNERABILITIES FOUND (EXACT VERSION MATCHES)"))
        print("="*80)
        
        # Group vulnerabilities by package
        package_vulns = {}
        for vuln in vulnerabilities:
            pkg_key = f"{vuln.get('package', 'Unknown')} v{vuln.get('package_version', 'N/A')}"
            if pkg_key not in package_vulns:
                package_vulns[pkg_key] = []
            package_vulns[pkg_key].append(vuln)
        
        # Display vulnerabilities grouped by package
        vuln_count = 0
        for pkg_idx, (package_key, vulns) in enumerate(sorted(package_vulns.items()), 1):
            # Package header
            print(f"\n{Colors.BOLD}{Colors.CYAN}📦 [{pkg_idx}] {package_key}{Colors.RESET}")
            print(f"{Colors.BOLD}    Found {len(vulns)} vulnerabilities in this package{Colors.RESET}")
            print(f"    {'-'*60}")
            
            # Severity summary for this package
            pkg_severity_counts = {}
            for v in vulns:
                sev = v.get('severity', 'UNKNOWN').upper()
                pkg_severity_counts[sev] = pkg_severity_counts.get(sev, 0) + 1
            
            severity_summary = []
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if pkg_severity_counts.get(sev, 0) > 0:
                    color = self.get_severity_color(sev)
                    severity_summary.append(f"{color}{sev}: {pkg_severity_counts[sev]}{Colors.RESET}")
            
            if severity_summary:
                print(f"    📊 Severity breakdown: {' | '.join(severity_summary)}")
                print(f"    {'-'*60}")
            
            # Display each vulnerability
            for vuln in vulns:
                vuln_count += 1
                severity_color = self.get_severity_color(vuln.get('severity', 'UNKNOWN'))
                
                print(f"\n    {Colors.BOLD}[{vuln_count}] {vuln.get('cve_id', 'N/A')}{Colors.RESET}")
                print(f"        📊 CVSS Score: {Colors.BOLD}{vuln.get('cvss_score', 'N/A')}{Colors.RESET}")
                print(f"        🚨 Severity: {severity_color}{Colors.BOLD}{vuln.get('severity', 'UNKNOWN')}{Colors.RESET}")
                print(f"        🌐 Data Source: {Colors.BLUE}{Colors.BOLD}{vuln.get('source', 'Unknown')}{Colors.RESET}")
                
                if detailed:
                    description = vuln.get('description', 'N/A')
                    if len(description) > 100:
                        description = description[:100] + "..."
                    print(f"        📝 Description: {description}")
                
                # Always show links
                print(f"        🔗 Link: {Colors.CYAN}{Colors.BOLD}{vuln.get('link', 'N/A')}{Colors.RESET}")
    
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
                        'scanner_version': '2.0.0-exact',
                        'matching_mode': 'exact_version_only'
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
    <title>NuGet Vulnerability Scan Report - Exact Version</title>
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
        .exact-mode {{ background-color: #17a2b8; color: white; padding: 5px 10px; border-radius: 5px; margin-left: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NuGet Vulnerability Scan Report <span class="exact-mode">Exact Version Mode</span></h1>
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
            <p><strong>Matching Mode:</strong> Exact Version Only (No fuzzy matching)</p>
        </div>
        
        <div class="vulnerabilities">
            <h3>🚨 Vulnerability Details</h3>
            {vulnerability_list}
        </div>
        
        <div class="footer">
            <p>This report was generated by NuGet Vulnerability Scanner CLI (Exact Version Mode)</p>
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
        """Execute enhanced main program with improved error handling"""
        self.start_time = time.time()
        
        try:
            # Load config file if specified
            if args.config:
                config_path = Path(args.config)
                if config_path.exists():
                    self.config = self.load_config_file(config_path)
                    if not self.config.quiet:
                        print(Colors.info(f"📁 Loaded configuration from {config_path}"))
                else:
                    print(Colors.warning(f"⚠️  Configuration file not found: {config_path}"))
            
            # Override config with command line arguments
            if args.verbose:
                self.config.verbose = True
            if args.quiet:
                self.config.quiet = True
            if args.workers:
                self.config.max_workers = args.workers
            
            if not self.config.quiet:
                self.print_banner()
                # Display current configuration
                print(Colors.info(f"⚙️  Configuration: Workers={self.config.max_workers}, Cache={'enabled' if self.config.cache_enabled else 'disabled'}, TTL={self.config.cache_ttl_hours}h"))
                print(Colors.info(f"🎯 Matching Mode: EXACT VERSION ONLY"))
            
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
            
            # Execute vulnerability check with dependency scanning
            scan_dependencies = not getattr(args, 'no_dependencies', False)
            vulnerabilities, scan_stats = self.scan_packages_parallel(packages, scan_dependencies=scan_dependencies)
            
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
                self.display_summary(vulnerabilities, scan_stats)
            
            # Export results
            if args.output:
                format_type = args.format or 'json'
                self.export_results(vulnerabilities, args.output, format_type)
            
            # Check exit conditions
            exit_code = 0
            
            if args.fail_on_vuln and vulnerabilities:
                if not self.config.quiet:
                    print(Colors.error("🚫 Exiting with error code due to --fail-on-vuln flag"))
                exit_code = 1
            
            if self.config.fail_on_severity:
                severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                min_severity_index = severity_levels.index(self.config.fail_on_severity.upper())
                
                for vuln in vulnerabilities:
                    vuln_severity = vuln.get('severity', 'UNKNOWN').upper()
                    if vuln_severity in severity_levels:
                        if severity_levels.index(vuln_severity) >= min_severity_index:
                            if not self.config.quiet:
                                print(Colors.error(f"🚫 Exiting with error code due to {vuln_severity} severity vulnerability (threshold: {self.config.fail_on_severity})"))
                            exit_code = 1
                            break
            
            # Final summary
            if not self.config.quiet and not self._interrupted:
                if exit_code == 0:
                    print(Colors.success("\n✅ Scan completed successfully!"))
                else:
                    print(Colors.error("\n❌ Scan completed with issues"))
            
            return exit_code
            
        except KeyboardInterrupt:
            self._interrupted = True
            print(Colors.warning("\n⚠️  Scan interrupted by user"))
            return 130
        except Exception as e:
            print(Colors.error(f"❌ Unexpected error during scan: {e}"))
            if self.config.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            # Cleanup operations
            if self.cache and not self.config.quiet:
                cache_stats = self.cache.get_stats()
                if cache_stats['total_entries'] > 0:
                    print(Colors.info(f"💾 Cache performance: {cache_stats['hit_rate']:.1%} hit rate, {cache_stats['valid_entries']} entries"))

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
    with open('sample_packages_exact.txt', 'w', encoding='utf-8') as f:
        f.write("# NuGet Package List Sample - Exact Version Matching\n")
        f.write("# One package per line, comments supported\n\n")
        for pkg in sample_packages:
            f.write(f"{pkg}\n")
    
    # Create sample JSON file
    sample_json = {
        "packages": sample_packages,
        "description": "Sample NuGet package list for exact version vulnerability scanning"
    }
    
    with open('sample_packages_exact.json', 'w', encoding='utf-8') as f:
        json.dump(sample_json, f, ensure_ascii=False, indent=2)
    
    print("✅ Sample files created:")
    print("  • sample_packages_exact.txt")
    print("  • sample_packages_exact.json")

def main():
    """Enhanced main function with comprehensive argument parsing"""
    parser = argparse.ArgumentParser(
        description='NuGet Package Vulnerability Scanner - Exact Version Matching CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎯 EXACT VERSION MATCHING MODE:
  This version only reports vulnerabilities for EXACT version matches.
  No fuzzy or conservative matching is performed.
  
🚀 Enhanced Features:
  • SQLite-based caching for 10x faster repeated scans
  • Parallel processing with configurable worker threads
  • Solution file (.sln) and project file scanning
  • Advanced filtering by severity, CVE patterns, and dates
  • Configuration file support with .nugetcli.config
  • Retry logic with exponential backoff and jitter
  • Interactive package selection mode
  • Multiple export formats: JSON, CSV, HTML, Markdown
  • Progress bars and enhanced terminal output
  • Network proxy support for enterprise environments
  • Graceful signal handling and interruption
  • Comprehensive statistics and performance metrics

📋 Usage Examples:
  %(prog)s -p "serilog.4.3.0,newtonsoft.json.13.0.1"
  %(prog)s --solution MyProject.sln -o security-report.md --format markdown
  %(prog)s -f packages.txt --filter-severity HIGH --fail-on-severity CRITICAL
  %(prog)s --scan-dir ./src --interactive --config .nugetcli.config -v
  %(prog)s -p "log4net.2.0.8" --no-cache --workers 10 --timeout 60
  %(prog)s --clear-cache  # Clear cached vulnerability data
  %(prog)s --create-config  # Generate sample configuration file

🔧 Configuration:
  Create .nugetcli.config file with settings for cache, proxy, workers, etc.
  Use --create-config to generate a sample configuration file.

🌐 Enterprise Support:
  Set proxy configuration in config file or environment variables.
  Supports HTTP_PROXY and HTTPS_PROXY environment variables.
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
    behavior_group.add_argument('--no-dependencies', action='store_true',
                              help='Skip scanning package dependencies')
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
    
    # Validate arguments
    if not any([args.packages, args.solution, args.list_format, args.file, args.scan_dir]):
        print(Colors.error("❌ No input specified. Please provide packages, files, or directories to scan."))
        print(Colors.info("💡 Use --help for usage examples and options."))
        parser.print_help()
        return 1
    
    # Validate worker count
    if args.workers and args.workers < 1:
        print(Colors.error("❌ Worker count must be at least 1"))
        return 1
    
    if args.workers and args.workers > 50:
        print(Colors.warning("⚠️  High worker count may overwhelm APIs. Consider using 10 or fewer workers."))
    
    # Environment variable support for proxy
    if not config.proxy:
        config.proxy = os.environ.get('HTTP_PROXY') or os.environ.get('HTTPS_PROXY')
    
    try:
        # Execute scan
        cli = ExactNuGetCLI(config)
        return cli.run(args)
    except Exception as e:
        print(Colors.error(f"❌ Failed to initialize scanner: {e}"))
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(Colors.warning("\n⚠️  Program interrupted by user"))
        sys.exit(130)
    except Exception as e:
        print(Colors.error(f"❌ Fatal error: {e}"))
        sys.exit(1)