# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NuGet Package Vulnerability Scanner - A comprehensive security tool that checks NuGet packages for known vulnerabilities across multiple vulnerability databases (NVD, OSV, GitHub Advisory, Snyk).

## Key Components

### Core Modules
- `vulnerability_checker.py` / `vulnerability_checker_en.py` - Core vulnerability scanning engine that queries multiple APIs
- `nuget_cli.py` / `nuget_cli_en.py` - Standard command-line interface (Chinese/English versions)
- `nuget_cli_en_improved.py` - Enhanced CLI with caching, parallel scanning, and advanced features (requires additional dependencies)
- `nuget_cli_optimized.py` - **RECOMMENDED** Optimized CLI with minimal dependencies and enhanced UI design
- `server.py` - Web server for browser-based interface
- `index.html` & `style.css` - Web UI components

### Architecture Patterns
- **Multi-source aggregation**: Queries 4 different vulnerability databases in parallel
- **Version parsing**: Handles various NuGet package naming conventions (package.version, package-version)
- **Conservative matching**: Includes potential matches when exact version info unavailable
- **ThreadPoolExecutor**: Used for concurrent API requests to improve performance

## Common Development Commands

### Running the Scanner

#### Optimized CLI (Recommended)
```bash
# Basic package scan with enhanced UI
python nuget_cli_optimized.py -p "serilog.4.3.0"

# Scan solution file with progress bar
python nuget_cli_optimized.py --solution MyProject.sln -o report.html --format html

# Interactive package selection
python nuget_cli_optimized.py -f packages.txt --interactive -v

# Parallel scanning with custom workers
python nuget_cli_optimized.py --scan-dir ./src --workers 10

# Generate markdown report
python nuget_cli_optimized.py -p "log4net.2.0.8" --format markdown -o report.md
```

#### Standard CLI
```bash
# Basic package scan
python nuget_cli_en.py -p "serilog.4.3.0"

# Scan from file
python nuget_cli_en.py -f packages.txt

# Scan directory for .csproj/.nupkg files
python nuget_cli_en.py --scan-dir ./MyProject

# Generate HTML report
python nuget_cli_en.py -p "log4net.2.0.8" --format html -o report.html
```

### Web Interface
```bash
# Start web server (runs on http://localhost:8000)
python server.py
```

### Dependencies

#### Optimized CLI (Minimal Dependencies)
```bash
# Only requires requests beyond standard library
pip install requests>=2.28.0

# Optional for vulnerability checker engine
pip install pandas>=1.5.0 packaging>=21.0
```

#### Standard CLI
```bash
# Install required packages for basic CLI
pip install -r requirements.txt
```

#### Enhanced CLI (Full Features)
```bash
# Enhanced CLI requires additional packages
pip install requests>=2.28.0 pandas>=1.5.0 packaging>=21.0 tqdm colorama
```

## Important Implementation Details

### API Rate Limiting
- NVD API: 0.5 second delay between requests
- GitHub API: Requires careful GraphQL query construction
- OSV/Snyk: No explicit delays but should monitor for 429 responses

### Version Comparison Logic
The code uses `packaging.version` for semantic version comparison. Key method: `_is_version_affected()` in vulnerability_checker.py handles:
- Exact version matches
- Version range checking
- Conservative matching when version info is incomplete

### Output Formats
- **Terminal**: Color-coded severity levels (CRITICAL=Red, HIGH=Purple, MEDIUM=Yellow, LOW=Green)
- **JSON**: Structured data with all vulnerability details
- **CSV**: Tabular format for spreadsheet analysis
- **HTML**: Professional reports with CSS styling and direct links to CVE databases
- **Markdown**: Clean, readable reports (enhanced CLI only)

### Error Handling
- All API calls wrapped in try-except blocks
- Network timeouts set to 10-30 seconds
- Graceful degradation if one API source fails
- Enhanced CLI includes retry logic with exponential backoff

## Testing Approach

Currently no automated tests. When implementing tests:
- Mock API responses for consistent testing
- Test version parsing edge cases
- Verify multi-source aggregation logic
- Check output format generation

## Security Considerations

- No API keys required (all APIs are public)
- No sensitive data stored
- Cache files stored in user home directory (~/.nuget-cli/cache)
- Proxy support available via config file

## Common Tasks

### Adding a New Vulnerability Source
1. Add new search method to `VulnerabilityChecker` class
2. Follow pattern of existing methods (search_nvd, search_osv, etc.)
3. Add to `check_vulnerabilities()` method
4. Update README documentation

### Modifying Output Formats
1. HTML templates are inline in the CLI classes
2. Color schemes defined in Colors class
3. Export methods follow pattern: `export_to_[format]()`

### Performance Optimization
- Enhanced CLI uses SQLite caching to reduce API calls
- Parallel processing with configurable worker count
- Connection pooling via requests.Session()

## Branch Information
Currently on `feature/enhanced-cli` branch which adds:
- Caching mechanism
- Progress bars
- Configuration file support
- Interactive mode
- Solution file scanning
- Advanced filtering options