# NuGet Package Vulnerability Scanner

A comprehensive NuGet package vulnerability scanning tool with both web interface and command-line capabilities.

## Features

🔍 **Multi-Source Vulnerability Detection**
- National Vulnerability Database (NVD)
- Open Source Vulnerabilities (OSV)
- GitHub Advisory Database
- Snyk Vulnerability Database

📦 **Multiple Input Formats**
- Direct package specification
- Text file input (.txt)
- JSON file input (.json)
- CSV file input (.csv)
- Automatic project directory scanning

📊 **Rich Output Options**
- Colorized terminal display
- JSON format reports
- CSV format reports
- HTML format reports with detailed findings

⚡ **Intelligent Version Analysis**
- Automatic package version parsing
- Precise vulnerability impact assessment
- Support for multiple version formats

🌐 **Comprehensive Source Coverage**
- Queries all major vulnerability databases
- Shows findings from each source with validation links
- Eliminates duplicate findings across sources

## Installation

```bash
pip install -r requirements.txt
```

### Dependencies
- requests >= 2.28.0
- pandas >= 1.5.0
- packaging >= 21.0

## Usage

### 1. Command Line Interface (Recommended)

#### Basic Usage

```bash
# Check single package
python nuget_cli_en.py -p "serilog.4.3.0"

# Check multiple packages
python nuget_cli_en.py -p "serilog.4.3.0,newtonsoft.json.13.0.1"

# Read from file
python nuget_cli_en.py -f packages.txt

# Scan project directory
python nuget_cli_en.py --scan-dir ./MyProject

# Verbose mode with detailed descriptions
python nuget_cli_en.py -p "log4net.2.0.8" -v

# Quiet mode (results only)
python nuget_cli_en.py -p "serilog.4.3.0" -q
```

#### Export Reports

```bash
# Generate JSON report
python nuget_cli_en.py -p "log4net.2.0.8" -o security_report.json

# Generate CSV report
python nuget_cli_en.py -f packages.txt --format csv -o vulnerabilities.csv

# Generate HTML report with all findings
python nuget_cli_en.py --scan-dir ./MyProject --format html -o security_assessment.html
```

#### CI/CD Integration

```bash
# Exit with non-zero code when vulnerabilities found (for CI/CD)
python nuget_cli_en.py -p "log4net.2.0.8" --fail-on-vuln

# Automated scanning with report generation
python nuget_cli_en.py --scan-dir . --format json -o scan_results.json --fail-on-vuln
```

#### Sample Files

```bash
# Create sample package list files
python nuget_cli_en.py --create-samples
```

### 2. Web Interface

```bash
# Start web server
python server.py

# Open browser to http://localhost:8000
```

## Input File Formats

### Text File (.txt)
```
# NuGet Package List
# Comments supported
serilog.4.3.0
newtonsoft.json.13.0.1
log4net.2.0.8
```

### JSON File (.json)
```json
{
  "packages": [
    "serilog.4.3.0",
    "newtonsoft.json.13.0.1",
    "log4net.2.0.8"
  ],
  "description": "Project package list for security scanning"
}
```

### CSV File (.csv)
```csv
package_name
serilog.4.3.0
newtonsoft.json.13.0.1
log4net.2.0.8
```

## Supported Project Files

The tool automatically scans for:

- **`.nupkg`** - NuGet package files
- **`packages.config`** - Legacy NuGet configuration files
- **`.csproj`** - .NET project files with PackageReference elements

## Command Line Arguments

### Input Options
- `-p, --packages` - Package list, comma separated
- `-f, --file` - Read package list from file
- `--scan-dir` - Scan directory for NuGet package files

### Output Options
- `-o, --output` - Output file path
- `--format` - Output format (json/csv/html)
- `-v, --verbose` - Show detailed information
- `-q, --quiet` - Quiet mode

### Behavior Options
- `--fail-on-vuln` - Exit with non-zero code when vulnerabilities found
- `--create-samples` - Create sample files

## Example Output

### Terminal Output
```
╔══════════════════════════════════════════════════════════════╗
║                  NuGet Vulnerability Scanner CLI            ║
║                     Security Assessment Tool v1.0           ║
╚══════════════════════════════════════════════════════════════╝

🚀 Starting scan of 1 packages...

================================================================================
🔍 VULNERABILITIES FOUND
================================================================================

📦 Package: log4net (v2.0.8)
------------------------------------------------------------

  [1] CVE-2021-44228
      🚨 Severity: CRITICAL
      📊 CVSS Score: 10.0
      🌐 Source: NVD
      🔗 Details: https://nvd.nist.gov/vuln/detail/CVE-2021-44228

  [2] CVE-2018-1285
      🚨 Severity: CRITICAL
      📊 CVSS Score: 9.8
      🌐 Source: NVD
      🔗 Details: https://nvd.nist.gov/vuln/detail/CVE-2018-1285

================================================================================
📊 SCAN SUMMARY
================================================================================
📦 Packages scanned: 1
🔍 Vulnerabilities found: 2
⚠️  Affected packages: 1
🌐 Data sources: NVD, OSV

🚨 Severity distribution:
  ● CRITICAL: 2

⚡ Overall risk level: CRITICAL
⏱️  Scan duration: 3.45 seconds
```

## Vulnerability Severity Levels

| Level | CVSS Score Range | Color | Description |
|-------|------------------|-------|-------------|
| CRITICAL | 9.0 - 10.0 | 🔴 Red | Extremely severe, immediate action required |
| HIGH | 7.0 - 8.9 | 🟣 Purple | High risk, priority remediation |
| MEDIUM | 4.0 - 6.9 | 🟡 Yellow | Medium risk, recommended remediation |
| LOW | 0.1 - 3.9 | 🟢 Green | Low risk, can be deferred |

## Real-World Examples

### Example 1: Critical Vulnerability Detection
```bash
python nuget_cli_en.py -p "log4net.2.0.8" -v
```

**Findings:**
- **CVE-2021-44228** (Log4Shell) - CRITICAL (10.0 CVSS)
- **CVE-2018-1285** (XXE Attack) - CRITICAL (9.8 CVSS)
- Multiple additional vulnerabilities from NVD and OSV sources

### Example 2: Comprehensive Project Scan
```bash
python nuget_cli_en.py --scan-dir ./MyDotNetProject --format html -o security_report.html
```

**Results:**
- Scans all `.csproj`, `packages.config`, and `.nupkg` files
- Generates professional HTML report with:
  - Executive summary with statistics
  - Detailed vulnerability listings grouped by package
  - Direct links to vulnerability databases for validation
  - Severity-based color coding

### Example 3: CI/CD Pipeline Integration
```bash
#!/bin/bash
# Security scan in CI/CD pipeline
python nuget_cli_en.py --scan-dir . --format json -o security_scan.json --fail-on-vuln

if [ $? -ne 0 ]; then
    echo "❌ Security vulnerabilities detected! Build failed."
    echo "📄 Check security_scan.json for details"
    exit 1
else
    echo "✅ No vulnerabilities found. Build can proceed."
fi
```

## Data Sources and Validation

### National Vulnerability Database (NVD)
- **URL Format:** `https://nvd.nist.gov/vuln/detail/{CVE-ID}`
- **Coverage:** Comprehensive CVE database maintained by NIST
- **Update Frequency:** Real-time

### Open Source Vulnerabilities (OSV)
- **URL Format:** `https://osv.dev/vulnerability/{VULN-ID}`
- **Coverage:** Open source specific vulnerabilities
- **Update Frequency:** Continuous integration with major repositories

### GitHub Advisory Database
- **URL Format:** `https://github.com/advisories/{GHSA-ID}`
- **Coverage:** GitHub-discovered and community-reported vulnerabilities
- **Update Frequency:** Real-time

### Snyk Vulnerability Database
- **URL Format:** `https://security.snyk.io/vuln/{SNYK-ID}`
- **Coverage:** Commercial vulnerability intelligence
- **Update Frequency:** Continuous

## Troubleshooting

### Common Issues

**Q: Why are some packages not showing vulnerabilities?**
A: Possible reasons:
- Package name spelling errors
- Incorrect version format
- Package genuinely has no known vulnerabilities
- Temporary API unavailability

**Q: Scan is running slowly**
A: The tool queries multiple sources in parallel but is limited by API rate limits:
- Reduce number of packages scanned simultaneously
- Check network connectivity
- Wait for API rate limits to reset

**Q: Getting false positives**
A: Some CVEs may have similar names but affect different packages:
- Review the vulnerability description
- Check the provided validation links
- Verify package name matches exactly

**Q: How to use in enterprise environments?**
A: Consider:
- Configure HTTP proxy settings
- Use internal vulnerability databases
- Set up automated scheduled scans
- Integrate with existing security tools

## Advanced Usage

### Custom Package Lists
```bash
# Create comprehensive package inventory
find . -name "*.csproj" -exec grep -H "PackageReference" {} \; > package_inventory.txt

# Scan the inventory
python nuget_cli_en.py -f package_inventory.txt --format html -o comprehensive_report.html
```

### Automated Reporting
```bash
# Daily security scan with email notification
python nuget_cli_en.py --scan-dir /path/to/projects \
    --format html -o "daily_scan_$(date +%Y%m%d).html" \
    && mail -s "Daily Security Scan" security@company.com < daily_scan_$(date +%Y%m%d).html
```

### Integration with Security Tools
```bash
# Export to SARIF format for integration with security platforms
python nuget_cli_en.py --scan-dir . --format json -o scan.json
# Convert to SARIF using custom script
python convert_to_sarif.py scan.json > results.sarif
```

## Project Structure

```
nuget-checker/
├── nuget_cli_en.py           # English CLI main program
├── nuget_cli.py              # Chinese CLI version
├── vulnerability_checker.py  # Core vulnerability checking logic
├── server.py                 # Web server
├── index.html                # Web interface
├── style.css                 # Stylesheet
├── requirements.txt          # Dependencies
├── README.md                 # Chinese documentation
├── README_EN.md              # English documentation
└── sample_packages_en.txt    # Sample package list
```

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

### Adding New Vulnerability Sources

To add a new vulnerability database:

1. Extend the `EnhancedVulnerabilityChecker` class
2. Implement a new `search_[source_name]` method
3. Add the source to the comprehensive check method
4. Update documentation

## License

This project is licensed under the MIT License.

## Changelog

### v1.0.0
- Initial release
- Multi-source vulnerability scanning
- Command-line and web interfaces
- Multiple input/output formats
- Comprehensive reporting with validation links
- CI/CD integration support

## Security Notice

This tool is designed to help identify known vulnerabilities in NuGet packages. However:

- **Not a substitute for comprehensive security testing**
- **May have false positives/negatives**
- **Requires manual verification of findings**
- **Should be part of a broader security strategy**

Always verify findings through the provided validation links and consult with security professionals for critical applications.
