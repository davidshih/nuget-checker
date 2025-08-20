# NuGet Vulnerability Scan Report

**Generated:** 2025-05-27 05:18:53  
**Total Vulnerabilities:** 8  
**Affected Packages:** 2

## Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| CRITICAL | 3 | 37.5% |
| HIGH | 2 | 25.0% |
| MEDIUM | 2 | 25.0% |

### Affected Packages

| Package | Version | Vulnerabilities |
|---------|---------|----------------|
| log4net | 2.0.8 | 7 |
| newtonsoft.json | 13.0.1 | 1 |

## Detailed Findings

### [1] log4net v2.0.8

**Severity Breakdown:** **CRITICAL**: 3 | **HIGH**: 1 | **MEDIUM**: 2 | **MODERATE**: 1

#### CVE-2021-44228

- **Severity:** CRITICAL
- **CVSS Score:** 10.0
- **Source:** NVD
- **Description:** Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker control...
- **Note:** ⚠️ Conservative match - package name matches but no specific version range found
- **Reference:** [https://nvd.nist.gov/vuln/detail/CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)

#### CVE-2018-1285

- **Severity:** CRITICAL
- **CVSS Score:** 9.8
- **Source:** NVD
- **Description:** Apache log4net versions before 2.0.10 do not disable XML external entities when parsing log4net configuration files. This allows for XXE-based attacks in applications that accept attacker-controlled l...
- **Reference:** [https://nvd.nist.gov/vuln/detail/CVE-2018-1285](https://nvd.nist.gov/vuln/detail/CVE-2018-1285)

#### GHSA-2cwj-8chv-9pp9

- **Severity:** CRITICAL
- **CVSS Score:** 9.5
- **Source:** OSV
- **Description:** XML External Entity attack in log4net
- **Reference:** [https://osv.dev/vulnerability/GHSA-2cwj-8chv-9pp9](https://osv.dev/vulnerability/GHSA-2cwj-8chv-9pp9)

#### CVE-2023-45253

- **Severity:** HIGH
- **CVSS Score:** 7.8
- **Source:** NVD
- **Description:** An issue was discovered in Huddly HuddlyCameraService before version 8.0.7, not including version 7.99, allows attackers to manipulate files and escalate privileges via RollingFileAppender.DeleteFile ...
- **Reference:** [https://nvd.nist.gov/vuln/detail/CVE-2023-45253](https://nvd.nist.gov/vuln/detail/CVE-2023-45253)

#### CVE-2021-44028

- **Severity:** MEDIUM
- **CVSS Score:** 5.5
- **Source:** NVD
- **Description:** XXE can occur in Quest KACE Desktop Authority before 11.2 because the log4net configuration file might be controlled by an attacker, a related issue to CVE-2018-1285.
- **Note:** ⚠️ Conservative match - package name matches but no specific version range found
- **Reference:** [https://nvd.nist.gov/vuln/detail/CVE-2021-44028](https://nvd.nist.gov/vuln/detail/CVE-2021-44028)

#### CVE-2006-0743

- **Severity:** MEDIUM
- **CVSS Score:** 5.0
- **Source:** NVD
- **Description:** Format string vulnerability in LocalSyslogAppender in Apache log4net 1.2.9 might allow remote attackers to cause a denial of service (memory corruption and termination) via unknown vectors.
- **Note:** ⚠️ Conservative match - package name matches but no specific version range found
- **Reference:** [https://nvd.nist.gov/vuln/detail/CVE-2006-0743](https://nvd.nist.gov/vuln/detail/CVE-2006-0743)

#### GHSA-f9fr-w54q-772h

- **Severity:** MODERATE
- **CVSS Score:** 5.0
- **Source:** OSV
- **Description:** Apache log4net format string vulnerability causes DoS
- **Reference:** [https://osv.dev/vulnerability/GHSA-f9fr-w54q-772h](https://osv.dev/vulnerability/GHSA-f9fr-w54q-772h)

---

### [2] newtonsoft.json v13.0.1

**Severity Breakdown:** **HIGH**: 1

#### CVE-2024-21907

- **Severity:** HIGH
- **CVSS Score:** 7.5
- **Source:** NVD
- **Description:** Newtonsoft.Json before version 13.0.1 is affected by a mishandling of exceptional conditions vulnerability. Crafted data that is passed to the JsonConvert.DeserializeObject method may trigger a StackO...
- **Note:** ⚠️ Conservative match - package name matches but no specific version range found
- **Reference:** [https://nvd.nist.gov/vuln/detail/CVE-2024-21907](https://nvd.nist.gov/vuln/detail/CVE-2024-21907)

---

