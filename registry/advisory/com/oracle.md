---
type: advisory
namespace: oracle.com
full_name: "Oracle Corporation"
operator: "secid:entity/oracle.com"
website: "https://www.oracle.com"
status: active

sources:
  cpu:
    full_name: "Oracle Critical Patch Update"
    urls:
      website: "https://www.oracle.com/security-alerts/"
      lookup: "https://www.oracle.com/security-alerts/cpujan{year}.html"
    id_pattern: "(jan|apr|jul|oct)\\d{4}"
    examples:
      - "secid:advisory/oracle.com/cpu#jan2024"
      - "secid:advisory/oracle.com/cpu#oct2023"
      - "secid:advisory/oracle.com/cpu#apr2024"
  alert:
    full_name: "Oracle Security Alert"
    urls:
      website: "https://www.oracle.com/security-alerts/"
      lookup: "https://www.oracle.com/security-alerts/alert-{id}.html"
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    examples:
      - "secid:advisory/oracle.com/alert#CVE-2024-1234"
      - "secid:advisory/oracle.com/alert#CVE-2021-44228"

  linux:
    full_name: "Oracle Linux Security Advisories"
    urls:
      website: "https://linux.oracle.com/security/"
      errata: "https://linux.oracle.com/errata/"
      lookup: "https://linux.oracle.com/errata/{id}.html"
    id_pattern: "ELSA-\\d{4}-\\d+"
    examples:
      - "secid:advisory/oracle.com/linux#ELSA-2024-1234"

  vm:
    full_name: "Oracle VM Security Advisories"
    urls:
      website: "https://www.oracle.com/security-alerts/"
    id_pattern: "OVMSA-\\d{4}-\\d+"
    examples:
      - "secid:advisory/oracle.com/vm#OVMSA-2024-0001"
---

# Oracle Advisory Sources

Oracle is a major enterprise software company known for databases, middleware, enterprise applications, and cloud services. Oracle releases security patches quarterly through Critical Patch Updates (CPUs).

## Why Oracle Matters for Security

Oracle software is deeply embedded in enterprise infrastructure:

- **Oracle Database** - Widely used enterprise database
- **Java** - Oracle owns and maintains Java SE
- **WebLogic** - Enterprise application server (frequent target)
- **MySQL** - Popular open-source database (Oracle-owned)
- **Oracle Cloud** - Enterprise cloud platform

## Critical Patch Update (CPU) Schedule

Oracle releases CPUs quarterly on predictable dates:
- January (third Tuesday)
- April (third Tuesday)
- July (third Tuesday)
- October (third Tuesday)

Each CPU bundles fixes for many CVEs across all Oracle products.

## Security Alerts

For critical vulnerabilities (like Log4Shell), Oracle issues Security Alerts outside the CPU schedule. These are reserved for issues too urgent to wait for the next quarterly release.

## Notes

- Oracle CPUs often fix hundreds of CVEs at once
- WebLogic vulnerabilities are frequently exploited in the wild
- Java vulnerabilities affect many applications beyond Oracle products

---

## cpu

Oracle's quarterly security patch releases.

### Format

```
secid:advisory/oracle.com/cpu#MMMYYYY
```

Month (jan, apr, jul, oct) and year. CPUs are released quarterly.

### Resolution

```
secid:advisory/oracle.com/cpu#jan2024
  -> https://www.oracle.com/security-alerts/cpujan2024.html

secid:advisory/oracle.com/cpu#oct2023
  -> https://www.oracle.com/security-alerts/cpuoct2023.html
```

### Schedule

Oracle releases CPUs quarterly:
- January
- April
- July
- October

### Notes

- CPUs bundle many CVE fixes across Oracle products
- Each CPU contains fixes for multiple product families
- For individual CVE alerts, see `secid:advisory/oracle.com/alert`

---

## alert

Oracle's out-of-band security alerts for critical vulnerabilities.

### Format

```
secid:advisory/oracle.com/alert#CVE-YYYY-NNNN
```

### Resolution

```
secid:advisory/oracle.com/alert#CVE-2021-44228
  -> https://www.oracle.com/security-alerts/alert-cve-2021-44228.html
```

### Notes

- Security Alerts are issued outside the regular CPU schedule
- Used for critical vulnerabilities requiring immediate attention
- For quarterly updates, see `secid:advisory/oracle.com/cpu`

---

## linux

Oracle Linux Security Advisories (ELSA) cover the Oracle Linux distribution.

### Format

```
secid:advisory/oracle.com/linux#ELSA-YYYY-NNNN
```

### Resolution

```
secid:advisory/oracle.com/linux#ELSA-2024-1234
  -> https://linux.oracle.com/errata/ELSA-2024-1234.html
```

### Coverage

| Version | Status |
|---------|--------|
| Oracle Linux 9 | Current |
| Oracle Linux 8 | Current |
| Oracle Linux 7 | Extended support |

### Relationship to RHEL

Oracle Linux is binary-compatible with Red Hat Enterprise Linux:
- Security fixes often mirror RHEL advisories
- May include Oracle-specific additions
- Ksplice provides rebootless kernel patching

### Notes

- Published same day as CPUs for relevant issues
- Monthly bulletins aggregate CVEs
- RSS feeds available at linux.oracle.com

---

## vm

Oracle VM Server security advisories (OVMSA).

### Format

```
secid:advisory/oracle.com/vm#OVMSA-YYYY-NNNN
```

### Coverage

- Oracle VM Server for x86
- Virtualization-specific vulnerabilities
- Hypervisor security issues

### Notes

- Published with quarterly CPUs
- Covers previous month's fixes
- Important for virtualized Oracle workloads
