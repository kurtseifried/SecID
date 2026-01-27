---
type: advisory
namespace: oracle
full_name: "Oracle Corporation"
operator: "secid:entity/oracle"
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
      - "secid:advisory/oracle/cpu#jan2024"
      - "secid:advisory/oracle/cpu#oct2023"
      - "secid:advisory/oracle/cpu#apr2024"
  alert:
    full_name: "Oracle Security Alert"
    urls:
      website: "https://www.oracle.com/security-alerts/"
      lookup: "https://www.oracle.com/security-alerts/alert-{id}.html"
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    examples:
      - "secid:advisory/oracle/alert#CVE-2024-1234"
      - "secid:advisory/oracle/alert#CVE-2021-44228"
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
secid:advisory/oracle/cpu#MMMYYYY
```

Month (jan, apr, jul, oct) and year. CPUs are released quarterly.

### Resolution

```
secid:advisory/oracle/cpu#jan2024
  -> https://www.oracle.com/security-alerts/cpujan2024.html

secid:advisory/oracle/cpu#oct2023
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
- For individual CVE alerts, see `secid:advisory/oracle/alert`

---

## alert

Oracle's out-of-band security alerts for critical vulnerabilities.

### Format

```
secid:advisory/oracle/alert#CVE-YYYY-NNNN
```

### Resolution

```
secid:advisory/oracle/alert#CVE-2021-44228
  -> https://www.oracle.com/security-alerts/alert-cve-2021-44228.html
```

### Notes

- Security Alerts are issued outside the regular CPU schedule
- Used for critical vulnerabilities requiring immediate attention
- For quarterly updates, see `secid:advisory/oracle/cpu`
