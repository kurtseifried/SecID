---
namespace: oracle
full_name: "Oracle Corporation"
website: "https://www.oracle.com"
type: corporation
founded: 1977
headquarters: "Austin, Texas, USA"
---

# Oracle Corporation

Oracle is a major enterprise software company known for databases, middleware, enterprise applications, and cloud services. Oracle releases security patches quarterly through Critical Patch Updates (CPUs).

## Why Oracle Matters for Security

Oracle software is deeply embedded in enterprise infrastructure:

- **Oracle Database** - Widely used enterprise database
- **Java** - Oracle owns and maintains Java SE
- **WebLogic** - Enterprise application server (frequent target)
- **MySQL** - Popular open-source database (Oracle-owned)
- **Oracle Cloud** - Enterprise cloud platform

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `cpu` | Critical Patch Update (quarterly) | jan2024, apr2024 |
| `alert` | Out-of-band Security Alerts | CVE-2021-44228 |

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
