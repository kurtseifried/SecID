---
type: advisory
namespace: github
full_name: "GitHub (Microsoft)"
operator: "secid:entity/github"
website: "https://github.com"
status: active

sources:
  ghsa:
    full_name: "GitHub Security Advisories"
    urls:
      website: "https://github.com/advisories"
      api: "https://api.github.com/advisories"
      bulk_data: "https://github.com/github/advisory-database"
      lookup: "https://github.com/advisories/{id}"
    id_pattern: "GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
    examples:
      - "secid:advisory/github/ghsa#GHSA-jfh8-c2jp-5v3q"
      - "secid:advisory/github/ghsa#GHSA-p6xc-xr62-6r2g"
---

# GitHub Advisory Sources

GitHub is the world's largest source code hosting platform, acquired by Microsoft in 2018. GitHub operates the GitHub Advisory Database and Dependabot vulnerability scanning.

## Why GitHub Matters for Security

GitHub is central to software supply chain security:

- **GitHub Advisory Database** - Aggregated vulnerability database for packages
- **Dependabot** - Automated vulnerability scanning and PR creation
- **Secret scanning** - Detects exposed credentials in repositories
- **Code scanning** - Static analysis via CodeQL

## GHSA (GitHub Security Advisory)

GHSA IDs use a distinctive format:
```
GHSA-xxxx-yyyy-zzzz  (four groups of four characters)
GHSA-jfh8-c2jp-5v3q
```

GitHub Advisory Database aggregates from:
- CVE/NVD
- npm
- PyPI
- RubyGems
- Go
- And other ecosystem databases

## npm Advisories

GitHub acquired npm in 2020. npm security advisories are now part of the GitHub Advisory Database. Use GHSA for npm vulnerabilities.

---

## ghsa

GitHub's security advisory database, focused on package ecosystems.

### Format

```
secid:advisory/github/ghsa#GHSA-xxxx-yyyy-zzzz
```

### Resolution

```
https://github.com/advisories/{id}
```

### Features

- Package-focused (npm, pip, maven, etc.)
- Integrates with Dependabot
- Community contributions
- Usually includes CVE aliases

### Relationships

```
secid:advisory/github/ghsa#GHSA-xxxx-yyyy-zzzz -> aliases -> secid:advisory/mitre/cve#CVE-YYYY-NNNN
```

### Notes

- GitHub is a CVE Numbering Authority (CNA)
- Advisory Database is open source: github.com/github/advisory-database
- Dependabot alerts are based on GHSA data
- Repository security advisories let maintainers privately fix issues
