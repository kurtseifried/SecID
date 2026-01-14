---
namespace: github
full_name: "GitHub (Microsoft)"
website: "https://github.com"
type: corporation
founded: 2008
headquarters: "San Francisco, California, USA"
parent: "Microsoft (acquired 2018)"
---

# GitHub (Microsoft)

GitHub is the world's largest source code hosting platform, acquired by Microsoft in 2018. GitHub operates the GitHub Advisory Database and Dependabot vulnerability scanning.

## Why GitHub Matters for Security

GitHub is central to software supply chain security:

- **GitHub Advisory Database** - Aggregated vulnerability database for packages
- **Dependabot** - Automated vulnerability scanning and PR creation
- **Secret scanning** - Detects exposed credentials in repositories
- **Code scanning** - Static analysis via CodeQL

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `ghsa` | GitHub Security Advisories | GHSA-jfh8-c2jp-5v3q |

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

## Notes

- GitHub is a CVE Numbering Authority (CNA)
- Advisory Database is open source: github.com/github/advisory-database
- Dependabot alerts are based on GHSA data
- Repository security advisories let maintainers privately fix issues
