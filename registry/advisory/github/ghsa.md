---
type: advisory
namespace: github
name: ghsa
full_name: "GitHub Security Advisories"
operator: "secid:entity/github/ghsa"

urls:
  website: "https://github.com/advisories"
  api: "https://api.github.com/advisories"
  bulk_data: "https://github.com/github/advisory-database"
  lookup: "https://github.com/advisories/{id}"

id_pattern: "GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
examples:
  - "secid:advisory/github/ghsa#GHSA-jfh8-c2jp-5v3q"
  - "secid:advisory/github/ghsa#GHSA-p6xc-xr62-6r2g"

status: active
---

# GHSA (GitHub)

GitHub's security advisory database, focused on package ecosystems.

## Format

```
secid:advisory/github/ghsa#GHSA-xxxx-yyyy-zzzz
```

## Resolution

```
https://github.com/advisories/{id}
```

## Features

- Package-focused (npm, pip, maven, etc.)
- Integrates with Dependabot
- Community contributions
- Usually includes CVE aliases

## Relationships

```
secid:advisory/github/ghsa#GHSA-xxxx-yyyy-zzzz → aliases → secid:advisory/mitre/cve#CVE-YYYY-NNNN
```
