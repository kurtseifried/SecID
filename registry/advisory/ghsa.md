---
namespace: ghsa
full_name: "GitHub Security Advisories"
type: advisory
operator: "secid:entity/github/ghsa"

urls:
  website: "https://github.com/advisories"
  api: "https://api.github.com/advisories"
  bulk_data: "https://github.com/github/advisory-database"
  lookup: "https://github.com/advisories/{id}"

id_pattern: "GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
examples:
  - "GHSA-jfh8-c2jp-5v3q"
  - "GHSA-p6xc-xr62-6r2g"

status: active
---

# GHSA Namespace

GitHub's security advisory database, focused on package ecosystems.

## Format

```
secid:advisory/ghsa/GHSA-xxxx-yyyy-zzzz
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
advisory/ghsa/GHSA-xxxx-yyyy → aliases → advisory/cve/CVE-YYYY-NNNN
```
