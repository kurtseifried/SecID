---
type: advisory
namespace: redhat
name: errata
full_name: "Red Hat Errata"
operator: "secid:entity/redhat"

urls:
  website: "https://access.redhat.com/errata/"
  api: "https://access.redhat.com/hydra/rest/securitydata"
  lookup: "https://access.redhat.com/errata/{id}"

id_patterns:
  - pattern: "RHSA-\\d{4}:\\d+"
    description: "Red Hat Security Advisory"
    type: security
  - pattern: "RHBA-\\d{4}:\\d+"
    description: "Red Hat Bug Advisory"
    type: bugfix
  - pattern: "RHEA-\\d{4}:\\d+"
    description: "Red Hat Enhancement Advisory"
    type: enhancement

examples:
  - "secid:advisory/redhat/errata#RHSA-2024:1234"
  - "secid:advisory/redhat/errata#RHBA-2024:5678"
  - "secid:advisory/redhat/errata#RHEA-2024:9012"

status: active
---

# Red Hat Errata

Red Hat's errata system publishes advisories for security fixes, bug fixes, and enhancements to Red Hat products.

## Format

```
secid:advisory/redhat/errata#RHSA-YYYY:NNNN   # Security Advisory
secid:advisory/redhat/errata#RHBA-YYYY:NNNN   # Bug Advisory
secid:advisory/redhat/errata#RHEA-YYYY:NNNN   # Enhancement Advisory
```

## Advisory Types

| Prefix | Type | Description |
|--------|------|-------------|
| `RHSA` | Security Advisory | Fixes for security vulnerabilities (CVEs) |
| `RHBA` | Bug Advisory | Fixes for non-security bugs |
| `RHEA` | Enhancement Advisory | New features or improvements |

## Resolution

All three types resolve to the same URL pattern:

```
secid:advisory/redhat/errata#RHSA-2024:1234
  → https://access.redhat.com/errata/RHSA-2024:1234

secid:advisory/redhat/errata#RHBA-2024:5678
  → https://access.redhat.com/errata/RHBA-2024:5678

secid:advisory/redhat/errata#RHEA-2024:9012
  → https://access.redhat.com/errata/RHEA-2024:9012
```

## Notes

- RHSA advisories often fix multiple CVEs in a single errata
- Errata are tied to specific product versions and architectures
- Each errata includes affected packages and their updated versions
- Security advisories (RHSA) include severity ratings

## Relationship to CVE

Errata are the fixes. CVE pages describe the vulnerabilities:

```
secid:advisory/redhat/errata#RHSA-2024:1234  # The fix
secid:advisory/redhat/cve#CVE-2024-1234      # The vulnerability it fixes
```

A single RHSA may fix multiple CVEs:

```
secid:advisory/redhat/errata#RHSA-2024:1234  # Fixes CVE-2024-1111, CVE-2024-2222, CVE-2024-3333
```

See `secid:advisory/redhat/cve` for CVE page documentation.
