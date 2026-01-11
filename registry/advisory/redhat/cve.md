---
type: advisory
namespace: redhat
name: cve
full_name: "Red Hat CVE Database"
operator: "secid:entity/redhat"

urls:
  website: "https://access.redhat.com/security/"
  api: "https://access.redhat.com/hydra/rest/securitydata"
  lookup: "https://access.redhat.com/security/cve/{id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"

examples:
  - "secid:advisory/redhat/cve#CVE-2024-1234"
  - "secid:advisory/redhat/cve#CVE-2023-44487"

status: active
---

# Red Hat CVE Database

Red Hat's CVE pages provide Red Hat-specific analysis of CVEs, including their own CVSS scores, affected products, and mitigation guidance.

## Format

```
secid:advisory/redhat/cve#CVE-YYYY-NNNN
```

## Resolution

```
secid:advisory/redhat/cve#CVE-2024-1234
  → https://access.redhat.com/security/cve/CVE-2024-1234
```

## Notes

- Red Hat CVE pages have their own CVSS scores (may differ from NVD)
- Includes RHEL-specific mitigation and remediation guidance
- Shows which Red Hat products are affected
- Links to related errata (RHSA) that fix the CVE

## Relationship to Errata

CVE pages describe the vulnerability. Errata (RHSA/RHBA/RHEA) are the actual fixes:

```
secid:advisory/redhat/cve#CVE-2024-1234      # The vulnerability description
secid:advisory/redhat/errata#RHSA-2024:1234  # The fix for that vulnerability
```

See `secid:advisory/redhat/errata` for errata documentation.
