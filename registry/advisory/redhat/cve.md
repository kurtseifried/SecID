---
type: advisory
namespace: redhat
name: cve
full_name: "Red Hat Security"
operator: "secid:entity/redhat"

urls:
  website: "https://access.redhat.com/security/"
  api: "https://access.redhat.com/hydra/rest/securitydata"
  lookup_cve: "https://access.redhat.com/security/cve/{id}"
  lookup_errata: "https://access.redhat.com/errata/{id}"

databases:
  - name: cve
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    description: "Red Hat CVE Database"
    url: "https://access.redhat.com/security/cve/{id}"
  - name: errata
    id_pattern: "RHSA-\\d{4}:\\d+"
    description: "Red Hat Security Advisory"
    url: "https://access.redhat.com/errata/{id}"
  - name: errata
    id_pattern: "RHBA-\\d{4}:\\d+"
    description: "Red Hat Bug Advisory"
    url: "https://access.redhat.com/errata/{id}"
  - name: errata
    id_pattern: "RHEA-\\d{4}:\\d+"
    description: "Red Hat Enhancement Advisory"
    url: "https://access.redhat.com/errata/{id}"

examples:
  - "secid:advisory/redhat/cve#CVE-2024-1234"
  - "secid:advisory/redhat/errata#RHSA-2024:1234"
  - "secid:advisory/redhat/errata#RHBA-2024:5678"

status: active
---

# Red Hat Security

Red Hat's security response content.

## Format

```
secid:advisory/redhat/cve#CVE-YYYY-NNNN       # Red Hat CVE pages
secid:advisory/redhat/errata#RHSA-YYYY:NNNN   # Security Advisories
secid:advisory/redhat/errata#RHBA-YYYY:NNNN   # Bug Advisories
secid:advisory/redhat/errata#RHEA-YYYY:NNNN   # Enhancement Advisories
```

## Resolution

Depends on ID pattern - see id_routing above.

## Notes

- Red Hat CVE pages have their own CVSS scores (may differ from NVD)
- RHSA often covers multiple CVEs
- Includes RHEL-specific mitigation guidance
