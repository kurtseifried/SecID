---
namespace: redhat
full_name: "Red Hat Security"
type: advisory
operator: "secid:entity/redhat"

urls:
  website: "https://access.redhat.com/security/"
  api: "https://access.redhat.com/hydra/rest/securitydata"
  lookup_cve: "https://access.redhat.com/security/cve/{id}"
  lookup_errata: "https://access.redhat.com/errata/{id}"

id_routing:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    system: "Red Hat CVE Database"
    url: "https://access.redhat.com/security/cve/{id}"
  - pattern: "RHSA-\\d{4}:\\d+"
    system: "Red Hat Security Advisory"
    url: "https://access.redhat.com/errata/{id}"
  - pattern: "RHBA-\\d{4}:\\d+"
    system: "Red Hat Bug Advisory"
    url: "https://access.redhat.com/errata/{id}"
  - pattern: "RHEA-\\d{4}:\\d+"
    system: "Red Hat Enhancement Advisory"
    url: "https://access.redhat.com/errata/{id}"
  - pattern: "\\d{6,}"
    system: "Red Hat Bugzilla"
    url: "https://bugzilla.redhat.com/show_bug.cgi?id={id}"

examples:
  - "CVE-2024-1234"
  - "RHSA-2024:1234"
  - "RHBA-2024:5678"
  - "2045678"

status: active
---

# Red Hat Namespace

Red Hat's security response content.

## Format

```
secid:advisory/redhat/{id}
```

ID pattern determines routing:
- `CVE-*` → Red Hat CVE pages
- `RHSA-*` → Security Advisories
- `RHBA-*` → Bug Advisories
- `RHEA-*` → Enhancement Advisories
- `NNNNNN` → Bugzilla

## Resolution

Depends on ID pattern - see id_routing above.

## Notes

- Red Hat CVE pages have their own CVSS scores (may differ from NVD)
- RHSA often covers multiple CVEs
- Includes RHEL-specific mitigation guidance
