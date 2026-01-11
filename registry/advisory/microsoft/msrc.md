---
type: advisory
namespace: microsoft
name: msrc
full_name: "Microsoft Security Response Center"
operator: "secid:entity/microsoft/msrc"

urls:
  website: "https://msrc.microsoft.com"
  api: "https://api.msrc.microsoft.com/cvrf/v2.0"
  lookup_cve: "https://msrc.microsoft.com/update-guide/vulnerability/{id}"
  lookup_advisory: "https://msrc.microsoft.com/update-guide/advisory/{id}"

databases:
  - name: msrc
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    description: "MSRC Vulnerability Database"
    url: "https://msrc.microsoft.com/update-guide/vulnerability/{id}"
  - name: advisory
    id_pattern: "ADV\\d{6}"
    description: "MSRC Security Advisory"
    url: "https://msrc.microsoft.com/update-guide/advisory/{id}"
  - name: kb
    id_pattern: "KB\\d+"
    description: "Knowledge Base"
    url: "https://support.microsoft.com/kb/{id}"

examples:
  - "secid:advisory/microsoft/msrc#CVE-2024-1234"
  - "secid:advisory/microsoft/advisory#ADV240001"
  - "secid:advisory/microsoft/kb#KB5001234"

status: active
---

# Microsoft MSRC

Microsoft Security Response Center content.

## Format

```
secid:advisory/microsoft/msrc#CVE-YYYY-NNNN    # Vulnerability details
secid:advisory/microsoft/advisory#ADV240001   # Security advisories
secid:advisory/microsoft/kb#KB5001234         # Knowledge base articles
```

## Resolution

Depends on ID pattern - see id_routing above.

## Notes

- Patch Tuesday releases monthly
- ADV advisories for defense-in-depth updates
- KB articles link patches to CVEs
