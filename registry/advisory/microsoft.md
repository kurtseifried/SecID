---
namespace: microsoft
full_name: "Microsoft Security Response Center"
type: advisory
operator: "secid:entity/microsoft/msrc"

urls:
  website: "https://msrc.microsoft.com"
  api: "https://api.msrc.microsoft.com/cvrf/v2.0"
  lookup_cve: "https://msrc.microsoft.com/update-guide/vulnerability/{id}"
  lookup_advisory: "https://msrc.microsoft.com/update-guide/advisory/{id}"

id_routing:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    system: "MSRC Vulnerability Database"
    url: "https://msrc.microsoft.com/update-guide/vulnerability/{id}"
  - pattern: "ADV\\d{6}"
    system: "MSRC Security Advisory"
    url: "https://msrc.microsoft.com/update-guide/advisory/{id}"
  - pattern: "KB\\d+"
    system: "Knowledge Base"
    url: "https://support.microsoft.com/kb/{id}"

examples:
  - "CVE-2024-1234"
  - "ADV240001"
  - "KB5001234"

status: active
---

# Microsoft Namespace

Microsoft Security Response Center content.

## Format

```
secid:advisory/microsoft/{id}
```

## ID Types

- `CVE-*` → Vulnerability details
- `ADV*` → Security advisories (may not have CVE)
- `KB*` → Knowledge base articles (patches)

## Resolution

Depends on ID pattern - see id_routing above.

## Notes

- Patch Tuesday releases monthly
- ADV advisories for defense-in-depth updates
- KB articles link patches to CVEs
