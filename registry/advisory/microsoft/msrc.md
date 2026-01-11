---
type: advisory
namespace: microsoft
name: msrc
full_name: "Microsoft Security Response Center"
operator: "secid:entity/microsoft"

urls:
  website: "https://msrc.microsoft.com"
  api: "https://api.msrc.microsoft.com/cvrf/v2.0"
  lookup: "https://msrc.microsoft.com/update-guide/vulnerability/{id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"

examples:
  - "secid:advisory/microsoft/msrc#CVE-2024-1234"
  - "secid:advisory/microsoft/msrc#CVE-2023-44487"

status: active
---

# Microsoft MSRC

Microsoft Security Response Center vulnerability database.

## Format

```
secid:advisory/microsoft/msrc#CVE-YYYY-NNNN
```

## Resolution

```
secid:advisory/microsoft/msrc#CVE-2024-1234
  → https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1234
```

## Notes

- MSRC provides Microsoft's view of CVEs affecting their products
- Patch Tuesday releases monthly security updates
- For security advisories (ADV), see `secid:advisory/microsoft/advisory`
- For KB articles, see `secid:advisory/microsoft/kb`
