---
type: advisory
namespace: microsoft
name: advisory
full_name: "Microsoft Security Advisory"
operator: "secid:entity/microsoft"

urls:
  website: "https://msrc.microsoft.com"
  lookup: "https://msrc.microsoft.com/update-guide/advisory/{id}"

id_pattern: "ADV\\d{6}"

examples:
  - "secid:advisory/microsoft/advisory#ADV240001"
  - "secid:advisory/microsoft/advisory#ADV230001"

status: active
---

# Microsoft Security Advisory

Microsoft security advisories for defense-in-depth updates and security guidance.

## Format

```
secid:advisory/microsoft/advisory#ADVYYNNNN
```

Where YY is the year and NNNN is the sequential number.

## Resolution

```
secid:advisory/microsoft/advisory#ADV240001
  → https://msrc.microsoft.com/update-guide/advisory/ADV240001
```

## Notes

- ADV advisories cover defense-in-depth updates
- May not have associated CVE identifiers
- For CVE-specific information, see `secid:advisory/microsoft/msrc`
- For KB articles, see `secid:advisory/microsoft/kb`
