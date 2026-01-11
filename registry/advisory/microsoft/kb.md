---
type: advisory
namespace: microsoft
name: kb
full_name: "Microsoft Knowledge Base"
operator: "secid:entity/microsoft"

urls:
  website: "https://support.microsoft.com"
  lookup: "https://support.microsoft.com/kb/{id}"

id_pattern: "KB\\d+"

examples:
  - "secid:advisory/microsoft/kb#KB5001234"
  - "secid:advisory/microsoft/kb#KB5034441"

status: active
---

# Microsoft Knowledge Base

Microsoft Knowledge Base articles documenting security updates and patches.

## Format

```
secid:advisory/microsoft/kb#KBNNNNNNN
```

## Resolution

```
secid:advisory/microsoft/kb#KB5001234
  → https://support.microsoft.com/kb/5001234
```

## Notes

- KB articles document specific patches and updates
- Links patches to the CVEs they fix
- Includes installation instructions and known issues
- For CVE details, see `secid:advisory/microsoft/msrc`
- For security advisories, see `secid:advisory/microsoft/advisory`
