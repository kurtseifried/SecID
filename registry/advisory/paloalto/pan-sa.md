---
type: advisory
namespace: paloalto
name: pan-sa
full_name: "Palo Alto Networks Security Advisory"
operator: "secid:entity/paloalto"

urls:
  website: "https://security.paloaltonetworks.com/"
  lookup: "https://security.paloaltonetworks.com/CVE-{id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"

examples:
  - "secid:advisory/paloalto/pan-sa#CVE-2024-3400"
  - "secid:advisory/paloalto/pan-sa#CVE-2024-0012"

status: active
---

# Palo Alto Networks Security Advisory

Palo Alto Networks security advisories.

## Format

```
secid:advisory/paloalto/pan-sa#CVE-YYYY-NNNN
```

Palo Alto indexes advisories by CVE ID.

## Resolution

```
secid:advisory/paloalto/pan-sa#CVE-2024-3400
  → https://security.paloaltonetworks.com/CVE-2024-3400
```

## Notes

- Covers PAN-OS, GlobalProtect, Cortex, Prisma, etc.
- High-profile vulnerabilities (firewalls are critical infrastructure)
- Also publishes PAN-SA-* identifiers in some contexts
