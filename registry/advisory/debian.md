---
namespace: debian
full_name: "Debian Security"
type: advisory
operator: "secid:entity/debian"

urls:
  website: "https://www.debian.org/security/"
  tracker: "https://security-tracker.debian.org/tracker"
  lookup_dsa: "https://www.debian.org/security/{year}/dsa-{num}"
  lookup_dla: "https://www.debian.org/lts/security/{year}/dla-{num}"

id_routing:
  - pattern: "DSA-\\d+-\\d+"
    system: "Debian Security Advisory"
    url: "https://www.debian.org/security/{year}/dsa-{num}"
  - pattern: "DLA-\\d+-\\d+"
    system: "Debian LTS Advisory"
    url: "https://www.debian.org/lts/security/{year}/dla-{num}"
  - pattern: "CVE-\\d{4}-\\d{4,}"
    system: "Debian Security Tracker"
    url: "https://security-tracker.debian.org/tracker/{id}"

examples:
  - "DSA-5678-1"
  - "DLA-1234-1"
  - "CVE-2024-1234"

status: active
---

# Debian Namespace

Debian's security advisory system.

## Format

```
secid:advisory/debian/{id}
```

## ID Types

- `DSA-NNNN-N` → Debian Security Advisory (stable)
- `DLA-NNNN-N` → Debian LTS Advisory
- `CVE-*` → Security Tracker entries

## Notes

- Suffix indicates revision (-1, -2, etc.)
- DSA for stable releases
- DLA for Long Term Support releases
