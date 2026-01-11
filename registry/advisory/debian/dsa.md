---
type: advisory
namespace: debian
name: dsa
full_name: "Debian Security"
operator: "secid:entity/debian"

urls:
  website: "https://www.debian.org/security/"
  tracker: "https://security-tracker.debian.org/tracker"
  lookup_dsa: "https://www.debian.org/security/{year}/dsa-{num}"
  lookup_dla: "https://www.debian.org/lts/security/{year}/dla-{num}"

databases:
  - name: dsa
    id_pattern: "DSA-\\d+-\\d+"
    description: "Debian Security Advisory"
    url: "https://www.debian.org/security/{year}/dsa-{num}"
  - name: dla
    id_pattern: "DLA-\\d+-\\d+"
    description: "Debian LTS Advisory"
    url: "https://www.debian.org/lts/security/{year}/dla-{num}"
  - name: tracker
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    description: "Debian Security Tracker"
    url: "https://security-tracker.debian.org/tracker/{id}"

examples:
  - "secid:advisory/debian/dsa#DSA-5678-1"
  - "secid:advisory/debian/dla#DLA-1234-1"
  - "secid:advisory/debian/tracker#CVE-2024-1234"

status: active
---

# Debian Security

Debian's security advisory system.

## Format

```
secid:advisory/debian/dsa#DSA-NNNN-N        # Debian Security Advisory (stable)
secid:advisory/debian/dla#DLA-NNNN-N        # Debian LTS Advisory
secid:advisory/debian/tracker#CVE-YYYY-NNNN # Security Tracker entries
```

## Notes

- Suffix indicates revision (-1, -2, etc.)
- DSA for stable releases
- DLA for Long Term Support releases
