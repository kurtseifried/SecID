---
type: advisory
namespace: debian
name: dsa
full_name: "Debian Security Advisory"
operator: "secid:entity/debian"

urls:
  website: "https://www.debian.org/security/"
  lookup: "https://www.debian.org/security/{year}/dsa-{num}"

id_pattern: "DSA-\\d+-\\d+"

examples:
  - "secid:advisory/debian/dsa#DSA-5678-1"
  - "secid:advisory/debian/dsa#DSA-5432-2"

status: active
---

# Debian Security Advisory (DSA)

Debian Security Advisories for stable Debian releases.

## Format

```
secid:advisory/debian/dsa#DSA-NNNN-N
```

The suffix (-1, -2, etc.) indicates the revision of the advisory.

## Resolution

```
secid:advisory/debian/dsa#DSA-5678-1
  → https://www.debian.org/security/2024/dsa-5678
```

## Notes

- DSA advisories are for stable Debian releases
- For LTS releases, see `secid:advisory/debian/dla`
- For CVE tracking, see `secid:advisory/debian/tracker`
