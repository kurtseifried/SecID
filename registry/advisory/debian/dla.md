---
type: advisory
namespace: debian
name: dla
full_name: "Debian LTS Advisory"
operator: "secid:entity/debian"

urls:
  website: "https://www.debian.org/lts/security/"
  lookup: "https://www.debian.org/lts/security/{year}/dla-{num}"

id_pattern: "DLA-\\d+-\\d+"

examples:
  - "secid:advisory/debian/dla#DLA-1234-1"
  - "secid:advisory/debian/dla#DLA-3456-2"

status: active
---

# Debian LTS Advisory (DLA)

Debian LTS (Long Term Support) Advisories for extended support releases.

## Format

```
secid:advisory/debian/dla#DLA-NNNN-N
```

The suffix (-1, -2, etc.) indicates the revision of the advisory.

## Resolution

```
secid:advisory/debian/dla#DLA-1234-1
  → https://www.debian.org/lts/security/2024/dla-1234
```

## Notes

- DLA advisories are for Debian LTS releases (extended support)
- For stable releases, see `secid:advisory/debian/dsa`
- For CVE tracking, see `secid:advisory/debian/tracker`
