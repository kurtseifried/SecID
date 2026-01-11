---
type: advisory
namespace: debian
name: bts
full_name: "Debian Bug Tracking System"
operator: "secid:entity/debian"

urls:
  website: "https://bugs.debian.org"
  lookup: "https://bugs.debian.org/{id}"

id_pattern: "\\d+"

examples:
  - "secid:advisory/debian/bts#1012345"
  - "secid:advisory/debian/bts#987654"

status: active
---

# Debian Bug Tracking System (BTS)

Debian's bug tracking system.

## Format

```
secid:advisory/debian/bts#NNNNNNN
```

## Resolution

```
secid:advisory/debian/bts#1012345
  → https://bugs.debian.org/1012345
```

## Notes

- Security bugs are tracked with "security" tag
- Referenced in DSA/DLA advisories
- For official advisories, see `secid:advisory/debian/dsa` and `secid:advisory/debian/dla`
- For CVE status, see `secid:advisory/debian/tracker`
