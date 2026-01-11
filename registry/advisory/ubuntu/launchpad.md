---
type: advisory
namespace: ubuntu
name: launchpad
full_name: "Launchpad Bugs"
operator: "secid:entity/ubuntu"

urls:
  website: "https://bugs.launchpad.net"
  lookup: "https://bugs.launchpad.net/bugs/{id}"

id_pattern: "\\d+"

examples:
  - "secid:advisory/ubuntu/launchpad#1234567"
  - "secid:advisory/ubuntu/launchpad#2045678"

status: active
---

# Launchpad Bugs

Ubuntu/Canonical's bug tracking system.

## Format

```
secid:advisory/ubuntu/launchpad#NNNNNNN
```

## Resolution

```
secid:advisory/ubuntu/launchpad#1234567
  → https://bugs.launchpad.net/bugs/1234567
```

## Notes

- Launchpad is used for Ubuntu and many other open source projects
- Security bugs may be marked private until fixed
- For official security notices, see `secid:advisory/ubuntu/usn`
