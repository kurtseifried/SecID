---
type: advisory
namespace: debian
name: tracker
full_name: "Debian Security Tracker"
operator: "secid:entity/debian"

urls:
  website: "https://security-tracker.debian.org/tracker"
  lookup: "https://security-tracker.debian.org/tracker/{id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"

examples:
  - "secid:advisory/debian/tracker#CVE-2024-1234"
  - "secid:advisory/debian/tracker#CVE-2023-44487"

status: active
---

# Debian Security Tracker

Debian's CVE tracking system showing how CVEs affect Debian packages.

## Format

```
secid:advisory/debian/tracker#CVE-YYYY-NNNN
```

## Resolution

```
secid:advisory/debian/tracker#CVE-2024-1234
  → https://security-tracker.debian.org/tracker/CVE-2024-1234
```

## Notes

- Shows CVE status across all Debian releases
- Links to related DSA/DLA advisories
- Includes affected package versions and fix status
- For official advisories, see `secid:advisory/debian/dsa` and `secid:advisory/debian/dla`
