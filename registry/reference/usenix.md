---
namespace: usenix
full_name: "USENIX Association"
type: reference

urls:
  website: "https://www.usenix.org"
  lookup: "https://www.usenix.org/conference/{venue}/presentation/{id}"
  legacy: "https://www.usenix.org/legacy/publications/library/proceedings/{venue}/{id}"

id_pattern: "[a-z0-9-]+"
examples:
  - "usenixsecurity23/presentation/smith"
  - "osdi23/presentation/jones"

status: draft
---

# USENIX Namespace

USENIX Association - publisher of top systems and security conferences.

## Format

```
secid:reference/usenix/{venue}/presentation/{name}
secid:reference/usenix/usenixsecurity23/presentation/smith
```

## Resolution

```
https://www.usenix.org/conference/{venue}/presentation/{id}
```

## Security Venues

| Venue | Conference |
|-------|------------|
| usenixsecurity{YY} | USENIX Security Symposium |
| osdi{YY} | Operating Systems Design and Implementation |
| nsdi{YY} | Networked Systems Design and Implementation |
| atc{YY} | Annual Technical Conference |
| woot{YY} | Workshop on Offensive Technologies |

## Notes

- USENIX Security is a top-tier security venue
- Papers are open access (free PDFs)
- Videos of presentations often available
- URL structure varies by venue and year
- Excellent source for systems security research
