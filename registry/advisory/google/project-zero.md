---
type: advisory
namespace: google
name: project-zero
full_name: "Google Project Zero"
operator: "secid:entity/google"

urls:
  website: "https://googleprojectzero.blogspot.com/"
  issues: "https://bugs.chromium.org/p/project-zero/issues/list"
  lookup: "https://bugs.chromium.org/p/project-zero/issues/detail?id={id}"

id_pattern: "\\d+"

examples:
  - "secid:advisory/google/project-zero#2374"
  - "secid:advisory/google/project-zero#1945"

status: active
---

# Google Project Zero

Google's elite vulnerability research team.

## Format

```
secid:advisory/google/project-zero#NNNN
```

Project Zero issue number.

## Resolution

```
secid:advisory/google/project-zero#2374
  → https://bugs.chromium.org/p/project-zero/issues/detail?id=2374
```

## Notes

- Researches vulnerabilities across all vendors
- 90-day disclosure deadline policy
- Often finds high-impact vulnerabilities
- Issues restricted until fixed or deadline expires
- Blog posts provide detailed technical analysis
