---
type: advisory
namespace: google
name: android
full_name: "Android Security Bulletin"
operator: "secid:entity/google"

urls:
  website: "https://source.android.com/docs/security/bulletin"
  lookup: "https://source.android.com/docs/security/bulletin/{date}"

id_patterns:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    description: "CVE identifier"
  - pattern: "\\d{4}-\\d{2}-\\d{2}"
    description: "Bulletin date"

examples:
  - "secid:advisory/google/android#2024-01-01"
  - "secid:advisory/google/android#CVE-2024-0031"

status: active
---

# Android Security Bulletin

Google's monthly Android security bulletins.

## Format

```
secid:advisory/google/android#YYYY-MM-DD
secid:advisory/google/android#CVE-YYYY-NNNN
```

Monthly bulletins or specific CVEs.

## Resolution

```
secid:advisory/google/android#2024-01-01
  → https://source.android.com/docs/security/bulletin/2024-01-01
```

## Notes

- Monthly security bulletins (released ~first Monday)
- Security patch levels (YYYY-MM-01 and YYYY-MM-05)
- Covers Android framework, kernel, vendor components
- OEMs ship patches at varying speeds
