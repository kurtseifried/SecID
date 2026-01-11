---
type: advisory
namespace: mozilla
name: mfsa
full_name: "Mozilla Foundation Security Advisory"
operator: "secid:entity/mozilla"

urls:
  website: "https://www.mozilla.org/security/advisories/"
  lookup: "https://www.mozilla.org/security/advisories/mfsa{id}/"

id_pattern: "\\d{4}-\\d{2}"

examples:
  - "secid:advisory/mozilla/mfsa#2024-01"
  - "secid:advisory/mozilla/mfsa#2023-56"

status: active
---

# Mozilla Foundation Security Advisory (MFSA)

Mozilla's official security advisories for Firefox, Thunderbird, and other products.

## Format

```
secid:advisory/mozilla/mfsa#YYYY-NN
```

Year and sequential number within that year.

## Resolution

```
secid:advisory/mozilla/mfsa#2024-01
  → https://www.mozilla.org/security/advisories/mfsa2024-01/
```

## Notes

- MFSA advisories cover Firefox, Firefox ESR, Thunderbird, etc.
- Often bundle multiple CVEs per advisory (per release)
- For bug details, see `secid:advisory/mozilla/bugzilla`
