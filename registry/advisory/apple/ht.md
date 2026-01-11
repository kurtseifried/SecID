---
type: advisory
namespace: apple
name: ht
full_name: "Apple Security Update (HT)"
operator: "secid:entity/apple"

urls:
  website: "https://support.apple.com/en-us/HT201222"
  lookup: "https://support.apple.com/{id}"

id_pattern: "HT\\d{6}"

examples:
  - "secid:advisory/apple/ht#HT214036"
  - "secid:advisory/apple/ht#HT213931"

status: active
---

# Apple Security Update (HT)

Apple's security update documentation.

## Format

```
secid:advisory/apple/ht#HTNNNNNN
```

## Resolution

```
secid:advisory/apple/ht#HT214036
  → https://support.apple.com/HT214036
```

## Notes

- HT articles document security content of updates
- Covers iOS, iPadOS, macOS, watchOS, tvOS, Safari, etc.
- Apple bundles many CVEs per release
- See also Apple Security Research for bounty program
