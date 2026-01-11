---
type: advisory
namespace: mozilla
name: bugzilla
full_name: "Mozilla Bugzilla"
operator: "secid:entity/mozilla"

urls:
  website: "https://bugzilla.mozilla.org"
  lookup: "https://bugzilla.mozilla.org/show_bug.cgi?id={id}"

id_pattern: "\\d+"

examples:
  - "secid:advisory/mozilla/bugzilla#1234567"
  - "secid:advisory/mozilla/bugzilla#1876543"

status: active
---

# Mozilla Bugzilla

Mozilla's bug tracking system.

## Format

```
secid:advisory/mozilla/bugzilla#NNNNNNN
```

## Resolution

```
secid:advisory/mozilla/bugzilla#1234567
  → https://bugzilla.mozilla.org/show_bug.cgi?id=1234567
```

## Notes

- Security bugs are often restricted until fixes ship
- Referenced in MFSA advisories
- For official advisories, see `secid:advisory/mozilla/mfsa`
