---
type: advisory
namespace: cisco
name: bug
full_name: "Cisco Bug Search"
operator: "secid:entity/cisco"

urls:
  website: "https://bst.cloudapps.cisco.com/bugsearch"
  lookup: "https://bst.cloudapps.cisco.com/bugsearch/bug/{id}"

id_pattern: "CSC[a-z]{2}\\d{5}"

examples:
  - "secid:advisory/cisco/bug#CSCvv12345"
  - "secid:advisory/cisco/bug#CSCwa98765"

status: active
---

# Cisco Bug Search

Cisco's bug tracking system. Security bugs are tracked with CSC identifiers.

## Format

```
secid:advisory/cisco/bug#CSCxx12345
```

CSC IDs are formatted as "CSC" + two lowercase letters + five digits.

## Resolution

```
secid:advisory/cisco/bug#CSCvv12345
  → https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv12345
```

## Notes

- CSC numbers are referenced in PSIRT advisories
- Some bugs require Cisco.com login to view
- For official security advisories, see `secid:advisory/cisco/psirt`
