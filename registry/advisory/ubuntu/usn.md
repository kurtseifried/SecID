---
type: advisory
namespace: ubuntu
name: usn
full_name: "Ubuntu Security Notice"
operator: "secid:entity/ubuntu"

urls:
  website: "https://ubuntu.com/security/notices"
  lookup: "https://ubuntu.com/security/notices/USN-{id}"

id_pattern: "USN-\\d+-\\d+"

examples:
  - "secid:advisory/ubuntu/usn#USN-6543-1"
  - "secid:advisory/ubuntu/usn#USN-6789-2"

status: active
---

# Ubuntu Security Notice (USN)

Canonical's security advisories for Ubuntu.

## Format

```
secid:advisory/ubuntu/usn#USN-NNNN-N
```

The suffix (-1, -2, etc.) indicates revisions or updates to the notice.

## Resolution

```
secid:advisory/ubuntu/usn#USN-6543-1
  → https://ubuntu.com/security/notices/USN-6543-1
```

## Notes

- USN advisories cover multiple Ubuntu releases
- Often reference multiple CVEs in a single notice
- For bug tracking, see `secid:advisory/ubuntu/launchpad`
- For CVE status, see `secid:advisory/ubuntu/cve-tracker`
