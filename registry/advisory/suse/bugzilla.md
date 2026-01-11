---
type: advisory
namespace: suse
name: bugzilla
full_name: "SUSE Bugzilla"
operator: "secid:entity/suse"

urls:
  website: "https://bugzilla.suse.com"
  lookup: "https://bugzilla.suse.com/show_bug.cgi?id={id}"

id_patterns:
  - pattern: "\\d+"
    description: "Bug ID"
  - pattern: "CVE-\\d{4}-\\d{4,}"
    description: "CVE alias"

examples:
  - "secid:advisory/suse/bugzilla#1234567"
  - "secid:advisory/suse/bugzilla#CVE-2024-1234"

status: active
---

# SUSE Bugzilla

SUSE's bug tracking system.

## Format

```
secid:advisory/suse/bugzilla#NNNNNNN
secid:advisory/suse/bugzilla#CVE-YYYY-NNNN
```

Accepts numeric bug IDs or CVE aliases.

## Resolution

```
secid:advisory/suse/bugzilla#1234567
  → https://bugzilla.suse.com/show_bug.cgi?id=1234567

secid:advisory/suse/bugzilla#CVE-2024-1234
  → https://bugzilla.suse.com/show_bug.cgi?id=CVE-2024-1234
```

## Notes

- SUSE Bugzilla supports CVE aliases (redirects to tracking bug)
- Security bugs may be restricted until fixed
- For official updates, see `secid:advisory/suse/suse-su`
