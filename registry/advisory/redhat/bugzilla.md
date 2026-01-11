---
type: advisory
namespace: redhat
name: bugzilla
full_name: "Red Hat Bugzilla"
operator: "secid:entity/redhat"

urls:
  website: "https://bugzilla.redhat.com"
  lookup: "https://bugzilla.redhat.com/show_bug.cgi?id={id}"

id_patterns:
  - pattern: "\\d+"
    description: "Bugzilla bug ID"
    type: primary
  - pattern: "CVE-\\d{4}-\\d{4,}"
    description: "CVE alias (redirects to associated bug)"
    type: alias

examples:
  - "secid:advisory/redhat/bugzilla#2045678"
  - "secid:advisory/redhat/bugzilla#CVE-2024-1234"

status: active
---

# Red Hat Bugzilla

Red Hat's bug tracking system. Security bugs are tracked here with CVE aliases.

## Format

```
secid:advisory/redhat/bugzilla#NNNNNNN           # Direct bug ID
secid:advisory/redhat/bugzilla#CVE-YYYY-NNNN    # CVE alias (redirects)
```

## Resolution

Both forms resolve to the same URL pattern - Bugzilla handles CVE aliases automatically:

```
secid:advisory/redhat/bugzilla#2045678
  → https://bugzilla.redhat.com/show_bug.cgi?id=2045678

secid:advisory/redhat/bugzilla#CVE-2024-1234
  → https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2024-1234
  → (redirects to the bug tracking that CVE)
```

## Alias Support

Bugzilla supports CVE aliases - you can look up a bug by its CVE identifier, and Bugzilla will redirect to the actual bug. This means both forms are valid SecIDs:

- `#2045678` - The canonical Bugzilla bug ID
- `#CVE-2024-1234` - An alias that resolves to the same bug

When possible, prefer the numeric bug ID for stability (aliases can theoretically change, though this is rare).

## Notes

- Security bugs often have restricted access until fixes are released
- CVE aliases are added when a CVE is assigned to a bug
- One bug may track multiple CVEs (or vice versa in rare cases)
- For official advisories, see `secid:advisory/redhat/errata`
- For CVE details, see `secid:advisory/redhat/cve`

## Relationships

```
secid:advisory/redhat/bugzilla#2045678 → tracks → secid:advisory/mitre/cve#CVE-2024-1234
secid:advisory/redhat/errata#RHSA-2024:1234 → fixes → secid:advisory/redhat/bugzilla#2045678
```
