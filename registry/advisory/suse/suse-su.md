---
type: advisory
namespace: suse
name: suse-su
full_name: "SUSE Security Update"
operator: "secid:entity/suse"

urls:
  website: "https://www.suse.com/security/cve/"
  lookup: "https://www.suse.com/security/cve/{id}/"

id_pattern: "SUSE-SU-\\d{4}:\\d{4}-\\d+"

examples:
  - "secid:advisory/suse/suse-su#SUSE-SU-2024:0001-1"
  - "secid:advisory/suse/suse-su#SUSE-SU-2023:4567-1"

status: active
---

# SUSE Security Update (SUSE-SU)

SUSE Linux security updates.

## Format

```
secid:advisory/suse/suse-su#SUSE-SU-YYYY:NNNN-R
```

Year, sequential number, and revision.

## Resolution

```
secid:advisory/suse/suse-su#SUSE-SU-2024:0001-1
  → https://www.suse.com/support/update/announcement/2024/suse-su-20240001-1/
```

## Notes

- Covers SUSE Linux Enterprise, openSUSE
- For CVE tracking, see `secid:advisory/suse/cve`
- For bug tracking, see `secid:advisory/suse/bugzilla`
