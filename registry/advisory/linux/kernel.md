---
type: advisory
namespace: linux
name: kernel
full_name: "Linux Kernel CVE"
operator: "secid:entity/linux"

urls:
  website: "https://www.kernel.org/"
  cve_list: "https://www.cve.org/CVERecord?id={id}"
  lore: "https://lore.kernel.org/all/"

id_pattern: "CVE-\\d{4}-\\d{4,}"

examples:
  - "secid:advisory/linux/kernel#CVE-2024-1234"
  - "secid:advisory/linux/kernel#CVE-2022-0847"

status: active
---

# Linux Kernel CVE

Linux kernel security vulnerabilities.

## Format

```
secid:advisory/linux/kernel#CVE-YYYY-NNNN
```

## Resolution

Linux kernel CVEs don't have a single canonical page. Resolution options:

```
secid:advisory/linux/kernel#CVE-2022-0847
  → https://www.cve.org/CVERecord?id=CVE-2022-0847 (CVE record)
  → https://nvd.nist.gov/vuln/detail/CVE-2022-0847 (NVD)
```

## Notes

- Linux kernel has its own CNA (CVE Numbering Authority) as of 2024
- Historically underreported; now aggressively assigning CVEs
- Kernel vulnerabilities affect all Linux distributions
- Famous examples: Dirty Pipe (CVE-2022-0847), Dirty COW (CVE-2016-5195)
- Fixes go to stable kernel trees, then distributions backport
