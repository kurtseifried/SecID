---
type: advisory
namespace: kernel.org
full_name: "Linux Kernel"
operator: "secid:entity/kernel.org"
website: "https://www.kernel.org"
status: active

sources:
  kernel:
    full_name: "Linux Kernel CVE"
    urls:
      website: "https://www.kernel.org/"
      cve_list: "https://www.cve.org/CVERecord?id={id}"
      lore: "https://lore.kernel.org/all/"
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    examples:
      - "secid:advisory/kernel.org/kernel#CVE-2024-1234"
      - "secid:advisory/kernel.org/kernel#CVE-2022-0847"
---

# Linux Advisory Sources

The Linux kernel is the core of Linux operating systems, running on everything from smartphones (Android) to supercomputers to cloud infrastructure. Kernel vulnerabilities affect all Linux systems.

## Why Linux Matters for Security

Linux runs critical infrastructure:

- **Servers** - Majority of internet servers run Linux
- **Cloud** - AWS, Azure, GCP all run Linux VMs
- **Containers** - Docker, Kubernetes run on Linux
- **Android** - Uses Linux kernel
- **Embedded** - Routers, IoT devices, industrial systems

A kernel vulnerability can enable privilege escalation on any Linux system.

## Notable Vulnerabilities

| CVE | Name | Impact |
|-----|------|--------|
| CVE-2022-0847 | **Dirty Pipe** | Arbitrary file overwrite, privilege escalation |
| CVE-2016-5195 | **Dirty COW** | Copy-on-write race condition, privilege escalation |
| CVE-2021-4034 | **PwnKit** | Polkit vulnerability (not kernel, but Linux) |

## Linux Kernel CNA

As of 2024, the Linux kernel project is its own CVE Numbering Authority (CNA). This led to a significant increase in assigned CVEs as the kernel team now proactively assigns CVEs to security-relevant commits.

## Patching

Linux kernel vulnerabilities are fixed in:
1. **Mainline kernel** - Linus's tree
2. **Stable kernels** - Greg KH maintains stable releases
3. **Distribution kernels** - Distros backport fixes to their kernels

## Notes

- Kernel vulnerabilities affect all distros, but patch timing varies
- Container escapes often exploit kernel vulnerabilities
- Android kernel patches lag mainline by months/years

---

## kernel

Linux kernel security vulnerabilities.

### Format

```
secid:advisory/kernel.org/kernel#CVE-YYYY-NNNN
```

### Resolution

Linux kernel CVEs don't have a single canonical page. Resolution options:

```
secid:advisory/kernel.org/kernel#CVE-2022-0847
  -> https://www.cve.org/CVERecord?id=CVE-2022-0847 (CVE record)
  -> https://nvd.nist.gov/vuln/detail/CVE-2022-0847 (NVD)
```

### Notes

- Linux kernel has its own CNA (CVE Numbering Authority) as of 2024
- Historically underreported; now aggressively assigning CVEs
- Kernel vulnerabilities affect all Linux distributions
- Famous examples: Dirty Pipe (CVE-2022-0847), Dirty COW (CVE-2016-5195)
- Fixes go to stable kernel trees, then distributions backport
