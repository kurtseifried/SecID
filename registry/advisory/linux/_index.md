---
namespace: linux
full_name: "Linux Kernel"
website: "https://www.kernel.org"
type: opensource
founded: 1991
creator: "Linus Torvalds"
---

# Linux Kernel

The Linux kernel is the core of Linux operating systems, running on everything from smartphones (Android) to supercomputers to cloud infrastructure. Kernel vulnerabilities affect all Linux systems.

## Why Linux Matters for Security

Linux runs critical infrastructure:

- **Servers** - Majority of internet servers run Linux
- **Cloud** - AWS, Azure, GCP all run Linux VMs
- **Containers** - Docker, Kubernetes run on Linux
- **Android** - Uses Linux kernel
- **Embedded** - Routers, IoT devices, industrial systems

A kernel vulnerability can enable privilege escalation on any Linux system.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `kernel` | Linux Kernel CVEs | CVE-2022-0847 |

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
