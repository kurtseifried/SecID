---
namespace: suse
full_name: "SUSE"
website: "https://www.suse.com"
type: corporation
founded: 1992
headquarters: "Nuremberg, Germany"
---

# SUSE

SUSE is a German enterprise Linux company producing SUSE Linux Enterprise (SLE) and sponsoring openSUSE. SUSE is popular in Europe and in SAP environments.

## Why SUSE Matters for Security

SUSE serves enterprise Linux needs:

- **SUSE Linux Enterprise Server (SLES)** - Enterprise Linux distribution
- **SUSE Linux Enterprise Desktop (SLED)** - Enterprise desktop
- **openSUSE** - Community distribution (Leap and Tumbleweed)
- **Rancher** - Kubernetes management (SUSE acquired Rancher Labs)

SUSE is particularly common in SAP deployments and European enterprises.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `suse-su` | SUSE Security Updates | SUSE-SU-2024:0001-1 |
| `bugzilla` | SUSE Bugzilla | 1234567 |

## Advisory ID Format

SUSE Security Updates use `SUSE-SU-YYYY:NNNN-R` format:
```
SUSE-SU-2024:0001-1  (year 2024, update 0001, revision 1)
```

## openSUSE vs SUSE Linux Enterprise

- **openSUSE Leap** - Binary-compatible with SLES, community-supported
- **openSUSE Tumbleweed** - Rolling release, latest packages
- **SLES/SLED** - Commercial support, longer lifecycle

Security updates are similar but support timelines differ.

## Notes

- SUSE is a CVE Numbering Authority (CNA)
- SUSE Bugzilla supports CVE aliases for lookup
- SUSE acquired Rancher Labs (Kubernetes) in 2020
