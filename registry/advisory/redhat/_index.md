---
namespace: redhat
full_name: "Red Hat (IBM)"
website: "https://www.redhat.com"
type: corporation
founded: 1993
headquarters: "Raleigh, North Carolina, USA"
parent: "IBM (acquired 2019)"
---

# Red Hat (IBM)

Red Hat is the world's largest open-source software company, acquired by IBM in 2019. Red Hat Enterprise Linux (RHEL) is the leading enterprise Linux distribution. Red Hat Product Security handles vulnerability response.

## Why Red Hat Matters for Security

Red Hat is enterprise Linux:

- **RHEL** - Red Hat Enterprise Linux, the enterprise standard
- **OpenShift** - Kubernetes platform
- **Ansible** - Automation platform
- **Fedora** - Upstream community distribution

RHEL and its derivatives (CentOS Stream, Rocky, Alma, Oracle Linux) run most enterprise Linux workloads.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `errata` | Red Hat Errata (RHSA/RHBA/RHEA) | RHSA-2024:1234 |
| `cve` | Red Hat CVE Database | CVE-2024-1234 |
| `bugzilla` | Red Hat Bugzilla | 2045678 |

## Errata Types

| Prefix | Type | Description |
|--------|------|-------------|
| RHSA | Security Advisory | Security vulnerability fixes |
| RHBA | Bug Advisory | Bug fixes (non-security) |
| RHEA | Enhancement Advisory | New features |

## Red Hat CVE Database

Red Hat maintains its own CVE database with:
- Red Hat-specific CVSS scores (may differ from NVD)
- Affected Red Hat products
- Mitigation guidance
- Links to fixing errata

## Notes

- Red Hat is a CVE Numbering Authority (CNA)
- Red Hat security data is available via API
- CentOS Stream is now RHEL's upstream (not downstream)
- Rocky Linux and AlmaLinux are RHEL-compatible alternatives
