---
namespace: ubuntu
full_name: "Ubuntu (Canonical)"
website: "https://ubuntu.com"
type: corporation
founded: 2004
headquarters: "London, UK (Canonical Ltd)"
parent: "Canonical Ltd"
---

# Ubuntu (Canonical)

Ubuntu is the most popular Linux distribution for desktops and cloud servers. It's developed by Canonical Ltd and based on Debian. Ubuntu has a dedicated security team and predictable release cycle.

## Why Ubuntu Matters for Security

Ubuntu's reach is extensive:

- **Cloud** - Default/popular choice on AWS, Azure, GCP
- **Desktop** - Most popular Linux desktop distribution
- **Containers** - Common base image for Docker containers
- **IoT** - Ubuntu Core for embedded devices

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `usn` | Ubuntu Security Notice | USN-6543-1 |
| `cve-tracker` | CVE Tracker | CVE-2024-1234 |
| `launchpad` | Bug Tracking (Launchpad) | 1234567 |

## Ubuntu Security Notice (USN)

USN format: `USN-NNNN-R` where R indicates revisions/updates.

Each USN may address multiple CVEs and specifies which Ubuntu releases are affected.

## Release Cycle

Ubuntu releases every 6 months (April, October):
- **LTS (Long Term Support)** - Every 2 years (e.g., 22.04, 24.04), 5+ years support
- **Interim releases** - 9 months support

Security support duration varies significantly by release type.

## Pro/Advantage

Ubuntu Pro (formerly Ubuntu Advantage) extends security support:
- Extended security maintenance (ESM)
- Kernel livepatch
- FIPS-certified packages

## Notes

- Ubuntu is downstream of Debian; many packages are shared
- Canonical is a CVE Numbering Authority (CNA)
- Ubuntu's CVE Tracker shows fix status across releases
