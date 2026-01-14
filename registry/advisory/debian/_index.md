---
namespace: debian
full_name: "Debian Project"
website: "https://www.debian.org"
type: opensource
founded: 1993
---

# Debian Project

Debian is one of the oldest and most influential Linux distributions. It's the upstream for Ubuntu and many other distributions. Debian's security team maintains security updates for stable releases.

## Why Debian Matters for Security

Debian's influence is broad:

- **Direct usage** - Popular for servers, especially in Europe
- **Derivatives** - Ubuntu, Linux Mint, and 100+ distros are based on Debian
- **Stability focus** - Debian Stable is known for reliability
- **Security team** - Dedicated team handles security updates

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `dsa` | Debian Security Advisory (stable) | DSA-5678-1 |
| `dla` | Debian LTS Advisory (extended support) | DLA-3456-1 |
| `tracker` | Security Tracker (CVE status) | CVE-2024-1234 |
| `bts` | Bug Tracking System | 1012345 |

## Advisory Types

- **DSA (Debian Security Advisory)** - For current stable release
- **DLA (Debian LTS Advisory)** - For extended support releases (community-supported)

Both use similar format: `DSA-NNNN-R` or `DLA-NNNN-R` where R is revision number.

## Security Tracker

Debian's Security Tracker (security-tracker.debian.org) shows CVE status across all Debian releases. It's useful for checking if/when a CVE is fixed in each release.

## Notes

- Debian is upstream for Ubuntu security advisories
- Debian Stable prioritizes stability over newest versions
- Security support varies by release (Stable vs LTS vs oldstable)
