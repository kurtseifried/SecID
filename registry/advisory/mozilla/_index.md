---
namespace: mozilla
full_name: "Mozilla Foundation / Mozilla Corporation"
website: "https://www.mozilla.org"
type: nonprofit
founded: 2003
headquarters: "San Francisco, California, USA"
---

# Mozilla

Mozilla is the nonprofit organization (and its subsidiary corporation) that develops Firefox, Thunderbird, and other open-source software. Mozilla pioneered many web security features.

## Why Mozilla Matters for Security

Mozilla develops critical internet software:

- **Firefox** - Major web browser (~3% market share, but security-focused users)
- **Thunderbird** - Email client
- **NSS (Network Security Services)** - Crypto library used by many projects
- **Rust** - Mozilla incubated the Rust programming language

Mozilla also runs security initiatives like the Mozilla Security Blog and bug bounty program.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `mfsa` | Mozilla Foundation Security Advisories | 2024-01 |
| `bugzilla` | Mozilla Bugzilla | 1234567 |

## Advisory ID Format

MFSA (Mozilla Foundation Security Advisory) uses YYYY-NN format:
```
MFSA 2024-01  (first advisory of 2024)
MFSA 2023-56  (56th advisory of 2023)
```

Each MFSA typically corresponds to a Firefox/Thunderbird release and may contain multiple CVEs.

## Security Culture

Mozilla has a strong security culture:
- Regular security releases
- Active bug bounty program
- Security bugs restricted until fixes ship
- Detailed security advisories

## Notes

- Mozilla is a CVE Numbering Authority (CNA)
- Firefox ESR (Extended Support Release) is popular in enterprises
- NSS vulnerabilities can affect many non-Mozilla applications
