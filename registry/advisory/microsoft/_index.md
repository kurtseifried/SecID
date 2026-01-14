---
namespace: microsoft
full_name: "Microsoft Corporation"
website: "https://www.microsoft.com"
type: corporation
founded: 1975
headquarters: "Redmond, Washington, USA"
---

# Microsoft Corporation

Microsoft is one of the world's largest technology companies, producing Windows, Office, Azure, and many other products. The Microsoft Security Response Center (MSRC) handles vulnerability disclosure and security updates.

## Why Microsoft Matters for Security

Microsoft's products are ubiquitous targets:

- **Windows** - Runs on billions of devices
- **Azure** - Major cloud platform
- **Office/365** - Enterprise productivity suite
- **Active Directory** - Enterprise identity infrastructure
- **Exchange** - Email infrastructure

Microsoft vulnerabilities frequently appear in CISA KEV and are targeted by nation-state actors.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `msrc` | Security Update Guide (current) | CVE-2024-1234 |
| `advisory` | Security Advisories (ADV) | ADV240001 |
| `kb` | Knowledge Base articles | KB5034441 |
| `bulletin` | Legacy Security Bulletins (pre-2017) | MS17-010 |

## Patch Tuesday

Microsoft releases security updates on the second Tuesday of each month ("Patch Tuesday"). This predictable schedule helps organizations plan patching.

## Historical Note

Before 2017, Microsoft used MS##-### format (e.g., MS17-010 for EternalBlue). These legacy bulletins are still referenced for historical vulnerabilities but new advisories use MSRC and CVE IDs.

## Notes

- Microsoft is a CVE Numbering Authority (CNA)
- MSRC provides its own CVSS scores which may differ from NVD
- Some advisories are Windows-specific, others cover Azure, Office, etc.
