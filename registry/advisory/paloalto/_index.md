---
namespace: paloalto
full_name: "Palo Alto Networks"
website: "https://www.paloaltonetworks.com"
type: corporation
founded: 2005
headquarters: "Santa Clara, California, USA"
---

# Palo Alto Networks

Palo Alto Networks is a cybersecurity company known for next-generation firewalls and the Cortex security platform. They pioneered application-aware firewalls.

## Why Palo Alto Matters for Security

Palo Alto protects enterprise networks:

- **PAN-OS** - Operating system for firewalls
- **GlobalProtect** - VPN and endpoint protection
- **Cortex XDR** - Extended detection and response
- **Prisma** - Cloud security platform
- **Unit 42** - Threat intelligence team

Like Fortinet, Palo Alto firewall vulnerabilities are high-value targets.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `pan-sa` | Security Advisories | CVE-2024-3400 |

## Advisory ID Format

Palo Alto indexes advisories by CVE ID rather than a proprietary ID format. The security portal allows lookup by CVE number directly.

## Notable Vulnerabilities

- **CVE-2024-3400** - Critical PAN-OS command injection (actively exploited)
- **CVE-2024-0012** - Authentication bypass in management interface

Both appeared in CISA KEV with evidence of nation-state exploitation.

## Notes

- Palo Alto is a CVE Numbering Authority (CNA)
- GlobalProtect VPN vulnerabilities are high-risk (internet-exposed)
- Unit 42 publishes detailed threat research and IOCs
