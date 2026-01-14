---
namespace: cisco
full_name: "Cisco Systems, Inc."
website: "https://www.cisco.com"
type: corporation
founded: 1984
headquarters: "San Jose, California, USA"
---

# Cisco Systems

Cisco is the world's largest networking equipment vendor, producing routers, switches, firewalls, and collaboration tools. Cisco's Product Security Incident Response Team (PSIRT) handles vulnerability disclosure.

## Why Cisco Matters for Security

Cisco equipment forms the backbone of most enterprise and ISP networks:

- **IOS/IOS-XE** - Operating system for routers and switches
- **ASA/Firepower** - Firewall and security appliances
- **Webex** - Collaboration and video conferencing
- **Meraki** - Cloud-managed networking

Cisco vulnerabilities can enable network-wide compromise. Nation-state actors frequently target Cisco devices.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `psirt` | PSIRT Security Advisories | cisco-sa-apache-log4j-qRuKNEbd |
| `bug` | Bug Search Tool (CSC IDs) | CSCvv12345 |

## Advisory ID Format

Cisco PSIRT advisories use descriptive IDs:
```
cisco-sa-{description}-{random-suffix}
cisco-sa-apache-log4j-qRuKNEbd
```

CSC bug IDs are referenced in advisories for tracking in Cisco's bug system.

## Notes

- Cisco is a CVE Numbering Authority (CNA)
- Many Cisco advisories require Cisco.com login for full details
- Cisco uses severity ratings: Critical, High, Medium, Low, Informational
