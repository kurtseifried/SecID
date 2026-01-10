---

type: "entity"
namespace: "microsoft"

common_name: "Microsoft"
full_name: "Microsoft Corporation"

urls:
  website: "https://www.microsoft.com"
  security: "https://www.microsoft.com/en-us/security"

names:
  msrc:
    full_name: "Microsoft Security Response Center"
    description: "Microsoft's security advisory and incident response program"
    urls:
      website: "https://msrc.microsoft.com"
      api: "https://api.msrc.microsoft.com"
      blog: "https://msrc.microsoft.com/blog"
    issues_type: "advisory"
    issues_namespace: "microsoft"
  azure:
    full_name: "Microsoft Azure"
    description: "Cloud computing platform"
    urls:
      website: "https://azure.microsoft.com"
      portal: "https://portal.azure.com"
      docs: "https://docs.microsoft.com/en-us/azure"
      security: "https://docs.microsoft.com/en-us/azure/security"
  windows:
    full_name: "Microsoft Windows"
    description: "Operating system family"
    urls:
      website: "https://www.microsoft.com/en-us/windows"
      docs: "https://docs.microsoft.com/en-us/windows"
      security: "https://www.microsoft.com/en-us/windows/comprehensive-security"
  m365:
    full_name: "Microsoft 365"
    description: "Productivity and collaboration platform"
    urls:
      website: "https://www.microsoft.com/en-us/microsoft-365"
      security: "https://www.microsoft.com/en-us/security/business/microsoft-365-security"
  defender:
    full_name: "Microsoft Defender"
    description: "Security product family"
    urls:
      website: "https://www.microsoft.com/en-us/security/business/microsoft-defender"
  sentinel:
    full_name: "Microsoft Sentinel"
    description: "Cloud-native SIEM and SOAR"
    urls:
      website: "https://azure.microsoft.com/en-us/products/microsoft-sentinel"

wikidata: "Q2283"
status: "active"
established: 1975
---


# Microsoft

Microsoft is a technology company providing operating systems, cloud services, productivity software, and security solutions.

## Names in This Namespace

| Name | Full Name | Description |
|------|-----------|-------------|
| `msrc` | Microsoft Security Response Center | Security advisories |
| `azure` | Microsoft Azure | Cloud platform |
| `windows` | Microsoft Windows | Operating system |
| `m365` | Microsoft 365 | Productivity platform |
| `defender` | Microsoft Defender | Security products |
| `sentinel` | Microsoft Sentinel | SIEM/SOAR platform |

## Examples

```
secid:entity/microsoft/msrc      # Security Response Center
secid:entity/microsoft/azure     # Azure cloud platform
secid:entity/microsoft/windows   # Windows operating system
```

## Security Content

Microsoft operates comprehensive security programs:

- **MSRC**: Security advisories, Patch Tuesday releases (see `advisory/microsoft`)
- **Threat intelligence**: Microsoft Threat Intelligence Center (MSTIC)
- **Bug bounty**: Multiple bounty programs for different products

## Notes

- Patch Tuesday releases monthly security updates
- Azure security services span identity, network, and data protection
- Microsoft acquired GitHub (2018), LinkedIn (2016), and Nuance (2022)
