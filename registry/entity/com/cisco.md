---

type: "entity"
namespace: "cisco.com"

common_name: "Cisco"
full_name: "Cisco Systems, Inc."

urls:
  website: "https://www.cisco.com"
  security: "https://sec.cloudapps.cisco.com/security/center/home.x"

names:
  psirt:
    full_name: "Cisco Product Security Incident Response Team"
    description: "Cisco's security advisory and incident response program"
    urls:
      website: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
      api: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory"
    issues_type: "advisory"
    issues_namespace: "cisco.com"
  ios:
    full_name: "Cisco IOS"
    description: "Network operating system for routers and switches"
    urls:
      website: "https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-software/index.html"
  ios-xe:
    full_name: "Cisco IOS XE"
    description: "Modern network operating system"
    urls:
      website: "https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xe/index.html"
  asa:
    full_name: "Cisco Adaptive Security Appliance"
    description: "Firewall and VPN appliance"
    urls:
      website: "https://www.cisco.com/c/en/us/products/security/adaptive-security-appliance-asa-software/index.html"
  firepower:
    full_name: "Cisco Firepower"
    description: "Next-generation firewall and IPS"
    urls:
      website: "https://www.cisco.com/c/en/us/products/security/firepower-ngfw/index.html"
  webex:
    full_name: "Cisco Webex"
    description: "Collaboration and video conferencing platform"
    urls:
      website: "https://www.webex.com"

wikidata: "Q173395"
status: "active"
established: 1984
---


# Cisco

Cisco is a networking and security company providing routers, switches, firewalls, and collaboration tools.

## Names in This Namespace

| Name | Full Name | Description |
|------|-----------|-------------|
| `psirt` | Cisco PSIRT | Security advisories |
| `ios` | Cisco IOS | Network operating system |
| `ios-xe` | Cisco IOS XE | Modern network OS |
| `asa` | Cisco ASA | Firewall/VPN appliance |
| `firepower` | Cisco Firepower | Next-gen firewall |
| `webex` | Cisco Webex | Collaboration platform |

## Examples

```
secid:entity/cisco.com/psirt        # Cisco security response
secid:entity/cisco.com/ios          # IOS operating system
secid:entity/cisco.com/asa          # ASA firewall
```

## Security Content

Cisco PSIRT provides:

- **Security advisories**: Published at sec.cloudapps.cisco.com
- **CVRF/CSAF**: Machine-readable advisory formats
- **Impact ratings**: Critical, High, Medium, Low

See `advisory/cisco` for advisory identifiers.

## Notes

- Cisco advisories use descriptive IDs (cisco-sa-*) with random suffixes
- Different product lines have different support lifecycles
- IOS and IOS XE are different code bases despite similar names
