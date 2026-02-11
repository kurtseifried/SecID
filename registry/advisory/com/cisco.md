---
type: advisory
namespace: cisco.com
full_name: "Cisco Systems, Inc."
operator: "secid:entity/cisco.com"
website: "https://www.cisco.com"
status: active

sources:
  psirt:
    full_name: "Cisco Security Advisories"
    urls:
      website: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
      api: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory"
      lookup: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{id}"
    id_pattern: "cisco-sa-[a-z0-9-]+"
    examples:
      - "secid:advisory/cisco.com/psirt#cisco-sa-apache-log4j-qRuKNEbd"
      - "secid:advisory/cisco.com/psirt#cisco-sa-asaftd-xss-webui-gfnP9LmM"
  bug:
    full_name: "Cisco Bug Search"
    urls:
      website: "https://bst.cloudapps.cisco.com/bugsearch"
      lookup: "https://bst.cloudapps.cisco.com/bugsearch/bug/{id}"
    id_pattern: "CSC[a-z]{2}\\d{5}"
    examples:
      - "secid:advisory/cisco.com/bug#CSCvv12345"
      - "secid:advisory/cisco.com/bug#CSCwa98765"
---

# Cisco Advisory Sources

Cisco is the world's largest networking equipment vendor, producing routers, switches, firewalls, and collaboration tools. Cisco's Product Security Incident Response Team (PSIRT) handles vulnerability disclosure.

## Why Cisco Matters for Security

Cisco equipment forms the backbone of most enterprise and ISP networks:

- **IOS/IOS-XE** - Operating system for routers and switches
- **ASA/Firepower** - Firewall and security appliances
- **Webex** - Collaboration and video conferencing
- **Meraki** - Cloud-managed networking

Cisco vulnerabilities can enable network-wide compromise. Nation-state actors frequently target Cisco devices.

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

---

## psirt

Cisco Security Advisories (PSIRT).

### Format

```
secid:advisory/cisco.com/psirt#cisco-sa-{description}-{suffix}
```

### Resolution

```
https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{id}
```

### Notes

- Uses descriptive IDs with random suffix
- Covers all Cisco products
- Includes severity ratings (Critical/High/Medium/Low)

---

## bug

Cisco's bug tracking system. Security bugs are tracked with CSC identifiers.

### Format

```
secid:advisory/cisco.com/bug#CSCxx12345
```

CSC IDs are formatted as "CSC" + two lowercase letters + five digits.

### Resolution

```
secid:advisory/cisco.com/bug#CSCvv12345
  -> https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv12345
```

### Notes

- CSC numbers are referenced in PSIRT advisories
- Some bugs require Cisco.com login to view
- For official security advisories, see `secid:advisory/cisco.com/psirt`
