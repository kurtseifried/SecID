---
namespace: cisco
full_name: "Cisco Security Advisories"
type: advisory
operator: "secid:entity/cisco/psirt"

urls:
  website: "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
  api: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory"
  lookup: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{id}"

id_pattern: "cisco-sa-[a-z0-9-]+"
examples:
  - "cisco-sa-apache-log4j-qRuKNEbd"
  - "cisco-sa-asaftd-xss-webui-gfnP9LmM"

status: active
---

# Cisco Namespace

Cisco Security Advisories (PSIRT).

## Format

```
secid:advisory/cisco/{id}
```

## Resolution

```
https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{id}
```

## Notes

- Uses descriptive IDs with random suffix
- Covers all Cisco products
- Includes severity ratings (Critical/High/Medium/Low)
