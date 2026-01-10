---
namespace: cve
full_name: "Common Vulnerabilities and Exposures"
type: advisory
operator: "secid:entity/mitre/cve"

urls:
  website: "https://www.cve.org"
  api: "https://cveawg.mitre.org/api"
  bulk_data: "https://github.com/CVEProject/cvelistV5"
  lookup: "https://www.cve.org/CVERecord?id={id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"
examples:
  - "CVE-2024-1234"
  - "CVE-2023-44487"
  - "CVE-2021-44228"

status: active
---

# CVE Namespace

The canonical vulnerability identifier system.

## Format

```
secid:advisory/cve/CVE-YYYY-NNNNN
```

## Resolution

```
https://www.cve.org/CVERecord?id={id}
https://cveawg.mitre.org/api/cve/{id}
```

## Notes

- CVE is the canonical identifier - other advisories reference CVEs
- NVD enriches CVE records with CVSS, CPE, CWE
- Quality of descriptions varies by CNA
