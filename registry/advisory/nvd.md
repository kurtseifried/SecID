---
namespace: nvd
full_name: "National Vulnerability Database"
type: advisory
operator: "secid:entity/nist/nvd"

urls:
  website: "https://nvd.nist.gov"
  api: "https://services.nvd.nist.gov/rest/json/cves/2.0"
  bulk_data: "https://nvd.nist.gov/vuln/data-feeds"
  lookup: "https://nvd.nist.gov/vuln/detail/{id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"
examples:
  - "CVE-2024-1234"
  - "CVE-2023-44487"

status: active
---

# NVD Namespace

NIST's enrichment layer for CVE records.

## Format

```
secid:advisory/nvd/CVE-YYYY-NNNNN
```

## Resolution

```
https://nvd.nist.gov/vuln/detail/{id}
```

## What NVD Adds

- CVSS scores (base, temporal, environmental)
- CPE (affected product) mappings
- CWE classification
- Reference categorization
- Analysis notes

## Notes

- Uses same CVE IDs as cve namespace
- `advisory/nvd/CVE-X` is NVD's enrichment of `advisory/cve/CVE-X`
- NVD has 20,000+ CVE backlog; enrichment can take weeks or months
