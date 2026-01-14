---
type: advisory
namespace: cisa
name: vulnrichment
full_name: "CISA Vulnrichment"
operator: "secid:entity/cisa"

urls:
  website: "https://github.com/cisagov/vulnrichment"
  bulk_data: "https://github.com/cisagov/vulnrichment"
  lookup: "https://github.com/cisagov/vulnrichment/tree/develop/cvelistV5/{year}/{id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"
examples:
  - "secid:advisory/cisa/vulnrichment#CVE-2024-1234"

status: active
---

# CISA Vulnrichment

CISA's CVE enrichment initiative providing additional context for CVE records including CWE mappings, CVSS scores, and CPE data.

## Format

```
secid:advisory/cisa/vulnrichment#CVE-YYYY-NNNNN
```

## Resolution

```
https://github.com/cisagov/vulnrichment/tree/develop/cvelistV5/{year}/{id}
```

Where `{year}` is extracted from the CVE ID and `{id}` is the full CVE ID.

## Why Vulnrichment Exists

CISA provides enrichment data to fill gaps in CVE records:
- **Faster enrichment** - Doesn't wait for NVD processing
- **CWE mappings** - Weakness classification
- **CVSS scores** - Severity assessment
- **CPE data** - Affected product identification

## Notes

- Enrichment data follows CVE JSON 5.0 format
- Contributed back to the CVE ecosystem
- Addresses NVD enrichment backlog
