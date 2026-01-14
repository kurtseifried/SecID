---
type: advisory
namespace: cisa
name: kev
full_name: "Known Exploited Vulnerabilities Catalog"
operator: "secid:entity/cisa"

urls:
  website: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
  api: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  bulk_data: "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
  lookup: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"
examples:
  - "secid:advisory/cisa/kev#CVE-2024-1234"
  - "secid:advisory/cisa/kev#CVE-2021-44228"

status: active
---

# CISA KEV (Known Exploited Vulnerabilities)

CISA's authoritative catalog of vulnerabilities confirmed to be actively exploited in the wild. Federal agencies are required to remediate KEV entries within specified timeframes.

## Format

```
secid:advisory/cisa/kev#CVE-YYYY-NNNNN
```

## Resolution

KEV uses CVE IDs as identifiers:
```
https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={id}
```

## Why KEV Matters

KEV is a prioritization signal, not just another vulnerability list:
- **Confirmed exploitation** - Every entry has evidence of active exploitation
- **Binding for federal agencies** - BOD 22-01 requires remediation
- **Industry benchmark** - Many organizations use KEV for prioritization
- **Quality over quantity** - ~1000 entries vs 200,000+ CVEs

## Notes

- KEV entries reference CVE IDs, so SecID representation uses CVE as the subpath
- JSON and CSV feeds updated as vulnerabilities are added
- Due dates included for federal agency compliance tracking
