---
namespace: osv
full_name: "Open Source Vulnerabilities"
type: advisory
operator: "secid:entity/google/osv"

urls:
  website: "https://osv.dev"
  api: "https://api.osv.dev/v1"
  bulk_data: "https://osv-vulnerabilities.storage.googleapis.com"
  lookup: "https://osv.dev/vulnerability/{id}"

id_patterns:
  - pattern: "PYSEC-\\d{4}-\\d+"
    ecosystem: "PyPI"
  - pattern: "RUSTSEC-\\d{4}-\\d+"
    ecosystem: "crates.io"
  - pattern: "GO-\\d{4}-\\d+"
    ecosystem: "Go"
  - pattern: "GHSA-.*"
    ecosystem: "GitHub"

examples:
  - "PYSEC-2024-1"
  - "RUSTSEC-2024-0001"
  - "GO-2024-0001"

status: active
---

# OSV Namespace

Google's aggregated open source vulnerability database.

## Format

```
secid:advisory/osv/{ecosystem-id}
```

## Resolution

```
https://osv.dev/vulnerability/{id}
```

## Ecosystems

OSV aggregates from multiple sources:
- PyPI (PYSEC-*)
- crates.io (RUSTSEC-*)
- Go (GO-*)
- npm (via GHSA)
- And many more

## Notes

- Ecosystem-specific IDs
- Standardized OSV schema
- Machine-readable format
