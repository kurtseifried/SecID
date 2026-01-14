---
type: advisory
namespace: go
name: vulndb
full_name: "Go Vulnerability Database"
operator: "secid:entity/google"

urls:
  website: "https://vuln.go.dev"
  api: "https://vuln.go.dev/index.json"
  bulk_data: "https://github.com/golang/vulndb"
  lookup: "https://pkg.go.dev/vuln/{id}"

id_pattern: "GO-\\d{4}-\\d+"
examples:
  - "secid:advisory/go/vulndb#GO-2024-2887"
  - "secid:advisory/go/vulndb#GO-2023-1840"

status: active
---

# Go Vulnerability Database

Official vulnerability database for Go modules, maintained by the Go security team at Google.

## Format

```
secid:advisory/go/vulndb#GO-YYYY-NNNN
```

## Resolution

```
https://pkg.go.dev/vuln/{id}
```

## Why Go Vulndb Matters

Go is the language of cloud-native infrastructure:
- **Security tools** - Trivy, Grype, Falco written in Go
- **Kubernetes ecosystem** - Controllers, operators, CLI tools
- **govulncheck** - Official vulnerability scanner
- **Symbol-level analysis** - Detects if vulnerable code is actually called

## Key Features

- **Call graph analysis** - govulncheck determines if vulnerable functions are reachable
- **Standard library coverage** - Includes Go stdlib vulnerabilities
- **Module-aware** - Understands Go module versioning
- **OSV format** - Machine-readable, interoperable

## Related Sources

- **OSV** - GO- advisories included in OSV
- **GitHub Advisory Database** - Cross-referenced

## Notes

- GO- IDs assigned by Go security team
- govulncheck integrates directly with this database
- Critical for Kubernetes and cloud-native security
