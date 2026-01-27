---
type: advisory
namespace: go
full_name: "Go Programming Language"
operator: "secid:entity/google"
website: "https://go.dev"
status: active

sources:
  vulndb:
    full_name: "Go Vulnerability Database"
    urls:
      website: "https://vuln.go.dev"
      api: "https://vuln.go.dev/index.json"
      bulk_data: "https://github.com/golang/vulndb"
      lookup: "https://pkg.go.dev/vuln/{id}"
    id_pattern: "GO-\\d{4}-\\d+"
    examples:
      - "secid:advisory/go/vulndb#GO-2024-2887"
      - "secid:advisory/go/vulndb#GO-2023-1840"
---

# Go Advisory Sources

Go (Golang) is a programming language developed by Google, known for its simplicity, concurrency support, and fast compilation. The Go team maintains an official vulnerability database for Go modules.

## Why Go Matters for Security

Go powers cloud-native infrastructure:

- **Kubernetes** - Written in Go
- **Docker** - Written in Go
- **Security tools** - Trivy, Grype, Falco, etc.
- **Cloud infrastructure** - Terraform, Consul, Vault

Go vulnerabilities can affect critical infrastructure tooling.

## GO- ID Format

Go advisories use GO- prefix:
```
GO-2024-2887  (year 2024, advisory 2887)
GO-2023-1840  (year 2023, advisory 1840)
```

## govulncheck

Go provides official tooling for vulnerability detection:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

**Key feature**: govulncheck performs call graph analysis to determine if vulnerable code is actually reachable in your application, reducing false positives.

## Relationship to OSV

Go advisories are indexed in Google's OSV database and use OSV schema:
```
https://osv.dev/vulnerability/GO-2024-2887
```

## Notes

- The Go team maintains vulndb at github.com/golang/vulndb
- Go's standard library is also covered (not just third-party modules)
- Symbol-level analysis distinguishes govulncheck from other scanners

---

## vulndb

Official vulnerability database for Go modules, maintained by the Go security team at Google.

### Format

```
secid:advisory/go/vulndb#GO-YYYY-NNNN
```

### Resolution

```
https://pkg.go.dev/vuln/{id}
```

### Why Go Vulndb Matters

Go is the language of cloud-native infrastructure:
- **Security tools** - Trivy, Grype, Falco written in Go
- **Kubernetes ecosystem** - Controllers, operators, CLI tools
- **govulncheck** - Official vulnerability scanner
- **Symbol-level analysis** - Detects if vulnerable code is actually called

### Key Features

- **Call graph analysis** - govulncheck determines if vulnerable functions are reachable
- **Standard library coverage** - Includes Go stdlib vulnerabilities
- **Module-aware** - Understands Go module versioning
- **OSV format** - Machine-readable, interoperable

### Related Sources

- **OSV** - GO- advisories included in OSV
- **GitHub Advisory Database** - Cross-referenced

### Notes

- GO- IDs assigned by Go security team
- govulncheck integrates directly with this database
- Critical for Kubernetes and cloud-native security
