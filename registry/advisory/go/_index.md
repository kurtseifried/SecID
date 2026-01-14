---
namespace: go
full_name: "Go Programming Language"
website: "https://go.dev"
type: opensource
founded: 2009
operator: "Go Team at Google"
---

# Go Programming Language

Go (Golang) is a programming language developed by Google, known for its simplicity, concurrency support, and fast compilation. The Go team maintains an official vulnerability database for Go modules.

## Why Go Matters for Security

Go powers cloud-native infrastructure:

- **Kubernetes** - Written in Go
- **Docker** - Written in Go
- **Security tools** - Trivy, Grype, Falco, etc.
- **Cloud infrastructure** - Terraform, Consul, Vault

Go vulnerabilities can affect critical infrastructure tooling.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `vulndb` | Go Vulnerability Database | GO-2024-2887 |

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
