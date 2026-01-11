# Advisory Type (`advisory`)

This type contains references to vulnerability advisories, publications, and records.

## Purpose

Track and coordinate vulnerability information across multiple advisory sources:
- CVE (MITRE) - canonical vulnerability identifier
- NVD (NIST) - CVE enrichment with CVSS, CWE, CPE
- GHSA (GitHub) - package-level advisories
- OSV (Google) - type-specific vulnerability data
- Vendor advisories (Red Hat, Microsoft, Debian, etc.)

## Identifier Format

```
secid:advisory/<namespace>/<name>[#subpath]

secid:advisory/mitre/cve#CVE-2024-1234
secid:advisory/nist/nvd#CVE-2024-1234
secid:advisory/github/ghsa#GHSA-xxxx-yyyy-zzzz
secid:advisory/google/osv#PYSEC-2024-1
secid:advisory/redhat/errata#RHSA-2024:1234
secid:advisory/debian/dsa#DSA-5678-1
```

## Namespaces

| Namespace | Name | Source | Description |
|-----------|------|--------|-------------|
| `mitre` | `cve` | MITRE CVE | Canonical vulnerability identifiers |
| `nist` | `nvd` | NIST NVD | CVE enrichment (CVSS, CWE, CPE) |
| `github` | `ghsa` | GitHub | Package security advisories |
| `google` | `osv` | Google OSV | Ecosystem vulnerability database |
| `redhat` | `cve`, `errata` | Red Hat | RHSA, RHBA, CVE pages |
| `debian` | `dsa`, `dla` | Debian | DSA, DLA advisories |
| `ubuntu` | `usn` | Ubuntu | USN advisories |
| `cnvd` | `cnvd` | China CNVD | Chinese vulnerability database |
| `eu` | `euvd` | EU EUVD | European vulnerability database |

## Why "Advisory" (Not "Vulnerability")?

A vulnerability doesn't exist without a description. The CVE Record IS what defines the CVE - there's no platonic vulnerability floating independent of some advisory describing it.

- **No redundancy**: CVE exists once, not in both `vulnerability/` and `advisory/`
- **Handles multi-vuln advisories**: RHSA-2024:1234 can be about multiple CVEs
- **Correct semantics**: All vulnerability records ARE publications/advisories

Canonical sources (CVE, OSV) are distinguished through **relationships**, not separate types.

## Vendor ID Routing

For vendors with multiple systems, the ID pattern determines routing:

```yaml
# Entity definition for advisory/redhat namespace
namespace: redhat
id_routing:
  - pattern: "CVE-*"
    system: "Red Hat CVE Database"
  - pattern: "RHSA-*"
    system: "Red Hat Security Advisory"
  - pattern: "RHBA-*"
    system: "Red Hat Bug Advisory"
  - pattern: "RHEA-*"
    system: "Red Hat Enhancement Advisory"
```

## Relationships

Advisories connect through aliasing and enrichment:

```json
{
  "from": "secid:advisory/github/ghsa#GHSA-xxxx-yyyy",
  "to": "secid:advisory/mitre/cve#CVE-2024-1234",
  "type": "aliases",
  "asserted_by": "github"
}
```

```json
{
  "from": "secid:advisory/nist/nvd#CVE-2024-1234",
  "to": "secid:advisory/mitre/cve#CVE-2024-1234",
  "type": "enriches",
  "description": "NVD adds CVSS, CPE, CWE to CVE records"
}
```

```json
{
  "from": "secid:advisory/redhat/errata#RHSA-2024:1234",
  "to": "secid:advisory/mitre/cve#CVE-2024-1234",
  "type": "about",
  "description": "RHSA addresses this CVE"
}
```

## Notes

- CVE is a MITRE project: `secid:advisory/mitre/cve#CVE-2024-1234`
- NVD enriches CVE but doesn't issue IDs - it's NIST's view: `secid:advisory/nist/nvd#CVE-2024-1234`
- Different databases may have the same vulnerability with different IDs
- Use `aliases` relationship to connect equivalent advisories

