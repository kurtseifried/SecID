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
secid:advisory/<namespace>/<id>

secid:advisory/cve/CVE-2024-1234
secid:advisory/nvd/CVE-2024-1234
secid:advisory/ghsa/GHSA-xxxx-yyyy-zzzz
secid:advisory/osv/PYSEC-2024-1
secid:advisory/redhat/RHSA-2024:1234
secid:advisory/debian/DSA-5678-1
```

## Namespaces

| Namespace | Source | Description |
|-----------|--------|-------------|
| `cve` | MITRE CVE | Canonical vulnerability identifiers |
| `nvd` | NIST NVD | CVE enrichment (CVSS, CWE, CPE) |
| `ghsa` | GitHub | Package security advisories |
| `osv` | Google OSV | Type vulnerability database |
| `redhat` | Red Hat | RHSA, RHBA, CVE pages |
| `debian` | Debian | DSA, DLA advisories |
| `ubuntu` | Ubuntu | USN advisories |
| `cnvd` | China CNVD | Chinese vulnerability database |
| `euvd` | EU EUVD | European vulnerability database |

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
  "from": "secid:advisory/ghsa/GHSA-xxxx-yyyy",
  "to": "secid:advisory/cve/CVE-2024-1234",
  "type": "aliases",
  "asserted_by": "github"
}
```

```json
{
  "from": "secid:advisory/nvd/CVE-2024-1234",
  "to": "secid:advisory/cve/CVE-2024-1234",
  "type": "enriches",
  "description": "NVD adds CVSS, CPE, CWE to CVE records"
}
```

```json
{
  "from": "secid:advisory/redhat/RHSA-2024:1234",
  "to": "secid:advisory/cve/CVE-2024-1234",
  "type": "about",
  "description": "RHSA addresses this CVE"
}
```

## Notes

- CVE IDs always use `cve` namespace (not `mitre/cve`)
- NVD enriches CVE but doesn't issue IDs - the CVE itself is `advisory/cve/...`
- Different databases may have the same vulnerability with different IDs
- Use `aliases` relationship to connect equivalent advisories

