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
| `microsoft` | `msrc`, `advisory`, `kb` | Microsoft | MSRC CVEs, ADV advisories, KB articles |
| `debian` | `dsa`, `dla`, `tracker` | Debian | DSA, DLA advisories, CVE tracker |
| `ubuntu` | `usn` | Ubuntu | USN advisories |
| `cisco` | `psirt` | Cisco | PSIRT advisories |
| `cnvd` | `cnvd` | China CNVD | Chinese vulnerability database |
| `eu` | `euvd` | EU EUVD | European vulnerability database |

## Why "Advisory" (Not "Vulnerability")?

A vulnerability doesn't exist without a description. The CVE Record IS what defines the CVE - there's no platonic vulnerability floating independent of some advisory describing it.

- **No redundancy**: CVE exists once, not in both `vulnerability/` and `advisory/`
- **Handles multi-vuln advisories**: RHSA-2024:1234 can be about multiple CVEs
- **Correct semantics**: All vulnerability records ARE publications/advisories

Canonical sources (CVE, OSV) are distinguished through **relationships**, not separate types.

## Vendors with Multiple Advisory Systems

Some vendors have multiple advisory systems, each with its own `name`:

**Red Hat example:**

```
secid:advisory/redhat/cve#CVE-2024-1234      # Red Hat CVE Database (vulnerability info)
secid:advisory/redhat/errata#RHSA-2024:1234  # Red Hat Security Advisory (the fix)
secid:advisory/redhat/errata#RHBA-2024:5678  # Red Hat Bug Advisory
secid:advisory/redhat/errata#RHEA-2024:9012  # Red Hat Enhancement Advisory
```

The `name` distinguishes the system (`cve` vs `errata`), and the subpath prefix (`RHSA-`, `RHBA-`, `RHEA-`) distinguishes the advisory type within errata.

**Microsoft example:**

```
secid:advisory/microsoft/msrc#CVE-2024-1234      # MSRC CVE database
secid:advisory/microsoft/advisory#ADV240001      # Security Advisory (defense-in-depth)
secid:advisory/microsoft/kb#KB5001234            # Knowledge Base article (patch)
```

**Debian example:**

```
secid:advisory/debian/dsa#DSA-5678-1         # Debian Security Advisory (stable)
secid:advisory/debian/dla#DLA-3456-1         # Debian LTS Advisory (extended support)
secid:advisory/debian/tracker#CVE-2024-1234  # Debian Security Tracker (CVE status)
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

