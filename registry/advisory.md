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

### Core Vulnerability Databases

| Namespace | Names | Source | Description |
|-----------|-------|--------|-------------|
| `mitre` | `cve` | MITRE CVE | Canonical vulnerability identifiers |
| `nist` | `nvd` | NIST NVD | CVE enrichment (CVSS, CWE, CPE) |
| `cisa` | `kev`, `vulnrichment` | CISA | Known Exploited Vulnerabilities, CVE enrichment |
| `github` | `ghsa` | GitHub | Package security advisories |
| `google` | `osv`, `chrome`, `android`, `gcp-bulletins`, `project-zero` | Google | OSV, Chrome, Android, GCP bulletins, P0 |
| `cert` | `vu` | CERT/CC | VU# vulnerability notes |

### Ecosystem-Specific

| Namespace | Names | Source | Description |
|-----------|-------|--------|-------------|
| `pypi` | `advisory-db` | PyPA | Python package vulnerabilities (PYSEC) |
| `go` | `vulndb` | Go Team | Go module vulnerabilities (GO-) |
| `rustsec` | `advisories` | RustSec | Rust crate vulnerabilities (RUSTSEC-) |

### AI Security

| Namespace | Names | Source | Description |
|-----------|-------|--------|-------------|
| `avid` | `avid` | AVID | AI Vulnerability Database (AVID-YYYY-VNNN) |
| `partnershiponai` | `aiid` | Partnership on AI | AI Incident Database |

### Linux Distributions

| Namespace | Names | Source | Description |
|-----------|-------|--------|-------------|
| `redhat` | `cve`, `errata`, `bugzilla` | Red Hat | CVE pages, RHSA/RHBA/RHEA, Bugzilla |
| `debian` | `dsa`, `dla`, `tracker`, `bts` | Debian | DSA, DLA, CVE tracker, bug tracking |
| `ubuntu` | `usn`, `launchpad`, `cve-tracker` | Ubuntu | USN, Launchpad bugs, CVE tracker |
| `suse` | `suse-su`, `bugzilla` | SUSE | Security updates, Bugzilla |
| `aws` | `alas` | AWS | Amazon Linux Security Advisories |

### Major Vendors

| Namespace | Names | Source | Description |
|-----------|-------|--------|-------------|
| `microsoft` | `msrc`, `advisory`, `kb`, `bulletin` | Microsoft | MSRC, ADV, KB, legacy MS bulletins |
| `cisco` | `psirt`, `bug` | Cisco | PSIRT advisories, CSC bug IDs |
| `vmware` | `vmsa` | VMware/Broadcom | VMSA advisories |
| `fortinet` | `fsa` | Fortinet | FG-IR advisories |
| `paloalto` | `pan-sa` | Palo Alto | PAN-SA advisories |
| `oracle` | `cpu`, `alert` | Oracle | Critical Patch Updates, Security Alerts |
| `apple` | `ht` | Apple | HT security articles |

### Open Source Projects

| Namespace | Names | Source | Description |
|-----------|-------|--------|-------------|
| `mozilla` | `mfsa`, `bugzilla` | Mozilla | MFSA advisories, Bugzilla bugs |
| `apache` | `security`, `jira` | Apache | Security pages, Jira issues |
| `linux` | `kernel` | Linux | Kernel CVEs |
| `openssl` | `secadv` | OpenSSL | Security advisories |
| `atlassian` | `jira-security` | Atlassian | Confluence, Jira, Bitbucket advisories |

### National/Regional

| Namespace | Names | Source | Description |
|-----------|-------|--------|-------------|
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
secid:advisory/redhat/bugzilla#2045678       # Bugzilla bug (by ID)
secid:advisory/redhat/bugzilla#CVE-2024-1234 # Bugzilla bug (by CVE alias)
```

The `name` distinguishes the system (`cve` vs `errata` vs `bugzilla`). Within errata, the subpath prefix (`RHSA-`, `RHBA-`, `RHEA-`) distinguishes advisory types. Bugzilla accepts both numeric IDs and CVE aliases.

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

