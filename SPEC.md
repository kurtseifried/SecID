# SecID Specification

Version: 1.0-draft
Status: Working Draft

## 1. Overview

SecID (Security Identifier) is an identifier system for security knowledge, directly modeled after [Package URL (PURL)](https://github.com/package-url/purl-spec). It provides stable, canonical identifiers for security-relevant concepts including advisories, weaknesses, attack techniques, controls, regulations, entities, threat intelligence, and reference documents.

**SecID identifies things. It does not imply authority, truth, severity, or correctness.**

This is intentionally aligned with PURL:
- Identity ≠ metadata
- Identity ≠ trust
- Identity ≠ location

Resolution, dereferencing, or retrieval happens via APIs outside the identifier itself.

## 2. Grammar

SecID follows PURL's grammar:

```
secid:<type>/<namespace>/<name>[@<version>][?<qualifiers>][#<subpath>]
```

### 2.1 Components

| Component | Required | Description |
|-----------|----------|-------------|
| `secid:` | Yes | Scheme prefix (like `pkg:` for PURL) |
| `<type>` | Yes | What kind of thing this is |
| `<namespace>` | Yes | The identifier system or publishing authority |
| `<name>` | Yes | The upstream identifier string |
| `@<version>` | No | Edition or revision of the thing itself |
| `?<qualifiers>` | No | Optional disambiguation or scope |
| `#<subpath>` | No | Addressable part inside the thing |

### 2.2 Hard Rules

1. The primary identifier must live in `<name>`, never in qualifiers
2. Qualifiers never define identity, only context
3. Subpaths reference internal structure (articles, sections, guidance)
4. Canonical form always includes `secid:`, type, and namespace
5. Shorthands may exist for display but must normalize to canonical

### 2.3 Examples

```
secid:advisory/cve/CVE-2024-1234
secid:advisory/nvd/CVE-2024-1234
secid:advisory/ghsa/GHSA-xxxx-yyyy-zzzz
secid:advisory/redhat/RHSA-2024:1234
secid:weakness/cwe/CWE-79
secid:ttp/attack/T1059.003
secid:control/csa-ccm/IAM-12@4.0
secid:control/csa-ccm/IAM-12@4.0#implementation-guidance
secid:regulation/eu/gdpr@2016-04-27
secid:regulation/eu/gdpr#art-32
secid:entity/mitre/cve
secid:entity/openai/gpt-4
secid:reference/whitehouse/eo-14110
secid:reference/arxiv/2303.08774
```

## 3. Types

SecID defines seven types. No type overlaps another - each answers a different question.

| Type | What it identifies | Question it answers |
|------|-------------------|---------------------|
| `advisory` | Publications/records about vulnerabilities | "What's known about this vulnerability?" |
| `weakness` | Abstract flaw patterns | "What kind of mistake is this?" |
| `ttp` | Adversary techniques and behaviors | "How do attackers do this?" |
| `control` | Security requirements and capabilities that implement them | "How do we prevent/detect this?" |
| `regulation` | Laws and binding legal requirements | "What does the law require?" |
| `entity` | Vendors, products, services, platforms | "What/who is this?" |
| `reference` | Documents, publications, research | "What source supports this?" |

### 3.1 Advisory

Publications, records, or analyses about vulnerabilities.

```
secid:advisory/cve/CVE-2024-1234           # CVE record (canonical)
secid:advisory/nvd/CVE-2024-1234           # NVD enrichment
secid:advisory/ghsa/GHSA-xxxx-yyyy-zzzz    # GitHub Security Advisory
secid:advisory/osv/PYSEC-2024-1            # OSV/PyPI advisory
secid:advisory/redhat/CVE-2024-1234        # Red Hat CVE page
secid:advisory/redhat/RHSA-2024:1234       # Red Hat Security Advisory
secid:advisory/debian/DSA-5678-1           # Debian Security Advisory
secid:advisory/ubuntu/USN-6789-1           # Ubuntu Security Notice
```

**Why "advisory" instead of "vulnerability"?**

A vulnerability doesn't exist without a description. The CVE Record IS what defines the CVE - there's no platonic vulnerability floating in the ether independent of some advisory describing it. CVE and OSV are "canonical" not because they live in a special namespace, but because other advisories reference them.

**Vendor advisory ID routing:**

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

### 3.2 Weakness

Abstract, recurring flaw patterns - the "what kind of mistake" that underlies vulnerabilities.

```
secid:weakness/cwe/CWE-79                  # Cross-site Scripting
secid:weakness/cwe/CWE-89                  # SQL Injection
secid:weakness/cwe/CWE-1427                # Prompt Injection
secid:weakness/owasp-top10/A03-2021        # Injection (2021)
secid:weakness/owasp-llm/LLM01             # Prompt Injection
```

Multiple advisories can share the same weakness type.

### 3.3 TTP (Tactics, Techniques, Procedures)

Reusable adversary behaviors - how attacks are carried out.

```
secid:ttp/attack/T1059                     # Command and Scripting Interpreter
secid:ttp/attack/T1059.003                 # Windows Command Shell
secid:ttp/attack/TA0001                    # Initial Access (tactic)
secid:ttp/atlas/AML.T0043                  # Prompt Injection
secid:ttp/atlas/AML.T0051                  # LLM Jailbreak
secid:ttp/capec/CAPEC-66                   # SQL Injection attack pattern
```

### 3.4 Control

Security requirements (from frameworks) or capabilities (from vendors).

```
secid:control/csa-ccm/IAM-12@4.0           # CSA CCM control
secid:control/csa-ccm/IAM-12@4.0#audit     # Audit guidance subpath
secid:control/nist-csf/PR.AC-1@2.0         # NIST CSF subcategory
secid:control/cis/1.1@8.0                  # CIS Control
secid:control/iso27001/A.8.1@2022          # ISO 27001 Annex A control
secid:control/csa-aicm/INP-01              # CSA AI Controls Matrix
```

### 3.5 Regulation

Laws, directives, and binding legal requirements.

```
secid:regulation/eu/gdpr                   # GDPR
secid:regulation/eu/gdpr@2016-04-27        # GDPR with version date
secid:regulation/eu/gdpr#art-32            # Article 32
secid:regulation/eu/gdpr#art-32.1.a        # Article 32(1)(a)
secid:regulation/us/hipaa                  # HIPAA
secid:regulation/us/hipaa#164.312.a.1      # Security Rule citation
secid:regulation/us/sox                    # Sarbanes-Oxley
secid:regulation/eu/nis2                   # NIS2 Directive
```

### 3.6 Entity

Organizations, products, services, platforms - stable anchors when PURL/SPDX are unavailable.

```
secid:entity/mitre/cve                     # CVE program (operated by MITRE)
secid:entity/mitre/cwe                     # CWE taxonomy
secid:entity/mitre/attack                  # ATT&CK framework
secid:entity/nist/nvd                      # NVD (operated by NIST)
secid:entity/openai/gpt-4                  # GPT-4 product
secid:entity/aws/s3                        # S3 service
secid:entity/redhat/rhel                   # RHEL product
```

The namespace is the organization; the name is the specific thing (product, service, system) within that organization. The namespace definition file (e.g., `registry/entity/mitre.md`) describes the organization itself.

### 3.7 Reference

Documents, publications, and research that don't fit into other categories. The reference type has a **deliberately narrow scope** to avoid duplicating what other types cover well.

```
secid:reference/whitehouse/eo-14110           # Executive Order on AI
secid:reference/whitehouse/eo-14028           # Cybersecurity Executive Order
secid:reference/whitehouse/m-24-10            # OMB AI Governance Memo
secid:reference/arxiv/2303.08774              # GPT-4 Technical Report
secid:reference/arxiv/2307.03109              # Jailbroken paper
secid:reference/arxiv/2402.05369              # Sleeper Agents paper
```

**What belongs in reference:**
- White House executive orders and policy documents
- Research papers (particularly AI security research on arXiv)
- Primary sources that inform security practices

**What does NOT belong in reference:**
- NIST publications → Use `control/nist-*` for frameworks, entity for systems
- ISO standards → Use `control/iso*`
- OWASP documents → Use `weakness/owasp-*`
- Vendor security pages → Use `advisory/*` or `entity/*`

**Reference namespaces (current):**
```
whitehouse      # White House publications (EOs, NSMs, OMB memos)
arxiv           # ArXiv preprints (AI/ML security research)
```

Additional namespaces may be added when there's a clear need for documents that genuinely don't fit elsewhere.

**Subpaths:**

```
secid:reference/whitehouse/eo-14110#section-4.1   # Specific section
secid:reference/arxiv/2303.08774#appendix-a       # Paper appendix
```

**Note:** Document classification (research paper, position paper, etc.) lives in metadata, not in the identifier.

## 4. Namespaces

Namespaces identify the system that issued the identifier.

### 4.0 Namespaces and the Registry

Each type has a directory in the registry containing namespace definition files:

```
registry/
├── advisory.md           # Describes the advisory type
├── advisory/             # Advisory namespaces
│   ├── cve.md            # CVE namespace: patterns, resolution, etc.
│   ├── nvd.md
│   ├── ghsa.md
│   └── redhat.md         # ID routing: CVE-*, RHSA-*, RHBA-*, RHEA-*, NNNNNN
├── entity.md             # Describes the entity type
├── entity/               # Entity namespaces
│   ├── mitre.md          # MITRE namespace (cve, cwe, attack, etc.)
│   └── openai.md         # OpenAI namespace (gpt-4, etc.)
...
```

The namespace file (e.g., `advisory/redhat.md`) contains all the rules for parsing and resolving the `<name>` component within that namespace.

### 4.1 Naming Conventions

**Keep namespaces short when unambiguous:**
```
cve         # Not mitre-cve (everyone knows CVE)
ghsa        # Not github-ghsa
cwe         # Not mitre-cwe
attack      # Not mitre-attack
nvd         # Not nist-nvd
```

**Use longer names only when needed for disambiguation:**
```
owasp-top10     # Distinguish from owasp-llm
owasp-llm       # OWASP LLM Top 10
csa-ccm         # CSA Cloud Controls Matrix
csa-aicm        # CSA AI Controls Matrix
nist-csf        # NIST Cybersecurity Framework
```

**For vendors, let ID patterns do the routing:**
```
secid:advisory/redhat/CVE-2024-1234      # Routes to CVE database
secid:advisory/redhat/RHSA-2024:1234     # Routes to advisory database
secid:advisory/redhat/2045678            # Routes to Bugzilla
```

Only create sub-namespaces (`redhat-bugzilla`) if ID patterns genuinely collide.

### 4.2 Namespace Governance

- Namespaces are assigned, not discovered
- Common systems get short names
- Unknown or third-party systems may require longer names
- Namespaces identify identifier systems, not trust

### 4.3 Namespace Documentation

Each namespace has a documentation file explaining:
- What identifiers it issues
- URLs for lookup/resolution
- How to reference items within documents (subpath conventions)
- Version history and conventions

See Section 8 for the entity registry format used for namespace documentation.

## 5. Versions, Qualifiers, and Subpaths

### 5.1 Version (`@version`)

Pins a specific edition of the thing itself. Use version when the **content changes across releases**.

#### When to Use Versions

| Scenario | Use Version? | Example |
|----------|--------------|---------|
| Framework releases | Yes | `@4.0`, `@8.0`, `@2.0` |
| Law publication dates | Yes | `@2016-04-27`, `@2022` |
| Annual updates | Yes | `@2021`, `@2024` |
| Scoring system versions | Yes | `@3.1`, `@4.0` |
| Static IDs that never change | No | CVE IDs don't need versions |

#### Version Format Conventions

**Semantic versions** - for frameworks with numbered releases:
```
secid:control/csa-ccm/IAM-12@4.0           # CCM version 4.0
secid:control/cis/1.1@8.0                  # CIS Controls v8
secid:control/nist-csf/PR.AC-1@2.0         # NIST CSF 2.0
secid:weakness/owasp-top10/A03@2021        # OWASP Top 10 2021 edition
secid:weakness/owasp-llm/LLM01@2.0         # OWASP LLM Top 10 v2
```

**Date versions** - for laws and dated publications:
```
secid:regulation/eu/gdpr@2016-04-27        # GDPR publication date
secid:regulation/eu/ai-act@2024-08-01      # EU AI Act effective date
secid:regulation/us/hipaa@1996             # Year for older laws
```

**Year versions** - for annual updates:
```
secid:weakness/owasp-top10/A01@2021        # 2021 edition
secid:weakness/owasp-top10/A01@2017        # 2017 edition (different!)
secid:control/iso27001/A.8.1@2022          # ISO 27001:2022
secid:control/iso27001/A.8.1@2013          # ISO 27001:2013
```

#### Versionless References

When version is omitted, assume "current" or "latest":
```
secid:control/csa-ccm/IAM-12               # Current CCM version
secid:weakness/owasp-top10/A03             # Current Top 10
```

### 5.2 Qualifiers (`?key=value`)

Optional context that doesn't change identity:

```
secid:control/cloudflare/waf?surface=api   # API-specific context
secid:advisory/nvd/CVE-2024-1234?lang=ja   # Japanese translation
```

Qualifiers never define identity - two SecIDs differing only in qualifiers refer to the same thing with different context.

### 5.3 Subpath (`#subpath`)

Addressable parts inside the thing. Use subpath to reference **structural components** within a document.

#### Subpath Conventions by Type

**Regulations - Legal Citations:**
```
# Articles
secid:regulation/eu/gdpr#art-32            # Article 32
secid:regulation/eu/gdpr#art-32.1          # Article 32, paragraph 1
secid:regulation/eu/gdpr#art-32.1.a        # Article 32(1)(a)
secid:regulation/eu/gdpr#art-32.1.a.ii     # Article 32(1)(a)(ii)

# Chapters and Sections
secid:regulation/eu/gdpr#chapter-4         # Chapter IV
secid:regulation/eu/gdpr#recital-78        # Recital 78

# US Code Style
secid:regulation/us/hipaa#164.312          # 45 CFR 164.312
secid:regulation/us/hipaa#164.312.a.1      # 164.312(a)(1)
secid:regulation/us/hipaa#164.312.a.2.iv   # 164.312(a)(2)(iv)

# Sections
secid:regulation/us/sox#section-302        # Section 302
secid:regulation/us/sox#section-404        # Section 404
```

**Controls - Guidance Sections:**
```
# CCM control guidance
secid:control/csa-ccm/IAM-12@4.0#audit-guidance
secid:control/csa-ccm/IAM-12@4.0#implementation-guidance
secid:control/csa-ccm/IAM-12@4.0#control-specification

# NIST sections
secid:control/nist-csf/PR.AC-1@2.0#examples
secid:control/nist-csf/PR.AC-1@2.0#informative-references

# ISO control parts
secid:control/iso27001/A.8.1@2022#purpose
secid:control/iso27001/A.8.1@2022#guidance
```

**Advisories - Multiple CVEs in One Advisory:**
```
# Red Hat advisory covering multiple CVEs
secid:advisory/redhat/RHSA-2024:1234#CVE-2024-1111
secid:advisory/redhat/RHSA-2024:1234#CVE-2024-2222
secid:advisory/redhat/RHSA-2024:1234#CVE-2024-3333

# Debian advisory sections
secid:advisory/debian/DSA-5678-1#CVE-2024-1234

# GHSA with multiple affected packages
secid:advisory/ghsa/GHSA-xxxx-yyyy-zzzz#npm
secid:advisory/ghsa/GHSA-xxxx-yyyy-zzzz#pip
```

**Weaknesses - Structural Sections:**
```
# CWE sections
secid:weakness/cwe/CWE-79#extended-description
secid:weakness/cwe/CWE-79#potential-mitigations
secid:weakness/cwe/CWE-79#detection-methods
secid:weakness/cwe/CWE-79#observed-examples

# OWASP Top 10 sections
secid:weakness/owasp-top10/A03@2021#description
secid:weakness/owasp-top10/A03@2021#how-to-prevent
secid:weakness/owasp-top10/A03@2021#example-attack-scenarios
```

**TTPs - Framework Sections:**
```
# ATT&CK technique sections
secid:ttp/attack/T1059#detection
secid:ttp/attack/T1059#mitigation
secid:ttp/attack/T1059#procedure-examples

# Sub-techniques (note: these are names, not subpaths)
secid:ttp/attack/T1059.003                 # This is the ID, not a subpath
secid:ttp/attack/T1059.003#detection       # Section within sub-technique
```

**References - Document Sections:**
```
# Executive orders and policy documents
secid:reference/whitehouse/eo-14110#section-4.1   # AI EO section 4.1
secid:reference/whitehouse/eo-14110#section-4.2   # AI EO section 4.2
secid:reference/whitehouse/m-24-10#appendix-a     # OMB memo appendix

# Research paper sections
secid:reference/arxiv/2303.08774#section-3        # GPT-4 paper section
secid:reference/arxiv/2307.03109#appendix         # Jailbroken appendix
secid:reference/arxiv/2402.05369#methodology      # Sleeper Agents methodology
```

#### Subpath Naming Rules

1. Use lowercase with hyphens: `#implementation-guidance` not `#ImplementationGuidance`
2. Keep it short but descriptive: `#art-32` not `#article-number-32`
3. Mirror source structure when possible: use the document's own section names
4. Preserve upstream IDs: `#CVE-2024-1234` keeps the CVE format

### 5.4 Combined Version and Subpath

Version and subpath can be used together:

```
# Specific article in specific version
secid:regulation/eu/gdpr@2016-04-27#art-32.1.a

# Control guidance in framework version
secid:control/csa-ccm/IAM-12@4.0#audit-guidance

# Specific section in dated release
secid:weakness/owasp-top10/A03@2021#how-to-prevent

# ISO control guidance in specific year
secid:control/iso27001/A.8.1@2022#implementation-guidance
```

## 6. Future Layers: Relationships and Overlays

**Identifiers are just identifiers.** This specification defines how to write SecID strings. What you can say *about* SecIDs - relationships between them, enrichments, corrections - belongs in separate data layers.

### Planned Layers

| Layer | Purpose | Status |
|-------|---------|--------|
| **Relationships** | Connect SecIDs (aliases, enriches, mitigates, etc.) | Planned - see [RELATIONSHIPS.md](RELATIONSHIPS.md) |
| **Overlays** | Add metadata without modifying sources | Planned - see [OVERLAYS.md](OVERLAYS.md) |

### Why Deferred?

These layers involve design decisions that benefit from real-world usage:

- Relationship directionality and cardinality
- Conflict resolution between assertions
- Provenance and authority tracking
- Storage formats and query patterns

Rather than design these upfront, we're building the identifier system and registry first. Usage will inform the data layer design.


## 7. Namespace Definition Format

Namespace files use Obsidian-style format: YAML frontmatter + Markdown body.

### 7.1 Frontmatter (Structured Data)

```yaml
---
# What type this namespace belongs to
type: "advisory"
namespace: "redhat"

# Human-readable names
common_name: "Red Hat Security"
full_name: "Red Hat Product Security"

# Resolution
urls:
  website: "https://access.redhat.com/security/"
  api: "https://access.redhat.com/hydra/rest/securitydata"

# ID routing - how to parse and resolve <name> patterns
id_routing:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    system: "Red Hat CVE Database"
    url_template: "https://access.redhat.com/security/cve/{id}"
  - pattern: "RHSA-\\d{4}:\\d+"
    system: "Red Hat Security Advisory"
    url_template: "https://access.redhat.com/errata/{id}"
  - pattern: "RHBA-\\d{4}:\\d+"
    system: "Red Hat Bug Advisory"
    url_template: "https://access.redhat.com/errata/{id}"
  - pattern: "\\d{7}"
    system: "Bugzilla"
    url_template: "https://bugzilla.redhat.com/show_bug.cgi?id={id}"

# Examples
examples:
  - "secid:advisory/redhat/CVE-2024-1234"
  - "secid:advisory/redhat/RHSA-2024:1234"

status: "active"
---
```

### 7.2 Markdown Body (Rich Context)

The body contains human/AI-readable context:

- **What It Is** - Description of this namespace
- **ID Formats** - Detailed explanation of name patterns
- **Resolution** - How to look up identifiers
- **Caveats** - Important gotchas, edge cases
- **Recent Developments** - Current events, changes

## 8. Normalization Rules

### 8.1 String Normalization

- Lowercase type and namespace: `secid:advisory/cve/...`
- Preserve case in name when it's an upstream ID: `CVE-2024-1234` not `cve-2024-1234`
- Remove special characters from namespaces: `ATT&CK` → `attack`
- Hyphens allowed for multi-word: `owasp-top10`
- No slashes in namespace (that's the separator)

### 8.2 Canonical Form

All SecIDs should normalize to:
```
secid:<type>/<namespace>/<name>[@version][?qualifiers][#subpath]
```

Display shorthands must expand to canonical form for storage and comparison.

## 9. Design Principles

1. **Identifiers are just identifiers** - Registry defines what exists; relationships and enrichment are separate future layers
2. **Identifier, not locator** - SecID identifies things; resolution is separate
3. **Identity ≠ authority** - Identifiers don't imply trust or correctness
4. **Guidelines, not rules** - Human/AI readable, some messiness OK
5. **PURL compatibility** - Same mental model, similar grammar

### 9.1 The Three Layers

SecID separates concerns into three layers:

| Layer | Purpose | Status |
|-------|---------|--------|
| **Registry** | Defines namespaces, ID patterns, resolution | Current (`registry/`) |
| **Relationships** | Connections between identifiers | Future (see [RELATIONSHIPS.md](RELATIONSHIPS.md)) |
| **Overlays** | Corrections, enrichments, warnings | Future (see [OVERLAYS.md](OVERLAYS.md)) |

The registry is definitional: "what identifiers exist and how to resolve them." It doesn't track history, state changes, or connections - those will belong in relationship and overlay layers once designed.

## 10. Repository Structure

SecID is a single repository containing specification and registry:

```
secid/
├── README.md              # Project overview
├── SPEC.md                # This specification
├── RATIONALE.md           # Design decisions
├── STRATEGY.md            # Adoption and governance
├── ROADMAP.md             # Implementation phases
├── USE-CASES.md           # Concrete examples
├── RELATIONSHIPS.md       # Future layer (exploratory)
├── OVERLAYS.md            # Future layer (exploratory)
├── registry/              # Namespace definitions by type
│   ├── advisory.md        # Advisory type description
│   ├── advisory/          # Advisory namespaces
│   │   ├── cve.md
│   │   ├── nvd.md
│   │   ├── ghsa.md
│   │   └── redhat.md
│   ├── entity.md          # Entity type description
│   ├── entity/            # Entity namespaces
│   │   ├── mitre.md
│   │   └── openai.md
│   ├── weakness.md
│   ├── weakness/
│   ├── ttp.md
│   ├── ttp/
│   ├── control.md
│   ├── control/
│   ├── regulation.md
│   ├── regulation/
│   ├── reference.md
│   └── reference/
└── seed/                  # Seed data for bulk import
    └── *.csv
```

