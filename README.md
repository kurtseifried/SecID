# SecID - Security Identifiers

A federated identifier system for security knowledge, using [Package URL (PURL)](https://github.com/package-url/purl-spec) grammar with `secid:` as the scheme.

## What Is SecID?

[Package URL (PURL)](https://github.com/package-url/purl-spec) provides `pkg:type/namespace/name` for identifying software packages. In security, we need to identify many different things: advisories, weaknesses, attack techniques, controls, regulations, entities, and reference documents.

**SecID uses PURL grammar with `secid:` as the scheme.** Just as PURL uses `pkg:` as its scheme, SecID uses `secid:`. Everything after `secid:` follows PURL grammar exactly: `type/namespace/name[@version][?qualifiers][#subpath]`.

SecID is **explicitly scoped to identifiers only**. On its own, a naming system is useful but limited. The real value comes from what you build on top: relationship graphs, enrichment layers, tooling, and integrations. SecID is foundational infrastructure.

## PURL to SecID Mapping

SecID is PURL with a different scheme. The grammar is identical:

```
PURL:   pkg:type/namespace/name@version?qualifiers#subpath
SecID:  secid:type/namespace/name@version?qualifiers#subpath
```

**How each component maps:**

| PURL Component | SecID Component | SecID Usage |
|----------------|-----------------|-------------|
| `pkg:` | `secid:` | Scheme (constant prefix) |
| `type` | `type` | Security domain: `advisory`, `weakness`, `ttp`, `control`, `regulation`, `entity`, `reference` |
| `namespace` | `namespace` | **Organization** that publishes/maintains (e.g., `mitre`, `nist`, `csa`, `redhat`, `iso`) |
| `name` | `name` | **Database/framework/standard** they publish (e.g., `cve`, `nvd`, `cwe`, `attack`, `27001`) |
| `@version` | `@version` | Edition or revision (e.g., `@4.0`, `@2022`, `@2.0`) |
| `?qualifiers` | `?qualifiers` | Optional context (e.g., `?lang=ja`) |
| `#subpath` | `#subpath` | **Specific item** within the database (e.g., `#CVE-2024-1234`, `#CWE-79`, `#T1059`, `#A.8.1`) |

**Visual mapping:**

```
secid:advisory/mitre/cve#CVE-2024-1234
       ───┬─── ──┬── ─┬─ ──────┬──────
          │      │    │        └─ subpath: specific CVE identifier
          │      │    └────────── name: the CVE database
          │      └─────────────── namespace: MITRE (the organization)
          └────────────────────── type: advisory

secid:control/iso/27001@2022#A.8.1
       ──┬─── ─┬─ ──┬── ─┬── ──┬──
         │     │    │    │     └─ subpath: specific control (Annex A.8.1)
         │     │    │    └─────── version: 2022 edition
         │     │    └──────────── name: ISO 27001 standard
         │     └───────────────── namespace: ISO (the organization)
         └─────────────────────── type: control
```

**Key insight:** The namespace is always the **organization** (who publishes it), the name is the **thing they publish** (database, framework, standard), and the subpath is the **specific item within** that thing.

**Subpath hierarchy:** Subpaths can use `/` to express hierarchy within a document:

```
secid:control/csa/ccm@4.0#IAM-12                        # The control
secid:control/csa/ccm@4.0#IAM-12/audit                  # Audit section within control
secid:control/csa/ccm@4.0#IAM-12/implementation         # Implementation guidance
secid:regulation/eu/gdpr#art-32/1/a                     # Article 32(1)(a)
secid:weakness/mitre/cwe#CWE-79/potential-mitigations   # Mitigations section
```

**Percent encoding:** Special characters in names and subpaths are percent-encoded (URL encoding):

| Character | Encoded | Example |
|-----------|---------|---------|
| Space | `%20` | `Auditing Guidelines` → `Auditing%20Guidelines` |
| `&` | `%26` | `A&A-01` → `A%26A-01` |
| `(` `)` | `%28` `%29` | `(Draft)` → `%28Draft%29` |

```
secid:control/csa/aicm@1.0#A%26A-01                     # A&A-01 control
secid:control/csa/ccm@4.0#IAM-12/Auditing%20Guidelines  # Section with space
```

Tools should render these human-friendly for display while storing the encoded form.

## Divergences from PURL

SecID uses PURL grammar but diverges in three specific ways:

### 1. Scheme: `secid:` instead of `pkg:`

PURL uses `pkg:` to identify packages. SecID uses `secid:` to identify security knowledge. This is the expected way to use PURL grammar for a different domain - you change the scheme.

### 2. Type: Security domains instead of package ecosystems

PURL types are package ecosystems: `npm`, `pypi`, `maven`, `cargo`, `nuget`, etc.

SecID types are security domains: `advisory`, `weakness`, `ttp`, `control`, `regulation`, `entity`, `reference`.

This is semantic, not structural - the grammar is identical, just the vocabulary differs.

### 3. Subpath: Identifier references instead of file paths

**This is the significant divergence.**

In PURL, `#subpath` is defined as:
> "a subpath within the package, relative to the package root"

It's meant for file paths: `pkg:npm/lodash@4.17.21#lib/fp.js`

In SecID, `#subpath` identifies **specific items within a database or framework**:

```
secid:advisory/mitre/cve#CVE-2024-1234       # A specific CVE
secid:weakness/mitre/cwe#CWE-79              # A specific weakness
secid:ttp/mitre/attack#T1059.003             # A specific technique
secid:control/nist/800-53@r5#AC-1            # A specific control
secid:control/iso/27001@2022#A.8.1           # An ISO Annex control
secid:advisory/redhat/errata#RHSA-2024:1234  # A Red Hat advisory
```

**Why this divergence is necessary:**

Security databases aren't packages with files - they're registries of identifiers. CVE-2024-1234 isn't a file path; it's an identifier within the CVE database. CWE-79 isn't a directory; it's an entry in the weakness enumeration.

The subpath lets us say "this specific item within that database" using PURL-compatible syntax.

**Extended subpath semantics:**

Because security knowledge is often hierarchical, SecID subpaths support:

1. **Identifier prefixes** - Different item types within one namespace:
   ```
   secid:advisory/redhat/errata#RHSA-2024:1234  # Security Advisory
   secid:advisory/redhat/errata#RHBA-2024:5678  # Bug Advisory
   secid:advisory/redhat/errata#RHEA-2024:9012  # Enhancement Advisory
   ```

2. **Hierarchical references** using `/`:
   ```
   secid:control/csa/ccm@4.0#IAM-12/audit           # Audit section of control
   secid:regulation/eu/gdpr#art-32/1/a              # Article 32(1)(a)
   secid:weakness/mitre/cwe#CWE-79/mitigations      # Mitigations for CWE-79
   ```

3. **Framework-specific patterns**:
   ```
   secid:ttp/mitre/attack#T1059.003    # Sub-technique (ATT&CK uses dots)
   secid:control/iso/27001@2022#A.8.1  # Annex control (ISO uses dots)
   secid:control/nist/800-53@r5#AC-1   # Control family-number format
   ```

Each registry file documents its subpath patterns and how to resolve them to URLs.

**Registry file mapping:** The registry directory structure mirrors the SecID structure:

```
SecID:                          Registry File:
secid:weakness/mitre/cwe        → registry/weakness/mitre/cwe.md
secid:advisory/nist/nvd         → registry/advisory/nist/nvd.md
secid:ttp/mitre/attack          → registry/ttp/mitre/attack.md
secid:control/csa/ccm           → registry/control/csa/ccm.md
secid:regulation/eu/gdpr        → registry/regulation/eu/gdpr.md
```

Each registry file contains resolution rules for subpaths. For example, `registry/weakness/mitre/cwe.md` explains how to resolve `#CWE-123`:

```yaml
# In registry/weakness/mitre/cwe.md
urls:
  lookup: "https://cwe.mitre.org/data/definitions/{num}.html"

# secid:weakness/mitre/cwe#CWE-123
#   → extract "123" from "CWE-123"
#   → https://cwe.mitre.org/data/definitions/123.html
```

## Identifier Format

```
secid:type/namespace/name[@version][?qualifiers][#subpath]
```

**Examples:**
```
secid:advisory/mitre/cve#CVE-2024-1234            # CVE record
secid:weakness/mitre/cwe#CWE-79                   # CWE weakness
secid:ttp/mitre/attack#T1059.003                  # ATT&CK technique
secid:control/nist/csf@2.0#PR.AC-1          # NIST CSF control
secid:control/csa/aicm@1.0#A%26A-01         # CSA AICM control (A&A-01)
secid:regulation/eu/gdpr#art-32             # GDPR Article 32
secid:entity/mitre/cve                      # CVE program
secid:reference/whitehouse/eo-14110         # Reference document
```

Names are URL-encoded: `A&A-01` becomes `A%26A-01` in the identifier. Subpaths can use `/` for hierarchy. Tools render these human-friendly for display.

## Types

| Type | What it identifies |
|------|-------------------|
| `advisory` | Publications/records about vulnerabilities |
| `weakness` | Abstract flaw patterns |
| `ttp` | Adversary techniques and behaviors |
| `control` | Security requirements and capabilities that implement them |
| `regulation` | Laws and binding legal requirements |
| `entity` | Organizations, products, services, platforms |
| `reference` | Documents, publications, research |

## Repository Structure

```
secid/
├── SPEC.md              # Identifier specification
├── RATIONALE.md         # Why SecID exists
├── DESIGN-DECISIONS.md  # Key decisions (e.g., why no UUIDs)
├── STRATEGY.md          # Adoption and governance
├── ROADMAP.md           # Implementation phases
├── USE-CASES.md         # Concrete examples
├── RELATIONSHIPS.md     # Future: relationship layer (exploratory)
├── OVERLAYS.md          # Future: overlay layer (exploratory)
├── registry/            # Namespace definitions (mirrors SecID structure)
│   ├── advisory.md      # Advisory type description
│   ├── advisory/        # Advisory namespaces
│   │   ├── mitre/       # MITRE advisories
│   │   │   └── cve.md   # secid:advisory/mitre/cve
│   │   ├── nist/
│   │   │   └── nvd.md   # secid:advisory/nist/nvd
│   │   ├── github/
│   │   │   └── ghsa.md  # secid:advisory/github/ghsa
│   │   └── ...
│   ├── weakness.md      # Weakness type description
│   ├── weakness/
│   │   ├── mitre/
│   │   │   └── cwe.md   # secid:weakness/mitre/cwe
│   │   └── owasp/
│   │       ├── top10.md # secid:weakness/owasp/top10
│   │       └── llm-top10.md
│   ├── ttp.md           # TTP type description
│   ├── ttp/
│   │   └── mitre/
│   │       ├── attack.md # secid:ttp/mitre/attack
│   │       ├── atlas.md  # secid:ttp/mitre/atlas
│   │       └── capec.md  # secid:ttp/mitre/capec
│   ├── control.md       # Control type description
│   ├── control/
│   │   ├── nist/
│   │   │   ├── csf.md   # secid:control/nist/csf
│   │   │   └── 800-53.md
│   │   └── cis/
│   │       └── controls.md
│   ├── entity.md        # Entity type description
│   ├── entity/          # Entity namespaces (org descriptions)
│   │   ├── mitre.md
│   │   └── nist.md
│   └── ...
└── seed/                # Seed data for bulk import
```

The registry directory structure mirrors SecID identifiers: `registry/<type>/<namespace>/<name>.md`

## File Format

SecID is AI-first, meaning files need to be easily parsed by AI agents while remaining human-readable. We use markdown with YAML frontmatter (Obsidian-compatible):

```markdown
---
title: CVE Namespace
type: advisory
namespace: cve
---

# Content here...
```

Why this format:
- **Embedded metadata** - Structured data lives with the content, not in a separate file or database
- **AI-parseable** - YAML frontmatter is trivially extracted; markdown is universally understood by LLMs
- **Human-readable** - Works in any text editor, renders nicely on GitHub
- **Tool support** - Compatible with Obsidian, static site generators, and countless other tools
- **No better alternative** - This is the most common, simplest format for structured documents; we haven't found anything easier or more widely supported

## Glossary

| Term | Definition |
|------|------------|
| **SecID** | A complete identifier string starting with `secid:` |
| **Scheme** | The URL scheme - always `secid:` (like `pkg:` in PURL) |
| **Type** | The security domain (advisory, weakness, ttp, control, regulation, entity, reference) |
| **Namespace** | The organization that publishes/maintains (e.g., `mitre`, `nist`, `csa`, `owasp`) |
| **Name** | The database/framework/document they publish (e.g., `cve`, `nvd`, `ccm`, `attack`) |
| **Version** | Optional `@version` suffix for edition/revision (e.g., `@4.0`, `@2021`, `@2016-04-27`) |
| **Qualifier** | Optional `?key=value` for context that doesn't change identity |
| **Subpath** | The specific item within the document (e.g., `#CVE-2024-1234`, `#IAM-12`, `#T1059`); can use `/` for hierarchy |
| **Registry** | The collection of namespace definition files that document what identifiers exist |
| **Resolution** | The process of converting a SecID to a URL or retrieving the identified resource |

## Resolution Examples

SecIDs identify things; resolution retrieves them. Each namespace defines how to resolve its identifiers:

```
secid:advisory/mitre/cve#CVE-2026-0544
  → https://www.cve.org/CVERecord?id=CVE-2026-0544

secid:advisory/nist/nvd#CVE-2026-0544
  → https://nvd.nist.gov/vuln/detail/CVE-2026-0544

secid:advisory/redhat/cve#CVE-2026-0544
  → https://access.redhat.com/security/cve/CVE-2026-0544

secid:advisory/redhat/errata#RHSA-2026:0414
  → https://access.redhat.com/errata/RHSA-2026:0414

secid:weakness/mitre/cwe#CWE-79
  → https://cwe.mitre.org/data/definitions/79.html

secid:ttp/mitre/attack#T1059.003
  → https://attack.mitre.org/techniques/T1059/003/

secid:regulation/eu/gdpr#art-32
  → https://gdpr-info.eu/art-32-gdpr/
```

Resolution URLs are defined in each namespace's registry file.

## Documentation

| Document | Purpose |
|----------|---------|
| [SPEC.md](SPEC.md) | Full technical specification for identifiers |
| [RATIONALE.md](RATIONALE.md) | Why SecID exists and how we got here |
| [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) | Key decisions and alternatives considered |
| [STRATEGY.md](STRATEGY.md) | Adoption, governance, and positioning |
| [ROADMAP.md](ROADMAP.md) | Implementation phases and priorities |
| [USE-CASES.md](USE-CASES.md) | Concrete examples of what SecID enables |

### Future Work (Not Yet Designed)

| Document | Purpose |
|----------|---------|
| [RELATIONSHIPS.md](RELATIONSHIPS.md) | Exploratory thinking on how identifiers might connect |
| [OVERLAYS.md](OVERLAYS.md) | Exploratory thinking on enrichment without mutation |

**The spec is just IDs.** Relationships and overlays are future layers that will be designed based on real-world usage of the identifier system. We're deliberately deferring these to avoid premature complexity.

## Design Principles

1. **AI-first** - Primary consumer is AI agents; registry content includes context, guidance, and parsing hints that enable AI to work autonomously with security knowledge
2. **Identifiers are just identifiers** - The spec defines identifier syntax; relationships and enrichment are separate future layers
3. **Identifier, not locator** - SecID identifies things; resolution is separate
4. **Identity ≠ authority** - Identifiers don't imply trust or correctness
5. **PURL compatibility** - Same mental model, similar grammar
6. **Guidelines, not rules** - Human/AI readable, some messiness OK

## Getting Started

- **Read the spec:** [SPEC.md](SPEC.md)
- **Understand why:** [RATIONALE.md](RATIONALE.md)
- **See examples:** [USE-CASES.md](USE-CASES.md)
- **Browse namespaces:** [registry/](registry/)

## Current Status

**Phase 1: Specification + Registry** (Current)
- Identifier grammar defined
- Seven types established
- Registry structure in place
- Seed data for major types

**Future Work** (Not yet designed)
- Relationship layer - will be designed based on usage
- Overlay layer - will be designed based on usage

## License

[CC0 1.0 Universal](LICENSE) - Public Domain Dedication

---

*A project of the Cloud Security Alliance*
