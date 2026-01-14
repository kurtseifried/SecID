# SecID - Security Identifiers

A federated identifier system for security knowledge, using [Package URL (PURL)](https://github.com/package-url/purl-spec) grammar with `secid:` as the scheme.

## The Problem

Security knowledge is fragmented across dozens of databases, each with its own identifier format, API, and data model:

- **CVE-2024-1234** lives in MITRE's CVE database
- **GHSA-xxxx-yyyy-zzzz** lives in GitHub's advisory database
- **CWE-79** lives in MITRE's weakness taxonomy
- **T1059.003** lives in MITRE ATT&CK
- **AC-1** lives in NIST 800-53

There's no standard way to say "this CVE is related to this CWE, which is exploited by this ATT&CK technique, and mitigated by this control." Tools can't easily cross-reference. AI agents can't navigate. Humans spend hours on manual lookup.

And if you want to build your own security database - tracking incidents, internal vulnerabilities, or emerging threats - there's no standard way to reference external knowledge. You end up with ad-hoc links, broken URLs, and no interoperability.

**SecID solves this** by providing a single, consistent identifier format for all security knowledge. Like DNS for domain names or PURL for packages, SecID is the "phone book" that tells you where things are and how they connect. Anyone can use it, anyone can extend it, and everything stays interoperable.

## What Is SecID?

[Package URL (PURL)](https://github.com/package-url/purl-spec) provides `pkg:type/namespace/name` for identifying software packages. In security, we need to identify many different things: advisories, weaknesses, attack techniques, controls, regulations, entities, and reference documents.

**SecID uses PURL grammar with `secid:` as the scheme.** Just as PURL uses `pkg:` as its scheme, SecID uses `secid:`. Everything after `secid:` follows PURL grammar exactly: `type/namespace/name[@version][?qualifiers][#subpath]`.

SecID is **explicitly scoped to identifiers only**. On its own, a naming system is useful but limited. The real value comes from what you build on top: relationship graphs, enrichment layers, tooling, and integrations. SecID is foundational infrastructure.

## Vision

**A SecID isn't just an identifier - it's a handle that gives you everything you need to understand and work with security knowledge.**

Today, security data is fragmented. CVEs live in one place, CWEs in another, controls in spreadsheets, regulations in PDFs. Finding information requires knowing where to look. Understanding it requires domain expertise. Connecting it requires manual effort.

SecID changes this. When you have a SecID, you can:

1. **Find it** - Get the URL or search instructions
2. **Understand it** - Read a description of what it is
3. **Read it** - Get the actual content (where licensing permits)
4. **Interpret it** - Understand what the fields mean
5. **Use it** - Know what to do with this data
6. **Connect it** - See related concepts, mitigations, and examples

**This is AI-first infrastructure.** The primary consumer is AI agents that need to navigate security knowledge autonomously. When an agent receives a SecID response, it should be self-describing - the agent knows what it has, how to interpret it, and what to do with it.

We're building this in layers:
- **v1.0**: URL resolution + descriptions (where to find it, what it is)
- **v1.x**: Raw content with licensing (the actual text, properly attributed)
- **v2.x**: Metadata wrapper (interpretation and usage guidance for AI)
- **Future**: Relationships and overlays (connections and enrichment)

See [ROADMAP.md](ROADMAP.md) for the full implementation plan.

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

**Percent encoding:** Special characters in names and subpaths are percent-encoded (URL encoding) for compatibility across URLs, filesystems, and shells:

| Character | Encoded | Example |
|-----------|---------|---------|
| Space | `%20` | `Auditing Guidelines` → `Auditing%20Guidelines` |
| `&` | `%26` | `A&A-01` → `A%26A-01` |
| `$` | `%24` | `$variable` → `%24variable` |
| `[` `]` | `%5B` `%5D` | `File[1]` → `File%5B1%5D` |

Many other characters require encoding: `: / @ ? # % \ < > " | { } ! ' ( ) * , + ; = ~ ^ `` ` ``

See [SPEC.md Section 8.2](SPEC.md#82-percent-encoding) for the complete encoding reference.

```
secid:control/csa/aicm@1.0#A%26A-01                     # A&A-01 control
secid:control/csa/ccm@4.0#IAM-12/Auditing%20Guidelines  # Section with space
```

Tools should render these human-friendly for display while storing the encoded form.

## Relationship to PURL

**SecID is 95% identical to PURL.** The grammar, structure, and mental model are the same. If you know PURL, you know SecID.

| Same as PURL | Different in SecID |
|--------------|-------------------|
| Grammar: `scheme:type/namespace/name@version?qualifiers#subpath` | Scheme: `secid:` instead of `pkg:` |
| Percent encoding rules | Types: security domains instead of package ecosystems |
| Version and qualifier semantics | Subpath: references items in databases, not files in packages |

### Why the Differences Matter

PURL identifies packages. SecID identifies security knowledge. Different domains need different schemes - that's expected.

The types change from package ecosystems (`npm`, `pypi`, `maven`) to security domains (`advisory`, `weakness`, `control`). This is vocabulary, not structure.

**The subpath difference is where the real value comes from.**

PURL's `#subpath` points to files: `pkg:npm/lodash@4.17.21#lib/fp.js`

SecID's `#subpath` points to **specific items within security knowledge**:

```
secid:advisory/mitre/cve#CVE-2024-1234           # A specific vulnerability
secid:control/nist/800-53@r5#AC-1               # A specific security control
secid:regulation/eu/gdpr#art-32/1/a             # Article 32(1)(a) of GDPR
secid:ttp/mitre/attack#T1059.003                # A specific attack technique
secid:weakness/mitre/cwe#CWE-79/mitigations     # Mitigations section within a weakness
```

Security knowledge isn't packages with files - it's databases of identifiers, frameworks of controls, and regulations with articles. The subpath lets us precisely reference any item within any security knowledge system.

### What This Precision Enables

Being able to reference specific items - not just "the NIST 800-53 framework" but "control AC-1 in revision 5" - unlocks capabilities that weren't possible before:

- **Cross-reference security knowledge**: Link a CVE to its CWE weakness to the ATT&CK technique that exploits it
- **Map compliance requirements**: Connect GDPR Article 32 to the specific controls that satisfy it
- **Build relationship graphs**: Express that control X mitigates weakness Y which is exploited by technique Z
- **Layer enrichment data**: Add severity scores, organizational context, or remediation guidance on top of canonical identifiers
- **Enable AI-powered security tooling**: Give agents precise handles to fetch, compare, and reason about security knowledge

SecID is foundational infrastructure. The identifier system is deliberately simple; the value comes from what you build on top.

### Subpath Patterns

SecID subpaths support hierarchical references and framework-specific patterns:

```
secid:control/csa/ccm@4.0#IAM-12/audit           # Audit section of a control
secid:regulation/eu/gdpr#art-32/1/a              # Article 32(1)(a)
secid:advisory/redhat/errata#RHSA-2024:1234      # Red Hat Security Advisory
secid:advisory/redhat/errata#RHBA-2024:5678      # Red Hat Bug Advisory
```

Each registry file documents its subpath patterns and resolution rules.

### Registry File Mapping

The registry directory structure mirrors SecID identifiers:

```
SecID:                          Registry File:
secid:weakness/mitre/cwe        → registry/weakness/mitre/cwe.md
secid:advisory/nist/nvd         → registry/advisory/nist/nvd.md
secid:ttp/mitre/attack          → registry/ttp/mitre/attack.md
secid:control/csa/ccm           → registry/control/csa/ccm.md
secid:regulation/eu/gdpr        → registry/regulation/eu/gdpr.md
```

Each registry file contains resolution rules. For example, `registry/weakness/mitre/cwe.md` explains how `#CWE-123` resolves to `https://cwe.mitre.org/data/definitions/123.html`.

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

**Version 0.9 - Public Draft**

This specification is open for public comment. We welcome feedback, questions, and suggestions via [GitHub Issues](https://github.com/kurtseifried/SecID/issues).

**What's Ready:**
- Identifier grammar defined
- Seven types established
- Registry structure with 100+ namespace definitions
- Documentation for spec, rationale, design decisions, and strategy

**What's In Progress:**
- Registry expansion (targeting broader coverage)
- Reference implementations (Python library first)
- Compliance test suite

**What's Planned (Post-1.0):**
- REST API for resolution
- Relationship layer
- Overlay layer

## License

[CC0 1.0 Universal](LICENSE) - Public Domain Dedication

---

*A project of the Cloud Security Alliance*
