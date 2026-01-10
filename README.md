# SecID - Security Identifiers

A federated identifier system for security knowledge, modeled after [Package URL (PURL)](https://github.com/package-url/purl-spec).

## What Is SecID?

SecID provides stable, canonical identifiers for security-relevant concepts:

```
secid:<type>/<namespace>/<name>[@<version>][?<qualifiers>][#<subpath>]
```

**Examples:**
```
secid:advisory/cve/CVE-2024-1234           # CVE record
secid:weakness/cwe/CWE-79                  # CWE weakness
secid:ttp/attack/T1059.003                 # ATT&CK technique
secid:control/nist-csf/PR.AC-1@2.0         # NIST CSF control
secid:regulation/eu/gdpr#art-32            # GDPR Article 32
secid:entity/mitre/cve                     # CVE program
secid:reference/whitehouse/eo-14110        # Reference document
```

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
├── registry/            # Namespace definitions by type
│   ├── advisory.md      # Advisory type description
│   ├── advisory/        # Advisory namespaces (cve.md, nvd.md, etc.)
│   ├── entity.md        # Entity type description
│   ├── entity/          # Entity namespaces (mitre.md, nist.md, etc.)
│   └── ...              # Other types follow same pattern
└── seed/                # Seed data for bulk import
```

## Glossary

| Term | Definition |
|------|------------|
| **SecID** | A complete identifier string starting with `secid:` |
| **Type** | The category of thing being identified (advisory, weakness, ttp, control, regulation, entity, reference) |
| **Namespace** | The system or authority that issued the identifier (e.g., `cve`, `ghsa`, `redhat`, `cwe`) |
| **Name** | The upstream identifier exactly as issued (e.g., `CVE-2024-1234`, `CWE-79`, `RHSA-2024:1234`) |
| **Version** | Optional `@version` suffix for edition/revision of the thing (e.g., `@4.0`, `@2021`, `@2016-04-27`) |
| **Qualifier** | Optional `?key=value` for context that doesn't change identity |
| **Subpath** | Optional `#subpath` to reference internal structure (e.g., `#art-32`, `#section-4.1`) |
| **Registry** | The collection of namespace definition files that document what identifiers exist |
| **Resolution** | The process of converting a SecID to a URL or retrieving the identified resource |

## Resolution Examples

SecIDs identify things; resolution retrieves them. Each namespace defines how to resolve its identifiers:

```
secid:advisory/cve/CVE-2026-0544
  → https://www.cve.org/CVERecord?id=CVE-2026-0544

secid:advisory/nvd/CVE-2026-0544
  → https://nvd.nist.gov/vuln/detail/CVE-2026-0544

secid:advisory/redhat/CVE-2026-0544
  → https://access.redhat.com/security/cve/CVE-2026-0544

secid:advisory/redhat/RHSA-2026:0414
  → https://access.redhat.com/errata/RHSA-2026:0414

secid:weakness/cwe/CWE-79
  → https://cwe.mitre.org/data/definitions/79.html

secid:ttp/attack/T1059.003
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

TBD

---

*A project of the Cloud Security Alliance*
