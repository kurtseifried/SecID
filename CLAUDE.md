# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SecID is about labeling and finding security knowledge. That's it.**

SecID provides a grammar and registry for referencing security knowledge. SecID does not assign identifiers—those come from their respective authorities (MITRE, NIST, etc.).

Format: `secid:type/namespace/name[@version][?qualifiers][#subpath]`

Examples:
- `secid:advisory/mitre/cve#CVE-2024-1234` - CVE record
- `secid:weakness/mitre/cwe#CWE-79` - CWE weakness
- `secid:ttp/mitre/attack#T1059.003` - ATT&CK technique
- `secid:control/nist/csf@2.0#PR.AC-1` - NIST CSF control
- `secid:reference/arxiv/2303.08774` - arXiv paper

## Current Status: v0.9 (Public Draft)

Working toward v1.0: Given a SecID string, return the URL(s) where that resource can be found.

See ROADMAP.md for details.

## Three Layers

SecID separates concerns:

| Layer | Contains | Example |
|-------|----------|---------|
| **Registry** | Identity, resolution, disambiguation | "CVE IDs look like CVE-YYYY-NNNNN, resolve at cve.org" |
| **Relationship** | Equivalence, succession | "This DOI = this arXiv paper" |
| **Data** | Enrichment, metadata | "This CVE affects Linux, severity high" |

The registry (this repo) only handles identity, resolution, and disambiguation.

## Repository Structure

```
secid/
├── SPEC.md                  # Full technical specification
├── RATIONALE.md             # Why SecID exists
├── DESIGN-DECISIONS.md      # Key design decisions and rationale
├── REGISTRY-GUIDE.md        # Principles and patterns for registry contributions
├── REGISTRY-JSON-FORMAT.md  # Target JSON schema specification
├── REGISTRY-FORMAT.md       # Current YAML+Markdown format
├── ROADMAP.md               # v1.0 scope and deliverables
├── registry/                # Namespace definitions (one file per namespace)
│   ├── <type>.md            # Type description
│   └── <type>/<namespace>.md
└── seed/                    # Bulk import data (CSV)
```

## Registry File Format

Registry files use YAML frontmatter + Markdown (Obsidian-compatible). One file per namespace containing all sources from that organization.

See [REGISTRY-GUIDE.md](REGISTRY-GUIDE.md) for contribution principles and [REGISTRY-JSON-FORMAT.md](REGISTRY-JSON-FORMAT.md) for the target JSON schema.

### Status Values

| Status | Meaning |
|--------|---------|
| `proposed` | Suggested, minimal info |
| `draft` | Being worked on |
| `pending` | Awaiting review (all fields present) |
| `published` | Reviewed and approved |

`published` means "reviewed", not "complete". Empty arrays and `null` values are valid—they show we looked and found nothing.

## Key Design Principles

1. **Scope: labeling and finding** - Identity, resolution, disambiguation only. Enrichment and relationships are separate layers.
2. **Follow the source** - Use names and ID structures the source uses
3. **AI-first** - Primary consumer is AI agents; include context and parsing hints
4. **PURL compatibility** - Same grammar as Package URL, different scheme

## SecID Types

| Type | Identifies |
|------|------------|
| `advisory` | Publications about vulnerabilities (CVE, GHSA, vendor advisories, incident reports) |
| `weakness` | Abstract flaw patterns (CWE, OWASP Top 10) |
| `ttp` | Adversary techniques (ATT&CK, ATLAS, CAPEC) |
| `control` | Security requirements (NIST CSF, ISO 27001, benchmarks) |
| `regulation` | Laws and legal requirements (GDPR, HIPAA) |
| `entity` | Organizations, products, services |
| `reference` | Documents, research, identifier systems (arXiv, DOI, ISBN, RFCs) |

Types are intentionally overloaded. Split only when usage proves it necessary.

## Granularity

Use the hierarchy levels the source provides:

```
secid:control/csa/ccm@4.0           → Whole framework
secid:control/csa/ccm@4.0#IAM       → Domain (group of controls)
secid:control/csa/ccm@4.0#IAM-12    → Specific control
```

Document each level with its own `id_pattern` and description.

## Adding New Namespaces

1. Determine type (advisory, weakness, ttp, control, regulation, entity, reference)
2. Check if `registry/<type>/<namespace>.md` exists
3. Add source to existing file OR create new namespace file
4. Include: urls, id_patterns (with descriptions), examples
5. Use `registry/_deferred/` for incomplete research

See [REGISTRY-GUIDE.md](REGISTRY-GUIDE.md) for detailed patterns.

## Development Commands

```bash
# Check registry files have required metadata
rg -n '^type:' registry/**/*.md

# Lint markdown
markdownlint **/*.md
```

## Encoding Rules

Special characters in names and subpaths are percent-encoded:
- `&` → `%26` (e.g., `A&A` → `A%26A`)
- Space → `%20`
- Reserved chars (`/`, `?`, `#`, `@`) must be encoded when literal

## Writing Principle

Explain **why**, not just what. "SecID uses `#subpath` because security knowledge is databases of identifiers, not packages with files" is better than just "SecID uses `#subpath` for specific items."
