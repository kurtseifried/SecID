# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecID is a federated identifier system for security knowledge using PURL grammar with `secid:` as the scheme. It provides canonical identifiers for security concepts: advisories, weaknesses, TTPs, controls, regulations, entities, and references.

Format: `secid:type/namespace/name[@version][?qualifiers][#subpath]`

Examples:
- `secid:advisory/mitre/cve#CVE-2024-1234` - CVE record
- `secid:weakness/mitre/cwe#CWE-79` - CWE weakness
- `secid:ttp/mitre/attack#T1059.003` - ATT&CK technique
- `secid:control/nist/csf@2.0#PR.AC-1` - NIST CSF control

## Current Status: v0.9 (Public Draft)

The specification and registry are open for public comment. Working toward v1.0 (URL Resolution).

**v1.0 Goal**: Given a SecID string, return the URL(s) where that resource can be found.

**Priority order**: Registry data → Python library → npm/TypeScript → REST API → Go → Rust → Java → C#/.NET

See ROADMAP.md for details.

## Repository Structure

```
secid/
├── SPEC.md              # Full technical specification
├── RATIONALE.md         # Why SecID exists
├── DESIGN-DECISIONS.md  # Key decisions (no UUIDs, AI-first design)
├── ROADMAP.md           # v1.0 scope and deliverables
├── registry/            # Namespace definitions (mirrors SecID structure)
│   ├── <type>.md        # Type description
│   └── <type>/<namespace>/<name>.md  # Database/framework definition
└── seed/                # Bulk import data (CSV)
```

Registry path mirrors SecID: `registry/advisory/mitre/cve.md` → `secid:advisory/mitre/cve`

## Development Commands

```bash
# Audit registry files have required metadata
rg -n '^type:' registry/**/*.md

# Lint markdown before PRs
markdownlint **/*.md

# Validate CSV structure
column -t -s, seed/seed-controls.csv | head
```

## Registry File Format

All registry files use YAML frontmatter + Markdown (Obsidian-compatible):

```yaml
---
type: advisory
namespace: mitre
name: cve
full_name: "Common Vulnerabilities and Exposures"
operator: "secid:entity/mitre/cve"

urls:
  website: "https://www.cve.org"
  lookup: "https://www.cve.org/CVERecord?id={id}"

id_pattern: "CVE-\\d{4}-\\d{4,}"
examples:
  - "secid:advisory/mitre/cve#CVE-2024-1234"

status: active
---

# CVE (MITRE)

[Narrative content for AI/human consumption]
```

Required frontmatter: `type`, `namespace`, `name`, title

## Key Design Principles

1. **Identifiers are just identifiers** - Relationships and enrichment are separate future layers (see RELATIONSHIPS.md, OVERLAYS.md)
2. **AI-first** - Primary consumer is AI agents; registry content includes context and parsing hints
3. **Follow the source** - Use names the owner/vendor uses (e.g., "ROSA" not "openshift-aws-managed-service")
4. **PURL compatibility** - Same grammar as Package URL, different scheme

## Writing Principle: Explain the Why

When writing documentation or registry content, always explain **why**, not just **what** or **how**.

- **Bad**: "SecID uses `#subpath` for specific items instead of file paths"
- **Good**: "SecID uses `#subpath` for specific items because security knowledge is databases of identifiers, not packages with files. This precision enables cross-referencing vulnerabilities to weaknesses to controls."

The "why" connects features to value:
- Why does this difference from PURL matter? → It enables relationship graphs and compliance mapping
- Why use this namespace structure? → It lets you reference specific controls in frameworks, not just the framework itself
- Why is SecID AI-first? → AI agents need precise handles to fetch, compare, and reason about security knowledge

Documentation that explains "why" helps readers (human and AI) understand when to use something, not just how to use it.

## SecID Types

| Type | Identifies |
|------|------------|
| `advisory` | Publications about vulnerabilities (CVE, GHSA, vendor advisories) |
| `weakness` | Abstract flaw patterns (CWE, OWASP Top 10) |
| `ttp` | Adversary techniques (ATT&CK, ATLAS, CAPEC) |
| `control` | Security requirements (NIST CSF, ISO 27001, CIS Controls) |
| `regulation` | Laws and legal requirements (GDPR, HIPAA) |
| `entity` | Organizations, products, services |
| `reference` | Documents and research (Executive Orders, arXiv papers) |

## Encoding Rules

Special characters in names and subpaths are percent-encoded:
- `&` → `%26` (e.g., `A&A-01` → `A%26A-01`)
- Space → `%20`
- Reserved chars (`/`, `?`, `#`, `@`) must be encoded when literal

## Adding New Namespaces

1. Determine type (advisory, weakness, ttp, control, regulation, entity, reference)
2. Identify namespace (organization) and name (what they publish)
3. Create `registry/<type>/<namespace>/<name>.md`
4. Include: frontmatter with urls/id_pattern/examples + markdown body with format/resolution/notes
5. Use `registry/_deferred/` for partially researched systems

## Peer Schemes (Don't Duplicate)

SecID complements, not replaces: `pkg:` (PURL), `CVSS:`, `spdx:`, `doi:`, `swh:`
