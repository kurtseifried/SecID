# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SecID provides a grammar and registry for referencing security knowledge. SecID does not assign identifiers—those come from their respective authorities.**

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
├── registry/            # Namespace definitions (one file per namespace)
│   ├── <type>.md        # Type description (advisory.md, weakness.md, etc.)
│   └── <type>/<namespace>.md  # All sources from that namespace in one file
└── seed/                # Bulk import data (CSV)
```

Registry uses one file per namespace: `registry/advisory/redhat.md` contains all Red Hat sources (cve, errata, bugzilla). Each source is a section within that file, not a separate subdirectory.

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

All registry files use YAML frontmatter + Markdown (Obsidian-compatible). Each namespace file contains all sources from that organization:

```yaml
---
type: advisory
namespace: redhat
full_name: "Red Hat Security"
operator: "secid:entity/redhat"
status: active

sources:
  cve:
    full_name: "Red Hat CVE Database"
    urls:
      website: "https://access.redhat.com/security/cve"
      lookup: "https://access.redhat.com/security/cve/{id}"
    id_pattern: "CVE-\\d{4}-\\d{4,}"
    examples:
      - "secid:advisory/redhat/cve#CVE-2024-1234"

  errata:
    full_name: "Red Hat Security Errata"
    urls:
      website: "https://access.redhat.com/errata"
      lookup: "https://access.redhat.com/errata/{id}"
    id_pattern: "RH[SBE]A-\\d{4}:\\d+"
    examples:
      - "secid:advisory/redhat/errata#RHSA-2024:1234"
---

# Red Hat Security Advisories

[Narrative content for AI/human consumption covering all Red Hat sources]
```

Required frontmatter: `type`, `namespace`, `full_name`, `status`, `sources` (with at least one source)

### Status Field

The `status` field indicates the state of the **registry entry itself**, not the external source it documents:

| Status | Meaning |
|--------|---------|
| `active` | Entry is current and maintained |
| `draft` | Entry is work-in-progress |
| `superseded` | Entry replaced by another (use `superseded_by` to indicate replacement) |
| `historical` | Kept for reference; source may no longer exist |

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

**Note:** Types are intentionally overloaded with related concepts:
- `advisory` also contains incident reports (AIID, NHTSA, FDA) - both are "something happened" publications
- `control` also contains prescriptive benchmarks (HarmBench, WMDP) and documentation standards (Model Cards)

Split into new types only when usage proves it necessary.

## Encoding Rules

Special characters in names and subpaths are percent-encoded:
- `&` → `%26` (e.g., `A&A-01` → `A%26A-01`)
- Space → `%20`
- Reserved chars (`/`, `?`, `#`, `@`) must be encoded when literal

## Adding New Namespaces

1. Determine type (advisory, weakness, ttp, control, regulation, entity, reference)
2. Identify namespace (organization that publishes the identifiers)
3. Check if `registry/<type>/<namespace>.md` exists:
   - **If yes**: Add a new source section to the existing file's `sources:` block
   - **If no**: Create the namespace file with frontmatter and all known sources
4. Include for each source: urls, id_pattern (PCRE2 safe subset), examples
5. Add narrative markdown explaining the namespace and its sources
6. Use `registry/_deferred/` for partially researched systems

## Peer Schemes (Don't Duplicate)

SecID complements, not replaces: `pkg:` (PURL), `CVSS:`, `spdx:`, `doi:`, `swh:`
