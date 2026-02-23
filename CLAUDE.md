# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SecID is about labeling and finding security knowledge. That's it.**

SecID provides a grammar and registry for referencing security knowledge. SecID does not assign identifiers—those come from their respective authorities (MITRE, NIST, etc.).

Format: `secid:type/namespace/name[@version][?qualifiers][#subpath[@item_version][?qualifiers]]`

Examples:
- `secid:advisory/mitre.org/cve#CVE-2024-1234` - CVE record
- `secid:weakness/mitre.org/cwe#CWE-79` - CWE weakness
- `secid:ttp/mitre.org/attack#T1059.003` - ATT&CK technique
- `secid:control/nist.gov/csf@2.0#PR.AC-1` - NIST CSF control
- `secid:reference/arxiv.org/2303.08774` - arXiv paper

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

## Document Map

With 20+ markdown files, know which document answers which question:

| Question | Read This |
|----------|-----------|
| How do SecID strings work? | [SPEC.md](SPEC.md) - grammar, types, parsing, encoding |
| Why does SecID exist? | [RATIONALE.md](RATIONALE.md) |
| Why was X designed this way? | [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) |
| How do I add a namespace? | [REGISTRY-GUIDE.md](REGISTRY-GUIDE.md) - principles, patterns, process |
| What's the JSON schema? | [REGISTRY-JSON-FORMAT.md](REGISTRY-JSON-FORMAT.md) - target format for v1.0+ |
| What's the current file format? | [REGISTRY-FORMAT.md](REGISTRY-FORMAT.md) - YAML+Markdown (what's in use now) |
| What's being built and when? | [ROADMAP.md](ROADMAP.md) |
| How does versioning work? | [VERSIONING.md](VERSIONING.md) - analysis, API behavior, response outcomes |
| Edge cases with domains? | [EDGE-CASES.md](EDGE-CASES.md) |
| What's deferred? | [TODO.md](TODO.md), [registry/_deferred/](registry/_deferred/) |

Documents like RELATIONSHIPS.md, OVERLAYS.md, FUTURE-VISION.md, and STRATEGY.md are exploratory/aspirational — not needed for day-to-day registry work.

## Repository Structure

```
secid/
├── SPEC.md                  # Full technical specification
├── REGISTRY-GUIDE.md        # Principles and patterns for registry contributions
├── REGISTRY-JSON-FORMAT.md  # Target JSON schema specification (v1.0+)
├── REGISTRY-FORMAT.md       # Current YAML+Markdown format (what's in use now)
├── registry/                # Namespace definitions (one file per namespace)
│   ├── <type>.md            # Type description (e.g., advisory.md)
│   ├── <type>/_template.md  # Template for new namespace files
│   ├── <type>/<tld>/<domain>.md  # Namespace file (reverse-DNS, e.g., org/mitre.md)
│   └── _deferred/           # Partially researched entries not ready for main registry
└── seed/                    # Bulk import data (CSV) for seeding
```

## Registry File Format

**Current state: All registry files are YAML frontmatter + Markdown.** The JSON format in REGISTRY-JSON-FORMAT.md is the target for v1.0+, not yet in use.

One file per namespace containing all sources from that organization. Use `registry/advisory/_template.md` as a starting point for new files.

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
secid:control/cloudsecurityalliance.org/ccm@4.0           → Whole framework
secid:control/cloudsecurityalliance.org/ccm@4.0#IAM       → Domain (group of controls)
secid:control/cloudsecurityalliance.org/ccm@4.0#IAM-12    → Specific control
```

Document each level with its own `id_pattern` and description.

## Namespace-to-Filesystem Algorithm

Given a namespace like `github.com/advisories` and type `advisory`:

1. Split namespace at first `/` → domain `github.com`, path `advisories`
2. Split domain on `.` → `github`, `com`
3. Reverse → `com/github`
4. Append path portion → `com/github/advisories`
5. Append `.md` → `com/github/advisories.md`
6. Prepend `registry/<type>/` → `registry/advisory/com/github/advisories.md`

Simple cases: `mitre.org` → `registry/<type>/org/mitre.md`, `nist.gov` → `registry/<type>/gov/nist.md`

## Adding New Namespaces

1. Determine type (advisory, weakness, ttp, control, regulation, entity, reference)
2. Compute the filesystem path using the algorithm above
3. Check if the file already exists — if so, add a source section to it
4. If new, copy from `registry/advisory/_template.md` and fill in fields
5. Include: urls, id_patterns (with descriptions), examples
6. Use `registry/_deferred/` for incomplete research

See [REGISTRY-GUIDE.md](REGISTRY-GUIDE.md) for detailed patterns.

## Entity Type Differences

Entity files describe organizations, not data sources. They use a `names` block instead of `sources` to document products/projects:

```yaml
# registry/entity/org/mitre.md uses names: { cve: {...}, attack: {...} }
# vs registry/advisory/org/mitre.md uses sources: { cve: {...} }
```

See REGISTRY-JSON-FORMAT.md "Entity Type Differences" section for the full schema.

## Development Commands

```bash
# Check registry files have required metadata
rg -n '^type:' registry/**/*.md

# List all namespaces and their types
rg -n '^namespace:' registry/**/*.md

# Find all files for a specific namespace (e.g., mitre.org appears in multiple types)
rg -l 'namespace: mitre.org' registry/

# Count registry files per type
for type in advisory weakness ttp control regulation entity reference; do echo "$type: $(find registry/$type -name '*.md' -not -name '_*' 2>/dev/null | wc -l)"; done

# Lint markdown (if markdownlint is installed)
markdownlint **/*.md
```

This is a **specification-only repository** — no build system, no tests, no compiled code. Validation is manual review + grep/ripgrep over YAML frontmatter.

## Parsing Rules

**SecID parsing requires registry access.** The registry defines what's valid - no banned character list to memorize.

**Namespaces are domain names**, optionally with `/`-separated path segments for platform sub-namespaces.

| Component | Character Rules |
|-----------|-----------------|
| `type` | Fixed list of 7 values |
| `namespace` | Domain name, optionally with `/`-separated sub-namespace path segments. Per-segment: `a-z`, `0-9`, `-`, `.`, Unicode `\p{L}\p{N}`. |
| `name` | **Anything** - resolved by registry lookup, longest match wins |
| `subpath` | Anything (everything after `#`). May include `@item_version` suffix — parsed via `id_patterns`. |

**Per-segment validation regex:** `^[\p{L}\p{N}]([\p{L}\p{N}._-]*[\p{L}\p{N}])?$` (applies to each segment between `/`)

**Namespace resolution: shortest-to-longest matching.** Since namespaces can contain `/`, the parser tries shortest namespace first against the registry, then progressively longer matches. Example: for `github.com/advisories/ghsa`, try `github.com` then `github.com/advisories` — longest match wins.

**Why domain-name namespaces?**
- **Self-registration (future)** - Domain owners will prove ownership via DNS/ACME; currently manual via pull requests
- **No naming authority** - DNS already provides globally unique names
- **Filesystem safety** - Namespaces become file paths (`registry/advisory/org/mitre.md`)
- **Unicode for internationalization** - Native language domain names supported

**Why registry-required?** Names can contain `#`, `@`, `?`, `:` - the registry lookup determines where name ends.

**Version resolution:** Sources with `version_required: true` behave differently when `@version` is omitted — the resolver returns all matching versions with disambiguation guidance instead of a single result. See REGISTRY-JSON-FORMAT.md "Version Resolution Fields".

## Preserve Source Identifiers

**Subpaths preserve the source's exact format - including special characters.**

| Source Format | SecID | NOT This |
|---------------|-------|----------|
| `RHSA-2026:0932` (colon) | `#RHSA-2026:0932` ✓ | `#RHSA-2026-0932` ✗ |
| `T1059.003` (dot) | `#T1059.003` ✓ | `#T1059-003` ✗ |
| `PR.AC-1` (dot+dash) | `#PR.AC-1` ✓ | Unchanged |

**Why:** Human recognition, copy-paste workflow, no information loss. What practitioners know is what SecID uses.

## Encoding Rules

**In the SecID string:** No encoding needed. Write identifiers naturally: `RHSA-2024:1234`, `A&A-01`.

**For storage/transport (filenames, URLs):** Percent-encode special characters:
- `&` → `%26`, Space → `%20`, `:` → `%3A`, `/` → `%2F`, `#` → `%23`

**Flexible input resolution:** Resolvers try input as-is first, then percent-decoded. Registry patterns match human-readable (unencoded) form. Backend storage format is an implementation choice. Do NOT strip quotes or other characters from input - the registry determines what matches.

## Writing Principle

Explain **why**, not just what. "SecID uses `#subpath` because security knowledge is databases of identifiers, not packages with files" is better than just "SecID uses `#subpath` for specific items."
