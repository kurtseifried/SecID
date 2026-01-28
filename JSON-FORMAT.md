# JSON Format Specification

This document defines the JSON format for SecID registry files. The registry currently uses YAML+Markdown (see REGISTRY-FORMAT.md) for flexibility during exploration. This document specifies the target JSON format for v1.0+.

## Scope: Labeling and Finding

**SecID is about labeling and finding things. That's it.**

The registry contains:
- **Identity** - What is this thing called?
- **Resolution** - How do I find/access it?
- **Disambiguation** - How do I tell similar things apart?

The registry does NOT contain:
- **Enrichment** - Metadata about the thing (authors, categories, relationships)
- **Judgments** - Quality assessments, trust scores, recommendations
- **Relationships** - How things connect to each other

Enrichment and relationships belong in separate data layers that reference SecIDs.

## Design Principles

### AI-First Data Modeling

Traditional data formats optimized for software that needed deterministic, single values. SecID takes an AI-first approach:

- **Provide options with context** rather than forcing single "canonical" choices
- **Let AI reason** about which option fits the current need
- **Include metadata** that aids decision-making

Example: Instead of one lookup URL, provide multiple with context about when each is appropriate.

### Pattern Selection

Use the right pattern for the data:

| Situation | Pattern | Example |
|-----------|---------|---------|
| Fixed, small set of categories | Named fields | `official_name`, `common_name`, `alternate_names` |
| Open-ended, numerous categories | Arrays with type/context | `urls`, `id_patterns` |
| Identity/classification | Singular values | `namespace`, `type`, `status` |

**Why?** Named fields are self-documenting. An AI reads `official_name` and immediately knows what it is. Arrays with type require understanding a schema to interpret.

### Null vs Absent Convention

Distinguish between "no data exists" and "not yet researched":

| State | Representation | Meaning |
|-------|----------------|---------|
| Has data | `"field": "value"` | We have the information |
| No data exists | `"field": null` | We looked, nothing to find |
| Not researched | field absent | We haven't looked yet |

For arrays:
- `[]` (empty array) = we looked, there are none
- `null` = we looked, not applicable to this source
- absent = not yet researched

**Why?** This lets us track completeness. An absent field signals work to be done. A `null` signals confirmed absence.

## Schema Structure

### Top-Level Fields

```json
{
  "schema_version": "1.0",
  "namespace": "mitre",
  "type": "advisory",
  "status": "published",

  "official_name": "MITRE Corporation",
  "common_name": "MITRE",
  "alternate_names": ["MITRE Corp"],

  "urls": [
    {"type": "website", "url": "https://www.mitre.org"}
  ],

  "sources": {
    "cve": { ... }
  }
}
```

#### Identity Fields (singular, required)

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | JSON schema version for this file |
| `namespace` | string | Organization identifier (used in SecIDs) |
| `type` | string | SecID type: advisory, weakness, ttp, control, regulation, entity, reference |
| `status` | string | Registry entry status (see below) |
| `status_notes` | string \| null | Optional context about status (blockers, gaps, guidance for contributors) |

#### Status Values

Registry entry status reflects documentation completeness and review state:

| Status | Meaning | Field Requirements |
|--------|---------|-------------------|
| `proposed` | Suggested, minimal info | namespace, type, status, official_name required |
| `draft` | Being worked on | Any fields, actively researching |
| `pending` | Awaiting review | All fields present (value, `null`, or `[]`) - nothing absent |
| `published` | Reviewed and approved | Same as pending, but reviewed |

**Key principle:** `published` doesn't mean "complete" - it means "reviewed." Empty arrays and `null` values are valid and valuable - they show we looked and couldn't find anything, which exposes gaps and invites contribution.

**Examples:**
```json
"status": "published",
"status_notes": "Vendor has no public security page - urls intentionally empty"
```

```json
"status": "draft",
"status_notes": "Waiting for vendor response about official URL"
```

#### Disambiguation Fields (optional)

| Field | Type | Description |
|-------|------|-------------|
| `wikidata` | string[] | Wikidata Q-numbers for entity disambiguation (e.g., ["Q1116236"]) |
| `wikipedia` | string[] | Wikipedia article URLs for direct access |

**Why arrays?** Entities can map to multiple Wikidata entries (mergers, name changes, historical entries) or have multiple relevant Wikipedia articles (different languages, related topics). Arrays handle 0, 1, or more consistently.

**Why both fields?**
- `wikidata` - Stable, language-neutral identifiers. Links to all Wikipedia versions. Preferred for disambiguation.
- `wikipedia` - Direct access to human-readable context. Convenience for AI/humans without extra lookup. Fallback when no Wikidata exists.

#### Name Fields (singular/array)

| Field | Type | Description |
|-------|------|-------------|
| `official_name` | string | Official/legal name of the organization |
| `common_name` | string \| null | Common short name (e.g., "MITRE", "NIST") |
| `alternate_names` | string[] \| null | Other names for search/matching |

**Why separate fields?** Fixed, small set of name categories. Named fields are self-documenting and easier for AI to generate correctly.

#### URLs (top-level)

Top-level `urls[]` array for the namespace/organization. Same structure as source-level URLs:

```json
"urls": [
  {"type": "website", "url": "https://www.mitre.org"},
  {"type": "website", "url": "https://www.cve.org", "note": "CVE Program site"}
]
```

See source-level URLs section for full field definitions.

### Sources Block

The `sources` block contains one or more data sources published by this namespace:

```json
"sources": {
  "cve": {
    "official_name": "Common Vulnerabilities and Exposures",
    "common_name": "CVE",
    "alternate_names": null,

    "urls": [ ... ],
    "id_patterns": [ ... ],
    "version_patterns": [ ... ],
    "examples": [ ... ]
  }
}
```

The source key (e.g., `cve`) becomes the `name` component in SecIDs: `secid:advisory/mitre/cve#CVE-2024-1234`

#### Source Name Fields

Same pattern as top-level: `official_name`, `common_name`, `alternate_names`.

#### URLs (array with context)

```json
"urls": [
  {"type": "website", "url": "https://cve.org"},
  {"type": "lookup", "url": "https://cve.org/CVERecord?id={id}", "note": "Human-readable page"},
  {"type": "lookup", "url": "https://cveawg.mitre.org/api/cve/{id}", "format": "json", "note": "API, richer data"},
  {"type": "bulk_data", "url": "https://github.com/CVEProject/cvelistV5", "format": "json"},
  {"type": "api", "url": "https://cveawg.mitre.org/api"}
]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | yes | URL category (see below) |
| `url` | string | yes | The URL, may contain `{placeholder}` templates |
| `format` | string | no | Response format: json, html, xml, csv, pdf |
| `note` | string | no | Context for AI: when/why to use, access instructions, auth requirements, download hints |

**Common URL types:**
- `website` - Main website for humans
- `lookup` - Resolution URL with `{id}` placeholder
- `api` - API endpoint
- `bulk_data` - Bulk download location
- `github` - GitHub repository
- `paper` - Academic paper
- `docs` - Documentation

**Why an array?** 70+ URL types exist. Multiple URLs of the same type are common (e.g., primary and fallback lookup endpoints). Context helps AI choose appropriately.

#### URL Template Placeholders

URLs may contain placeholders for dynamic resolution:

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{id}` | Full identifier from subpath | `CVE-2024-1234` |
| `{num}` | Numeric portion of identifier | `1234` |
| `{year}` | Year component of identifier | `2024` |
| `{version}` | Version from `@version` component | `4.0` |

#### ID Patterns (array with context)

```json
"id_patterns": [
  {"pattern": "CVE-\\d{4}-\\d{4,}", "description": "Standard CVE ID format"}
]
```

For sources with multiple ID types:

```json
"id_patterns": [
  {"pattern": "T\\d{4}(\\.\\d{3})?", "type": "technique", "description": "ATT&CK technique"},
  {"pattern": "TA\\d{4}", "type": "tactic", "description": "ATT&CK tactic"},
  {"pattern": "M\\d{4}", "type": "mitigation", "description": "ATT&CK mitigation"},
  {"pattern": "G\\d{4}", "type": "group", "description": "Threat group"}
]
```

For sources where different ID patterns need different lookup URLs:

```json
"id_patterns": [
  {"pattern": "ALAS-\\d{4}-\\d+", "type": "al1", "description": "Amazon Linux 1", "url": "https://alas.aws.amazon.com/{id}.html"},
  {"pattern": "ALAS2-\\d{4}-\\d+", "type": "al2", "description": "Amazon Linux 2", "url": "https://alas.aws.amazon.com/AL2/{id}.html"},
  {"pattern": "ALAS2023-\\d{4}-\\d+", "type": "al2023", "description": "Amazon Linux 2023", "url": "https://alas.aws.amazon.com/AL2023/{id}.html"}
]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | yes | PCRE2-compatible regular expression |
| `type` | string | no | Category when source has multiple ID types |
| `description` | string | no | Human/AI-readable description |
| `ecosystem` | string | no | For ecosystem-specific patterns (e.g., PyPI, Go) |
| `url` | string | no | Pattern-specific lookup URL (overrides default lookup URL) |

**Why always an array?** Consistency. Even single-pattern sources use an array with one item. Avoids having both `id_pattern` (string) and `id_patterns` (array).

**Why `url` in patterns?** Some sources have multiple ID formats that resolve to different URLs. Rather than a separate `id_routing` concept, patterns can include their own lookup URL when needed.

**Note:** These are **format patterns**, not validity checks. A pattern like `CVE-\d{4}-\d{4,}` tells you "this looks like a CVE ID" - whether that specific CVE actually exists is only known when you try to resolve it.

#### Version Patterns (array, optional)

For sources where different versions have different URL structures, use `version_patterns` to route based on the `@version` component:

```json
"version_patterns": [
  {
    "pattern": "4\\..*",
    "description": "Version 4.x",
    "url": "https://example.com/v4/resource/{id}"
  },
  {
    "pattern": "3\\..*",
    "description": "Version 3.x and earlier",
    "url": "https://example.com/legacy/v{version}/{id}"
  }
]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | yes | PCRE2-compatible regex to match version string |
| `description` | string | no | Human/AI-readable description |
| `url` | string | yes | URL template for this version range |

**Resolution example:** `secid:control/csa/ccm@4.0.1#IAM-12`
1. Extract version = `4.0.1`, id = `IAM-12`
2. Match version against patterns → `4\..*` matches
3. Use that pattern's URL template with `{version}` and `{id}` substitution

**When not needed:** Most sources don't need `version_patterns`. Use when:
- Different major versions have incompatible URL structures
- Legacy versions are hosted on different infrastructure

If URLs are predictable (just substitute `{version}`), use the placeholder in the main `urls[]` instead.

#### Examples

```json
"examples": ["CVE-2024-1234", "CVE-2021-44228", "CVE-2023-44487"]
```

Simple string array showing valid ID formats. Helps humans and AI understand what identifiers look like.

## Reference Type Fields

For `type: reference` (documents, papers, standards), additional identifier fields help with finding and disambiguation:

```json
{
  "type": "reference",
  "namespace": "nist",

  "title": "AI RMF",
  "full_title": "Artificial Intelligence Risk Management Framework",

  "doi": "10.6028/NIST.AI.100-1",
  "isbn": null,
  "issn": null,
  "asin": null,

  "sources": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Short/common title |
| `full_title` | string \| null | Complete formal title |
| `doi` | string \| null | Digital Object Identifier |
| `isbn` | string \| null | Book ISBN |
| `issn` | string \| null | Journal/series ISSN |
| `asin` | string \| null | Amazon Standard Identification Number |

**Why these fields?** They are identifiers that help find the document. Metadata like authors, publication date, and category belong in an enrichment layer, not the registry.

**Note:** For references accessed via specific systems (arXiv, RFC), the identifier is typically part of the SecID itself (e.g., `secid:reference/arxiv/2303.08774` or `secid:reference/ietf/rfc9110`).

## Entity Type Differences

Entity files describe organizations rather than data sources. They use a `names` block instead of `sources` to document products/projects the entity is known for:

```json
{
  "namespace": "mitre",
  "type": "entity",
  "official_name": "The MITRE Corporation",
  "common_name": "MITRE",
  "wikidata": ["Q1116236"],
  "wikipedia": ["https://en.wikipedia.org/wiki/Mitre_Corporation"],

  "urls": [
    {"type": "website", "url": "https://www.mitre.org"}
  ],

  "names": {
    "cve": {
      "official_name": "Common Vulnerabilities and Exposures",
      "common_name": "CVE",
      "urls": [ ... ]
    },
    "attack": {
      "official_name": "MITRE ATT&CK",
      "common_name": "ATT&CK",
      "urls": [ ... ]
    }
  }
}
```

The `names` block helps with disambiguation and finding - "What does MITRE publish?" These are labels and access points, not relationship data. Cross-references between entities and their publications belong in an enrichment layer.

## Complete Example

```json
{
  "schema_version": "1.0",
  "namespace": "mitre",
  "type": "advisory",
  "status": "published",
  "status_notes": null,

  "official_name": "MITRE Corporation",
  "common_name": "MITRE",
  "alternate_names": ["The MITRE Corporation"],
  "wikidata": ["Q1116236"],
  "wikipedia": ["https://en.wikipedia.org/wiki/Mitre_Corporation"],

  "urls": [
    {"type": "website", "url": "https://www.mitre.org"}
  ],

  "sources": {
    "cve": {
      "official_name": "Common Vulnerabilities and Exposures",
      "common_name": "CVE",
      "alternate_names": null,

      "urls": [
        {"type": "website", "url": "https://cve.org"},
        {"type": "lookup", "url": "https://cve.org/CVERecord?id={id}", "note": "Human-readable"},
        {"type": "lookup", "url": "https://cveawg.mitre.org/api/cve/{id}", "format": "json", "note": "JSON API"},
        {"type": "bulk_data", "url": "https://github.com/CVEProject/cvelistV5"},
        {"type": "api", "url": "https://cveawg.mitre.org/api"}
      ],

      "id_patterns": [
        {"pattern": "CVE-\\d{4}-\\d{4,}", "description": "Standard CVE ID format"}
      ],

      "examples": ["CVE-2024-1234", "CVE-2021-44228", "CVE-2023-44487"]
    }
  }
}
```

## Migration from YAML+Markdown

The current YAML frontmatter maps to JSON as follows:

| YAML Field | JSON Field | Notes |
|------------|------------|-------|
| `full_name` | `official_name` | Renamed for clarity |
| `website` | `urls[] where type=website` | Now array with context |
| `id_pattern` | `id_patterns[].pattern` | Now always array |
| `id_routing` | `id_patterns[].url` | Merged into id_patterns |
| `urls.lookup` | `urls[] where type=lookup` | Now array with context |
| `wikidata` | `wikidata[]` | Now array |
| `wikipedia` | `wikipedia[]` | New field, array |
| `status` | `status` | New values: proposed, draft, pending, published |
| `status_notes` | `status_notes` | New field |

### Fields Moved to Data Layer

The following fields were considered but belong in the enrichment/relationship data layer, not the registry:

| Field | Reason |
|-------|--------|
| `operator` | Relationship (who operates what) |
| `superseded_by` | Relationship + judgment (X replaced Y) |
| `deprecated_by` | Relationship (source X replaced by Y) |
| `deprecated_date` | Temporal enrichment |
| `established` | Temporal enrichment |
| `versions[]` | Replaced by `version_patterns[]` for resolution; version catalog is enrichment |

The registry focuses on identity, resolution, and disambiguation. Relationships and lifecycle metadata belong in separate data layers that reference SecIDs.

The Markdown body content (narrative documentation) will be handled separately - either as a companion `.md` file or a `description` field. Decision pending.

## Schema Versioning

The `schema_version` field allows for future evolution. Parsers should check this field and handle unknown versions gracefully.

Current version: `1.0` (draft)
