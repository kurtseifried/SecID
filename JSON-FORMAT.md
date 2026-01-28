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
  "status": "active",

  "official_name": "MITRE Corporation",
  "common_name": "MITRE",
  "alternate_names": ["MITRE Corp"],

  "urls": [
    {"type": "website", "url": "https://www.mitre.org"}
  ],

  "operators": [
    {"ref": "secid:entity/mitre", "role": "operator"}
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
| `status` | string | Registry entry status: active, draft, deprecated, historical |

#### Disambiguation Fields (optional)

| Field | Type | Description |
|-------|------|-------------|
| `wikidata` | string[] | Wikidata Q-numbers for entity disambiguation (e.g., ["Q1116236"]) |
| `wikipedia` | string[] | Wikipedia article URLs for direct access |

**Why arrays?** Entities can map to multiple Wikidata entries (mergers, name changes, historical entries) or have multiple relevant Wikipedia articles (different languages, related topics). Arrays handle 0, 1, or more consistently.

**Why both fields?**
- `wikidata` - Stable, language-neutral identifiers. Links to all Wikipedia versions. Preferred for disambiguation.
- `wikipedia` - Direct access to human-readable context. Convenience for AI/humans without extra lookup. Fallback when no Wikidata exists.

#### Lifecycle Fields (optional)

| Field | Type | Description |
|-------|------|-------------|
| `superseded_by` | string \| null | SecID of replacement when status=superseded |

When a namespace is superseded (e.g., an organization merges or renames), this field points to where to look instead.

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

#### Operators (array with context)

```json
"operators": [
  {"ref": "secid:entity/mitre", "role": "operator"},
  {"ref": "secid:entity/cisa", "role": "sponsor"}
]
```

| Field | Type | Description |
|-------|------|-------------|
| `ref` | string | SecID reference to the operating entity |
| `role` | string | Role: operator, sponsor, maintainer, contributor |

**Why an array?** Joint operations exist (e.g., Azure Red Hat OpenShift). Context about roles helps AI understand relationships.

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
    "examples": [ ... ],
    "versions": [ ... ]
  }
}
```

The source key (e.g., `cve`) becomes the `name` component in SecIDs: `secid:advisory/mitre/cve#CVE-2024-1234`

#### Source Name Fields

Same pattern as top-level: `official_name`, `common_name`, `alternate_names`.

#### Source Lifecycle Fields

| Field | Type | Description |
|-------|------|-------------|
| `deprecated_by` | string \| null | What replaces this source |
| `deprecated_date` | string \| null | ISO date when deprecated (YYYY-MM-DD) |

Sources within a namespace can be deprecated independently (e.g., an old API version).

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
| `{id}` | Full identifier | `CVE-2024-1234` |
| `{num}` | Numeric portion | `1234` |
| `{year}` | Year component | `2024` |

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

#### Examples and Versions

```json
"examples": ["CVE-2024-1234", "CVE-2021-44228", "CVE-2023-44487"],
"versions": ["5.1", "5.0", "4.0"]
```

Simple string arrays. Examples show valid ID formats. Versions list known versions (newest first).

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
  "status": "active",
  "superseded_by": null,

  "official_name": "MITRE Corporation",
  "common_name": "MITRE",
  "alternate_names": ["The MITRE Corporation"],
  "wikidata": ["Q1116236"],
  "wikipedia": ["https://en.wikipedia.org/wiki/Mitre_Corporation"],

  "urls": [
    {"type": "website", "url": "https://www.mitre.org"}
  ],

  "operators": [
    {"ref": "secid:entity/mitre", "role": "operator"},
    {"ref": "secid:entity/cisa", "role": "sponsor"}
  ],

  "sources": {
    "cve": {
      "official_name": "Common Vulnerabilities and Exposures",
      "common_name": "CVE",
      "alternate_names": null,
      "deprecated_by": null,
      "deprecated_date": null,

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

      "examples": ["CVE-2024-1234", "CVE-2021-44228", "CVE-2023-44487"],

      "versions": ["5.1", "5.0", "4.0"]
    }
  }
}
```

## Migration from YAML+Markdown

The current YAML frontmatter maps to JSON as follows:

| YAML Field | JSON Field | Notes |
|------------|------------|-------|
| `full_name` | `official_name` | Renamed for clarity |
| `operator` | `operators[].ref` | Now array with roles |
| `website` | `urls[] where type=website` | Now array with context |
| `id_pattern` | `id_patterns[].pattern` | Now always array |
| `id_routing` | `id_patterns[].url` | Merged into id_patterns |
| `urls.lookup` | `urls[] where type=lookup` | Now array with context |
| `wikidata` | `wikidata[]` | Now array |
| `wikipedia` | `wikipedia[]` | New field, array |
| `superseded_by` | `superseded_by` | Unchanged |
| `established` | (removed) | Enrichment layer, not registry |

The Markdown body content (narrative documentation) will be handled separately - either as a companion `.md` file or a `description` field. Decision pending.

## Schema Versioning

The `schema_version` field allows for future evolution. Parsers should check this field and handle unknown versions gracefully.

Current version: `1.0` (draft)
