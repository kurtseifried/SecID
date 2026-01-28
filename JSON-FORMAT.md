# JSON Format Specification

This document defines the JSON format for SecID registry files. The registry currently uses YAML+Markdown (see REGISTRY-FORMAT.md) for flexibility during exploration. This document specifies the target JSON format for v1.0+.

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

  "website": "https://www.mitre.org",

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

#### Name Fields (singular/array)

| Field | Type | Description |
|-------|------|-------------|
| `official_name` | string | Official/legal name of the organization |
| `common_name` | string \| null | Common short name (e.g., "MITRE", "NIST") |
| `alternate_names` | string[] \| null | Other names for search/matching |

**Why separate fields?** Fixed, small set of name categories. Named fields are self-documenting and easier for AI to generate correctly.

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
| `note` | string | no | Context for AI about when/why to use this URL |

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

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | yes | PCRE2-compatible regular expression |
| `type` | string | no | Category when source has multiple ID types |
| `description` | string | no | Human/AI-readable description |
| `ecosystem` | string | no | For ecosystem-specific patterns (e.g., PyPI, Go) |

**Why always an array?** Consistency. Even single-pattern sources use an array with one item. Avoids having both `id_pattern` (string) and `id_patterns` (array).

#### Examples and Versions

```json
"examples": ["CVE-2024-1234", "CVE-2021-44228", "CVE-2023-44487"],
"versions": ["5.1", "5.0", "4.0"]
```

Simple string arrays. Examples show valid ID formats. Versions list known versions (newest first).

## Entity Type Differences

Entity files describe organizations rather than data sources. They use a `names` block instead of `sources`:

```json
{
  "namespace": "mitre",
  "type": "entity",
  "official_name": "The MITRE Corporation",
  "common_name": "MITRE",

  "names": {
    "cve": {
      "official_name": "Common Vulnerabilities and Exposures",
      "description": "Canonical vulnerability identifier system",
      "issues_type": "advisory",
      "issues_namespace": "mitre",
      "urls": [ ... ]
    },
    "attack": {
      "official_name": "MITRE ATT&CK",
      "description": "Adversary tactics and techniques knowledge base",
      "issues_type": "ttp",
      "issues_namespace": "mitre",
      "urls": [ ... ]
    }
  }
}
```

The `names` block documents what the entity publishes, with cross-references to where those publications live in the SecID namespace.

## Complete Example

```json
{
  "schema_version": "1.0",
  "namespace": "mitre",
  "type": "advisory",
  "status": "active",

  "official_name": "MITRE Corporation",
  "common_name": "MITRE",
  "alternate_names": ["The MITRE Corporation"],

  "website": "https://www.mitre.org",

  "operators": [
    {"ref": "secid:entity/mitre", "role": "operator"},
    {"ref": "secid:entity/cisa", "role": "sponsor"}
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
| `id_pattern` | `id_patterns[].pattern` | Now always array |
| `urls.lookup` | `urls[] where type=lookup` | Now array with context |

The Markdown body content (narrative documentation) will be handled separately - either as a companion `.md` file or a `description` field. Decision pending.

## Schema Versioning

The `schema_version` field allows for future evolution. Parsers should check this field and handle unknown versions gracefully.

Current version: `1.0` (draft)
