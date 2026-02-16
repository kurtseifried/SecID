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

## Resolution Pipeline

This section explains how a SecID string is resolved to URLs using registry data.

**Important:** SecID parsing requires registry access. The registry defines what types, namespaces, and names are valid. This eliminates the need for a complex "banned characters" list - if it's not in the registry, it's not valid.

### Step 1: Parse the SecID String (Registry-Aware)

Parsing uses the registry to identify components:

```
secid:advisory/github.com/advisories/ghsa#GHSA-1234-5678-abcd
      ───┬─── ──────────┬──────────── ─┬── ─────────┬─────────
         │              │              │            └─ subpath
         │              │              └─ name (registry lookup, longest match)
         │              └─ namespace (domain, optionally with /path segments)
         └─ type (known list)
```

| Step | Component | How to Parse |
|------|-----------|--------------|
| 1 | scheme | Literal `secid:` |
| 2 | type | Match against 7 known values |
| 3 | namespace | **Shortest-to-longest matching** against registry. Namespaces can contain `/` (e.g., `github.com/advisories`). See SPEC.md Section 4.3. |
| 4 | name | Longest match against sources in `registry[type][namespace]` |
| 5 | version | After name, parse `@...` until `?` or `#` |
| 6 | qualifiers | Parse `?...` until `#` |
| 7 | subpath | Everything after the `#` following version/qualifiers |

**Why registry-aware?** Names can contain any characters (including `#`, `@`, `?`, `:`). The registry defines what names exist, and longest-match resolves ambiguity.

**Shortest-to-longest namespace resolution:** Since namespaces can contain `/`, the parser tries shortest namespace first against the registry, then progressively longer matches. See SPEC.md Section 4.3 for details.

```
Input: secid:advisory/github.com/advisories/ghsa#GHSA-xxxx

After extracting type "advisory", remaining path: github.com/advisories/ghsa#GHSA-xxxx

Try namespace matches (shortest first):
  1. "github.com"              → exists in registry? Yes → candidate
  2. "github.com/advisories"   → exists in registry? Yes → longer candidate
  3. "github.com/advisories/ghsa" → exists? No → stop

Longest matching namespace: "github.com/advisories"
Remaining: "ghsa#GHSA-xxxx" → name="ghsa", subpath="GHSA-xxxx"
```

**Example with special characters:**
```
secid:advisory/vendor.com/weird#name:here#ID-2024
```
If registry has source `weird#name:here` in `advisory/vendor`, then:
- name = `weird#name:here`
- subpath = `ID-2024`

### Step 2: Lookup the Source

Using type, namespace, and name, find the source definition:

```
registry[type][namespace][name] → registry["advisory"]["mitre.org"]["cve"]
```

**Filesystem mapping:** The abstract `registry[type][namespace]` maps to a filesystem path via the reverse-DNS algorithm (see SPEC.md Section 4.0):

| Lookup | Filesystem Path |
|--------|----------------|
| `registry["advisory"]["mitre.org"]` | `registry/advisory/org/mitre.json` |
| `registry["advisory"]["github.com/advisories"]` | `registry/advisory/com/github/advisories.json` |
| `registry["control"]["cloudsecurityalliance.org"]` | `registry/control/org/cloudsecurityalliance.json` |

### Step 3: Match Patterns Against Subpath

The subpath is tested against each `id_patterns[].pattern`. Patterns should be anchored (`^...$`) to match the complete subpath:

```json
"id_patterns": [
  {"pattern": "^CVE-\\d{4}-\\d{4,}$", "description": "Standard CVE ID format"}
]
```

**Important:** Patterns match the **complete subpath**, not a substring. This means:
- `secid:advisory/mitre.org/cve#CVE-2024-1234` → subpath `CVE-2024-1234` → matches
- `secid:advisory/mitre.org/cve#CVE-2024-1234/extra` → subpath `CVE-2024-1234/extra` → **no match**

Invalid subpaths simply don't match any pattern. This is intentional - CVE IDs don't have path suffixes, so such a SecID would be malformed.

### Step 4: Extract Variables (if needed)

For simple cases, the subpath is used directly as `{id}` in the URL template:

```json
{"type": "lookup", "url": "https://cve.org/CVERecord?id={id}"}
```

For complex URL structures where parts of the ID need transformation, patterns can specify a `variables` object:

```json
{
  "pattern": "^CWE-\\d+$",
  "url": "https://cwe.mitre.org/data/definitions/{number}.html",
  "variables": {
    "number": {
      "extract": "^CWE-(\\d+)$",
      "description": "Numeric ID portion (e.g., '79' from 'CWE-79')"
    }
  }
}
```

Each variable has:
- `extract` - Regex applied to the subpath. Capture groups `()` are numbered `{1}`, `{2}`, etc.
- `format` - (Optional) How to combine capture groups. Defaults to `{1}` (first group). Can include literals.
- `description` - Explains what this variable represents and how it's derived.

### Step 5: Build URL

Substitute variables into the URL template:

| Placeholder | Source | Example |
|-------------|--------|---------|
| `{id}` | Full subpath | `CVE-2024-1234` |
| `{version}` | From `@version` component | `4.0` |
| `{year}` | Extracted from subpath (if in variables) | `2024` |
| `{number}` | Extracted from subpath (if in variables) | `1234` |

**Result:** `https://cve.org/CVERecord?id=CVE-2024-1234`

### Variable Extraction Example

For CWE, the lookup URL needs just the number, not the full ID:

```json
{
  "pattern": "^CWE-\\d+$",
  "description": "CWE weakness ID",
  "url": "https://cwe.mitre.org/data/definitions/{number}.html",
  "variables": {
    "number": {
      "extract": "^CWE-(\\d+)$",
      "description": "Numeric ID portion (e.g., '79' from 'CWE-79')"
    }
  }
}
```

Resolution of `secid:weakness/mitre.org/cwe#CWE-79`:
1. Subpath: `CWE-79`
2. Pattern matches: `^CWE-\d+$` ✓
3. Extract variables: apply `number.extract` regex → first capture group `(\d+)` captures `79`
4. Build URL: `https://cwe.mitre.org/data/definitions/79.html`

### More Complex Variable Extraction

For the CVE GitHub repository, files are organized by year and a "bucket" (all but last 3 digits + `xxx`):

```json
{
  "pattern": "^CVE-\\d{4}-\\d{4,}$",
  "description": "CVE JSON record on GitHub",
  "url": "https://github.com/CVEProject/cvelistV5/blob/main/cves/{year}/{bucket}/{id}.json",
  "variables": {
    "year": {
      "extract": "^CVE-(\\d{4})-\\d+$",
      "description": "4-digit year (e.g., '2026' from 'CVE-2026-25010')"
    },
    "bucket": {
      "extract": "^CVE-\\d{4}-(\\d+)\\d{3}$",
      "format": "{1}xxx",
      "description": "All but last 3 digits + 'xxx' (e.g., '25xxx' from 'CVE-2026-25010')"
    },
    "id": {
      "extract": "^(CVE-\\d{4}-\\d+)$",
      "description": "Full CVE ID"
    }
  }
}
```

Resolution of `secid:advisory/mitre.org/cve#CVE-2026-25010`:
1. Subpath: `CVE-2026-25010`
2. Pattern matches ✓
3. Extract variables:
   - `year`: extract `(2026)` → `2026`
   - `bucket`: extract `(25)` from before last 3 digits, format `{1}xxx` → `25xxx`
   - `id`: extract `(CVE-2026-25010)` → `CVE-2026-25010`
4. Build URL: `https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/25xxx/CVE-2026-25010.json`

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
  "namespace": "mitre.org",
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
| `namespace` | string | Organization identifier — domain name (used in SecIDs). See namespace validation below. |
| `type` | string | SecID type: advisory, weakness, ttp, control, regulation, entity, reference |
| `status` | string | Registry entry status (see below) |
| `status_notes` | string \| null | Optional context about status (blockers, gaps, guidance for contributors) |
| `alias_of` | string \| null | If present, this is an alias stub — namespace redirects to the value. No sources needed. |

#### Namespace Validation

Namespaces must be safe for filesystems, shells, and URLs while supporting international names.

**Allowed characters:**
- `a-z` (lowercase ASCII letters)
- `0-9` (ASCII digits)
- `-` (hyphen, not at start/end of DNS labels)
- `.` (period, as DNS label separator)
- Unicode letters (`\p{L}`) and numbers (`\p{N}`)

**Validation regex:** `^[\p{L}\p{N}]([\p{L}\p{N}._-]*[\p{L}\p{N}])?$`

**Not allowed within a segment:** Spaces, punctuation (except `-` and `.`), shell metacharacters.

**Per-segment validation:** Namespaces are domain names, optionally with `/`-separated path segments for platform sub-namespaces (e.g., `github.com/advisories`). `/` separates segments but is not allowed *within* a segment. Each segment between `/` must match the regex above.

**Examples:**
```
mitre.org                ✓  Domain name
nist.gov                 ✓  Government domain
github.com/advisories    ✓  Platform sub-namespace
aws.amazon.com           ✓  Subdomain
字节跳动.com              ✓  Unicode domain (ByteDance)
red_hat.com              ✗  Underscore not allowed in segment
```

**Alias stubs:** When `alias_of` is present, the entry is a redirect. Resolvers follow it to the target namespace. Used for Punycode/Unicode IDN equivalence (e.g., `xn--mnchen-3ya.de` → `münchen.de`). See [EDGE-CASES.md](EDGE-CASES.md) for details.

**Why these rules:**

1. **Filesystem safety** - Namespace segments become file paths (`registry/advisory/org/mitre.json`). Sub-namespaces become directories (`registry/advisory/com/github/advisories.json`). Avoiding shell metacharacters ensures repos work in Git across all platforms.

2. **Domain names are globally unique** - DNS already provides authoritative, collision-free identifiers. No centralized namespace assignment needed.

3. **Unicode for internationalization** - Organizations worldwide should use native language names. Unicode letter/number categories include all alphabets while excluding dangerous punctuation.

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

The source key (e.g., `cve`) becomes the `name` component in SecIDs: `secid:advisory/mitre.org/cve#CVE-2024-1234`

#### Source Name Fields

Same pattern as top-level: `official_name`, `common_name`, `alternate_names`.

#### Source Description

The `description` field provides context about what this source is and when to use it:

```json
"sources": {
  "errata": {
    "official_name": "Red Hat Security Advisories",
    "description": "Red Hat publishes three types of errata: RHSA (Security Advisory) for security fixes, RHBA (Bug Advisory) for bug fixes, and RHEA (Enhancement Advisory) for new features. Most security work focuses on RHSA.",
    ...
  }
}
```

**What to describe:**
- Classes of objects the source contains (what is an RHSA vs RHBA vs RHEA?)
- When to use this source vs similar ones
- Important quirks or exceptions (e.g., numbering restarts annually)

**What NOT to describe:**
- Every individual instance (don't describe CVE-2024-1234)
- Data enrichment (severity, affected products, authors)

**Rule of thumb:** Is it an object or a class of objects? Describe classes. For individual objects, only describe when unique/important (like ISO standards or NIST special publications).

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

**URL type vocabulary:**

| Type | Description |
|------|-------------|
| `website` | Main website for humans |
| `docs` | Documentation pages |
| `search` | Search interface (human or programmatic) |
| `lookup` | Resolution URL with `{id}` placeholder |
| `api` | API endpoint |
| `bulk_data` | Bulk download location |
| `github` | GitHub repository |
| `paper` | Academic paper |
| `secid_api` | SecID REST API for this source (if different from main) |
| `secid_mcp` | SecID MCP endpoint for this source (if different from main) |

**Why an array?** Multiple URLs of the same type are common (e.g., primary and fallback lookup endpoints, multiple mirrors). The `note` field provides context to help AI choose appropriately.

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
  {"pattern": "^CVE-\\d{4}-\\d{4,}$", "description": "Standard CVE ID format"}
]
```

For sources with multiple ID types:

```json
"id_patterns": [
  {"pattern": "^T\\d{4}(\\.\\d{3})?$", "type": "technique", "description": "ATT&CK technique"},
  {"pattern": "^TA\\d{4}$", "type": "tactic", "description": "ATT&CK tactic"},
  {"pattern": "^M\\d{4}$", "type": "mitigation", "description": "ATT&CK mitigation"},
  {"pattern": "^G\\d{4}$", "type": "group", "description": "Threat group"}
]
```

For sources where different ID patterns need different lookup URLs:

```json
"id_patterns": [
  {"pattern": "^ALAS-\\d{4}-\\d+$", "type": "al1", "description": "Amazon Linux 1", "url": "https://alas.aws.amazon.com/{id}.html"},
  {"pattern": "^ALAS2-\\d{4}-\\d+$", "type": "al2", "description": "Amazon Linux 2", "url": "https://alas.aws.amazon.com/AL2/{id}.html"},
  {"pattern": "^ALAS2023-\\d{4}-\\d+$", "type": "al2023", "description": "Amazon Linux 2023", "url": "https://alas.aws.amazon.com/AL2023/{id}.html"}
]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | yes | PCRE2-compatible regular expression (should be anchored with `^...$`) |
| `type` | string | no | Category when source has multiple ID types |
| `description` | string | no | Human/AI-readable description of what this pattern represents |
| `ecosystem` | string | no | For ecosystem-specific patterns (e.g., PyPI, Go) |
| `url` | string | no | Pattern-specific lookup URL (overrides default lookup URL) |
| `variables` | object | no | Map of placeholder names to extraction objects (see below) |
| `known_values` | object | no | Enumeration of finite, stable values (see below) |

**Variables structure:**

Each key in `variables` is a placeholder name (e.g., `number`, `year`). The value is an object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `extract` | string | yes | Regex with capture groups. Groups are numbered `{1}`, `{2}`, etc. |
| `format` | string | no | How to assemble the value from capture groups. Defaults to `{1}`. Can include literals. |
| `description` | string | yes | Explains what this variable is and how it's derived from the ID. |

Simple example (single capture group, default format):
```json
"variables": {
  "number": {
    "extract": "^CWE-(\\d+)$",
    "description": "Numeric ID portion (e.g., '79' from 'CWE-79')"
  }
}
```

Example with format (appending literal text):
```json
"variables": {
  "bucket": {
    "extract": "^CVE-\\d{4}-(\\d+)\\d{3}$",
    "format": "{1}xxx",
    "description": "All but last 3 digits + 'xxx' (e.g., '25xxx' from 'CVE-2026-25010')"
  }
}
```

**Why always an array?** Consistency. Even single-pattern sources use an array with one item. Avoids having both `id_pattern` (string) and `id_patterns` (array).

**Why anchored patterns?** Anchored patterns (`^CVE-\d{4}-\d{4,}$`) ensure the entire subpath must match, rejecting malformed SecIDs like `secid:advisory/mitre.org/cve#CVE-2024-1234/garbage`. Unanchored patterns would match substrings, allowing invalid input.

**Why `url` in patterns?** Some sources have multiple ID formats that resolve to different URLs. Rather than a separate `id_routing` concept, patterns can include their own lookup URL when needed.

**Patterns match the human-readable (unencoded) form.** Write patterns matching what you see in the source documentation. `^Auditing Guidelines$` with a literal space, not `^Auditing%20Guidelines$`. Resolvers are responsible for decoding percent-encoded input before matching against patterns (see SPEC.md Section 8.3).

**Patterns are independent, not chained.** All patterns are tested against the subpath independently — there is no ordering, priority, or conditional chaining between patterns. A future version may support chained patterns (e.g., "if pattern A matches, try pattern B on a captured group") if real-world usage demonstrates the need. For now, independent patterns keep the matching model simple and predictable. Each pattern either matches or it doesn't, and all matching patterns contribute resolution URLs.

**Note:** These are **format patterns**, not validity checks. A pattern like `CVE-\d{4}-\d{4,}` tells you "this looks like a CVE ID" - whether that specific CVE actually exists is only known when you try to resolve it.

#### Known Values

For patterns with finite, stable value sets, use `known_values` to enumerate them with descriptions:

```json
"id_patterns": [
  {
    "pattern": "^[A-Z]{2,3}$",
    "type": "domain",
    "description": "Control domain. Contains multiple controls.",
    "known_values": {
      "IAM": "Identity & Access Management",
      "DSP": "Data Security & Privacy Lifecycle Management",
      "GRC": "Governance, Risk & Compliance",
      "SEF": "Security Incident Management, E-Discovery & Forensics"
    }
  },
  {
    "pattern": "^[A-Z]{2,3}-\\d{2}$",
    "type": "control",
    "description": "Specific control (e.g., IAM-12). Belongs to a domain."
  }
]
```

**When to use `known_values`:**
- Finite, stable sets (control domains, advisory types, document categories)
- Classes that need disambiguation (what is IAM vs DSP vs GRC?)
- Important individual items worth enumerating (ISO standard numbers with their titles)

**When NOT to use:**
- Open-ended or growing sets (individual CVEs, specific controls)
- Values that are obvious from context (years, sequential numbers)

**Examples of good candidates:**

Control framework domains:
```json
"known_values": {
  "IAM": "Identity & Access Management",
  "DSP": "Data Security & Privacy Lifecycle Management"
}
```

Advisory types (Red Hat errata):
```json
"known_values": {
  "RHSA": "Security Advisory - security fixes, most commonly referenced",
  "RHBA": "Bug Advisory - non-security bug fixes",
  "RHEA": "Enhancement Advisory - new features"
}
```

ISO standard numbers with titles:
```json
"known_values": {
  "27001": "Information security management systems — Requirements",
  "27002": "Information security controls",
  "42001": "Artificial intelligence — Management system"
}
```

**Rule of thumb:** Ask "is this a class of objects?" If yes, describe it. For individual instances, only include in `known_values` when they're distinct enough to need disambiguation (ISO 27001 vs 42001) or when the set is small and stable.

#### Version Patterns (array, optional)

For sources where different versions have different URL structures, use `version_patterns` to route based on the `@version` component:

```json
"version_patterns": [
  {
    "pattern": "^4\\..*$",
    "description": "Version 4.x",
    "url": "https://example.com/v4/resource/{id}"
  },
  {
    "pattern": "^3\\..*$",
    "description": "Version 3.x and earlier",
    "url": "https://example.com/legacy/v{version}/{id}"
  }
]
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | yes | PCRE2-compatible regex to match version string (should be anchored) |
| `description` | string | no | Human/AI-readable description |
| `url` | string | yes | URL template for this version range |

**Resolution example:** `secid:control/cloudsecurityalliance.org/ccm@4.0.1#IAM-12`
1. Extract version = `4.0.1`, id = `IAM-12`
2. Match version against patterns → `^4\..*$` matches
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

For `type: reference` (documents, papers, standards), additional fields help with identity:

```json
{
  "type": "reference",
  "namespace": "nist.gov",

  "title": "AI RMF",
  "full_title": "Artificial Intelligence Risk Management Framework",

  "sources": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Short/common title |
| `full_title` | string \| null | Complete formal title |

**Note:** Standard identifier systems (DOI, ISBN, ISSN, arXiv, etc.) are **namespaces**, not fields:

```
secid:reference/doi.org/10.6028/NIST.AI.100-1
secid:reference/isbn.org/978-0-123456-78-9
secid:reference/arxiv.org/2303.08774
secid:reference/ietf.org/rfc9110
```

If a document has both a human-readable reference (`secid:reference/nist.gov/ai-rmf`) and a DOI (`secid:reference/doi.org/10.6028/NIST.AI.100-1`), the equivalence relationship between them belongs in the **relationship layer**, not the registry.

## Entity Type Differences

Entity files describe organizations rather than data sources. They use a `names` block instead of `sources` to document products/projects the entity is known for:

```json
{
  "namespace": "mitre.org",
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
  "namespace": "mitre.org",
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
        {"type": "api", "url": "https://cveawg.mitre.org/api"},
        {"type": "bulk_data", "url": "https://github.com/CVEProject/cvelistV5"}
      ],

      "id_patterns": [
        {
          "pattern": "^CVE-\\d{4}-\\d{4,}$",
          "description": "Standard CVE ID format",
          "url": "https://cve.org/CVERecord?id={id}"
        },
        {
          "pattern": "^CVE-\\d{4}-\\d{4,}$",
          "description": "CVE JSON record on GitHub",
          "url": "https://github.com/CVEProject/cvelistV5/blob/main/cves/{year}/{bucket}/{id}.json",
          "format": "json",
          "note": "Raw CVE record from cvelistV5 repository",
          "variables": {
            "year": {
              "extract": "^CVE-(\\d{4})-\\d+$",
              "description": "4-digit year (e.g., '2026' from 'CVE-2026-25010')"
            },
            "bucket": {
              "extract": "^CVE-\\d{4}-(\\d+)\\d{3}$",
              "format": "{1}xxx",
              "description": "All but last 3 digits + 'xxx' (e.g., '25xxx' from 'CVE-2026-25010')"
            },
            "id": {
              "extract": "^(CVE-\\d{4}-\\d+)$",
              "description": "Full CVE ID"
            }
          }
        },
        {
          "pattern": "^CVE-\\d{4}-\\d{4,}$",
          "description": "CVE JSON via API",
          "url": "https://cveawg.mitre.org/api/cve/{id}",
          "format": "json",
          "note": "JSON API, richer data"
        }
      ],

      "examples": ["CVE-2024-1234", "CVE-2021-44228", "CVE-2026-25010"]
    }
  }
}
```

## Complete Example: Sub-Namespace

This example shows a namespace with a `/`-separated path portion (`github.com/advisories`). The namespace maps to `registry/advisory/com/github/advisories.json` via the reverse-DNS algorithm.

```json
{
  "schema_version": "1.0",
  "namespace": "github.com/advisories",
  "type": "advisory",
  "status": "draft",
  "status_notes": null,

  "official_name": "GitHub Advisory Database",
  "common_name": "GitHub Advisories",
  "alternate_names": null,

  "urls": [
    {"type": "website", "url": "https://github.com/advisories"}
  ],

  "sources": {
    "ghsa": {
      "official_name": "GitHub Security Advisories",
      "common_name": "GHSA",
      "alternate_names": null,

      "urls": [
        {"type": "website", "url": "https://github.com/advisories"},
        {"type": "api", "url": "https://api.github.com/advisories"},
        {"type": "bulk_data", "url": "https://github.com/github/advisory-database"}
      ],

      "id_patterns": [
        {
          "pattern": "^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$",
          "description": "GitHub Security Advisory ID",
          "url": "https://github.com/advisories/{id}"
        }
      ],

      "examples": ["GHSA-jfh8-c2jp-5v3q", "GHSA-8v63-cqqc-6r2c"]
    }
  }
}
```

**Key differences from simple namespace:**
- `namespace` includes a path: `github.com/advisories` (not just `github.com`)
- Filesystem path uses reverse-DNS for domain + appended path: `registry/advisory/com/github/advisories.json`
- SecID references use the full namespace: `secid:advisory/github.com/advisories/ghsa#GHSA-jfh8-c2jp-5v3q`

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

## Multi-Level Pattern Example

For sources with hierarchical identifiers (domain → control → section), define patterns for each level:

```json
{
  "schema_version": "1.0",
  "namespace": "cloudsecurityalliance.org",
  "type": "control",
  "status": "published",

  "official_name": "Cloud Security Alliance",
  "common_name": "CSA",
  "wikidata": ["Q5135329"],

  "urls": [
    {"type": "website", "url": "https://cloudsecurityalliance.org"}
  ],

  "sources": {
    "ccm": {
      "official_name": "Cloud Controls Matrix",
      "common_name": "CCM",
      "description": "Security controls framework organized by domains. Domains contain controls, controls may have implementation sections.",

      "urls": [
        {"type": "website", "url": "https://cloudsecurityalliance.org/research/cloud-controls-matrix"},
        {"type": "docs", "url": "https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4"}
      ],

      "id_patterns": [
        {
          "pattern": "^[A-Z]{2,3}$",
          "type": "domain",
          "description": "Control domain (e.g., IAM). Contains multiple controls.",
          "known_values": {
            "A&A": "Audit & Assurance",
            "AIS": "Application & Interface Security",
            "BCR": "Business Continuity Management & Operational Resilience",
            "CCC": "Change Control & Configuration Management",
            "CEK": "Cryptography, Encryption & Key Management",
            "DCS": "Datacenter Security",
            "DSP": "Data Security & Privacy Lifecycle Management",
            "GRC": "Governance, Risk & Compliance",
            "HRS": "Human Resources",
            "IAM": "Identity & Access Management",
            "IPY": "Interoperability & Portability",
            "IVS": "Infrastructure & Virtualization Security",
            "LOG": "Logging & Monitoring",
            "SEF": "Security Incident Management, E-Discovery & Forensics",
            "STA": "Supply Chain Management, Transparency & Accountability",
            "TVM": "Threat & Vulnerability Management",
            "UEM": "Universal Endpoint Management"
          }
        },
        {
          "pattern": "^[A-Z]{2,3}-\\d{2}$",
          "type": "control",
          "description": "Specific control (e.g., IAM-12). Belongs to a domain.",
          "url": "https://ccm.cloudsecurityalliance.org/control/{id}"
        },
        {
          "pattern": "^[A-Z]{2,3}-\\d{2}\\.\\d{1,2}$",
          "type": "section",
          "description": "Control section (e.g., IAM-12.1). Implementation detail within a control."
        }
      ],

      "version_patterns": [
        {
          "pattern": "^4\\..*$",
          "description": "Version 4.x",
          "url": "https://ccm.cloudsecurityalliance.org/v4/control/{id}"
        },
        {
          "pattern": "^3\\..*$",
          "description": "Version 3.x (legacy)",
          "url": "https://cloudsecurityalliance.org/artifacts/ccm-v3/{id}"
        }
      ],

      "examples": [
        "secid:control/cloudsecurityalliance.org/ccm#IAM",
        "secid:control/cloudsecurityalliance.org/ccm#IAM-12",
        "secid:control/cloudsecurityalliance.org/ccm@4.0#IAM-12",
        "secid:control/cloudsecurityalliance.org/ccm#IAM-12.1"
      ]
    }
  }
}
```

**Key points:**
- Three pattern levels: domain, control, section
- `known_values` only on domain level (finite, stable set)
- Pattern-specific URLs for controls (different from domain lookups)
- Version patterns for major version routing
- Not every level needs a lookup URL (domain-level has none)

## Schema Versioning

The `schema_version` field allows for future evolution. Parsers should check this field and handle unknown versions gracefully.

Current version: `1.0` (draft)
