# Registry Guide

This document explains the principles, patterns, and process for contributing to the SecID registry.

For technical details, see:
- [REGISTRY-JSON-FORMAT.md](REGISTRY-JSON-FORMAT.md) - JSON schema, resolution pipeline, variable extraction
- [SPEC.md](SPEC.md) - Full SecID specification

## Scope: Labeling and Finding

**SecID is about labeling and finding things. That's it.**

The registry contains:
- **Identity** - What is this thing called?
- **Resolution** - How do I find/access it?
- **Disambiguation** - How do I tell similar things apart?

The registry does NOT contain:
- **Enrichment** - Metadata about the thing (authors, categories, publication dates)
- **Judgments** - Quality assessments, trust scores, recommendations
- **Relationships** - How things connect to each other

## Three Layers

SecID separates concerns into layers:

| Layer | Contains | Example |
|-------|----------|---------|
| **Registry** | Identity, resolution, disambiguation | "CVE is at cve.org, IDs look like CVE-YYYY-NNNNN" |
| **Relationship** | Equivalence, succession, hierarchy | "This DOI and this arXiv ID are the same paper" |
| **Data** | Enrichment, metadata, attributes | "This CVE affects Linux kernel, severity is high" |

When deciding if something belongs in the registry, ask: "Is this needed to **identify**, **find**, or **disambiguate** the thing?" If no, it belongs in another layer.

## Follow the Source

Use names and structures the source uses:

- **Names**: If Red Hat calls it "ROSA", use `rosa`, not `openshift-aws-managed-service`
- **IDs**: If CVE uses `CVE-2024-1234`, use that as the subpath
- **Hierarchy**: If the source has domains/sections, use their structure

Don't invent naming schemes. The source's identifiers are authoritative.

## Granularity and Hierarchy

Many sources have hierarchical structure. Use the granularity levels the source provides.

### Example: Cloud Controls Matrix (CCM)

| Level | Example | SecID |
|-------|---------|-------|
| Framework | CCM 4.0 | `secid:control/csa/ccm@4.0` |
| Domain | Identity & Access Management | `secid:control/csa/ccm@4.0#IAM` |
| Control | IAM-12 | `secid:control/csa/ccm@4.0#IAM-12` |

### Example: ISO 42001

| Level | Example | SecID |
|-------|---------|-------|
| Standard | ISO 42001 | `secid:control/iso/42001` |
| Annex | Annex B | `secid:control/iso/42001#B` |
| Section | B.1 | `secid:control/iso/42001#B.1` |
| Subsection | B.1.2 | `secid:control/iso/42001#B.1.2` |

### Example: GDPR

| Level | Example | SecID |
|-------|---------|-------|
| Regulation | GDPR | `secid:regulation/eu/gdpr` |
| Chapter | Chapter III | `secid:regulation/eu/gdpr#chapter-3` |
| Article | Article 17 | `secid:regulation/eu/gdpr#article-17` |
| Paragraph | Article 17(1) | `secid:regulation/eu/gdpr#article-17-1` |

### Documenting Hierarchy in id_patterns

Each granularity level should have its own pattern with a description:

```json
"id_patterns": [
  {
    "pattern": "^[A-Z]{2,3}$",
    "type": "domain",
    "description": "Control domain (e.g., IAM). Contains multiple controls.",
    "known_values": {
      "IAM": "Identity & Access Management",
      "DSP": "Data Security & Privacy Lifecycle Management"
    }
  },
  {
    "pattern": "^[A-Z]{2,3}-\\d{2}$",
    "type": "control",
    "description": "Specific control (e.g., IAM-12). Belongs to a domain."
  }
]
```

**Note:** Patterns should be anchored (`^...$`) to match the complete subpath. This ensures malformed identifiers are rejected.

Use `known_values` for the domain/category level (finite set) but not for individual controls (open-ended set).

Not every granularity level needs to resolve to a URL. An identifier can be valid for reference purposes even without direct resolution.

## Common Patterns

### Security Tools: Entity + Control

Security tools that provide security checks should appear in **both** types:

| Type | Documents | Example |
|------|-----------|---------|
| `entity` | What the tool IS | Product description, capabilities, access methods |
| `control` | What checks it PROVIDES | Specific detections, validations, mappings |

Example: A vulnerability scanner is an entity (`secid:entity/vendor/scanner`) and its detection rules are controls (`secid:control/vendor/scanner#rule-123`).

### Identifier Systems as Namespaces

Standard identifier systems (DOI, ISBN, arXiv, etc.) are **namespaces**, not fields:

```
secid:reference/doi/10.6028/NIST.AI.100-1
secid:reference/isbn/978-0-13-468599-1
secid:reference/arxiv/2303.08774
```

If a document has multiple identifiers (DOI and arXiv ID for the same paper), the equivalence relationship belongs in the relationship layer, not the registry.

### Frameworks with Weaknesses AND Controls

Some frameworks define both problems and solutions (like OWASP AI Exchange):

```
secid:weakness/owasp/ai-exchange#DIRECTPROMPTINJECTION   → The threat
secid:control/owasp/ai-exchange#INPUTVALIDATION          → The mitigation
```

Document in both types when the source provides both perspectives.

## Adding to the Registry

### Step 1: Understand the Source

Before adding anything, study how the source is **presented** and how people **use** it:

**Examine the structure:**
- How is the document/framework organized? (chapters, sections, domains, categories)
- What identifier system does it use? (numeric, alphanumeric, hierarchical)
- Are there multiple levels of granularity? (framework → domain → control)
- Does the source have an official ID scheme, or just titles/descriptions?

**Observe real-world usage:**
- How do practitioners actually reference it? ("GDPR Article 17" vs "GDPR Art. 17" vs "right to erasure")
- What granularity levels do people cite? (whole framework, sections, specific items)
- Are there common abbreviations or shorthand? (CCM, CSF, 800-53)
- Do other tools/databases reference it, and how?

**Check for existing patterns:**
- Does the source provide lookup URLs for specific items?
- Is there an API or structured data export?
- Are there official ID patterns documented?

**Document what you find** - this research informs every field in the registry entry.

### Step 2: Decision Tree

1. **Is this security knowledge?** If not, it doesn't belong in SecID.

2. **What type is it?**
   - Publications about vulnerabilities → `advisory`
   - Abstract flaw patterns → `weakness`
   - Adversary techniques → `ttp`
   - Security requirements → `control`
   - Laws and legal requirements → `regulation`
   - Organizations, products, services → `entity`
   - Documents and research → `reference`

3. **Does the namespace exist?**
   - Yes → Add a source to the existing namespace file
   - No → Create a new namespace file

4. **What granularity levels exist?** Document each with an id_pattern.

### Step 3: Namespace File Location

```
registry/<type>/<namespace>.md
```

One file per namespace containing all sources from that organization:
- `registry/advisory/redhat.md` → Red Hat CVE, errata, bugzilla
- `registry/control/nist.md` → NIST CSF, 800-53, AI RMF

### Step 4: Required Information

For each source, you need:
- **Name**: `official_name`, `common_name` (if different)
- **Resolution**: `urls[]` with lookup templates
- **Recognition**: `id_patterns[]` for each granularity level
- **Examples**: Representative SecID strings

### Status Progression

| Status | Meaning | Requirements |
|--------|---------|--------------|
| `proposed` | Suggested, minimal info | namespace, type, status, official_name |
| `draft` | Being worked on | Any fields, actively researching |
| `pending` | Awaiting review | All fields present (value, `null`, or `[]`) |
| `published` | Reviewed and approved | Same as pending, reviewed by maintainer |

**Key insight**: `published` means "reviewed", not "complete". Empty arrays and `null` values are valid—they show we looked and couldn't find anything.

Use `status_notes` to explain blockers or gaps:
```json
"status": "draft",
"status_notes": "Waiting for vendor response about official URL"
```

### Using _deferred/

Put partially researched entries in `registry/_deferred/` until they're ready. This keeps the main registry clean while preserving research in progress.

## Quality Standards

### Null vs Absent Convention

| State | Representation | Meaning |
|-------|----------------|---------|
| Has data | `"field": "value"` | We have the information |
| No data exists | `"field": null` | We looked, nothing to find |
| Not researched | field absent | We haven't looked yet |

This lets us track completeness. An absent field signals work to be done.

### Good id_patterns

- **Anchor patterns** with `^...$` to match the complete subpath (rejects malformed IDs)
- Use PCRE2-compatible regex (safe subset for cross-platform compatibility)
- Include `description` explaining what the pattern matches
- Include `type` for multi-level hierarchies
- Patterns are **format checks**, not validity checks—they recognize structure, not existence
- Use `variables` with `extract` and `format` for complex URL building (see REGISTRY-JSON-FORMAT.md)

### Good Descriptions

Explain what and why:
- What kind of thing is this?
- When would someone use it vs alternatives?
- Any quirks or gotchas?

**The rule of thumb:** Is it an object or a class of objects?

- **Describe classes** - Always explain what categories, types, or domains mean (RHSA vs RHBA vs RHEA)
- **Sometimes describe unique objects** - Include hints for important individual items (ISO 27001 vs 42001 deserve titles)
- **Never describe every instance** - Don't describe individual CVEs or advisories

### When to Use known_values

Use `known_values` to enumerate finite, stable value sets:

```json
"id_patterns": [
  {
    "pattern": "^[A-Z]{2,3}$",
    "type": "domain",
    "description": "Control domain. Contains multiple controls.",
    "known_values": {
      "IAM": "Identity & Access Management",
      "DSP": "Data Security & Privacy Lifecycle Management"
    }
  }
]
```

**Good candidates for known_values:**
- Control framework domains (IAM, DSP, GRC)
- Advisory type prefixes (RHSA, RHBA, RHEA)
- ISO standard numbers with titles (27001, 42001)
- Small, stable category codes

**Not good candidates:**
- Growing or open-ended sets (individual CVEs)
- Self-explanatory values (years, sequential numbers)
- Instance data (specific controls within a domain)

### Why This Isn't Enrichment

Descriptions and known_values walk a line - technically "what is IAM" could be enrichment. We include it because:

1. **Critical for finding** - You can't use `secid:control/csa/ccm@4.0#IAM-12` without knowing what IAM means
2. **Class-level** - We describe categories, not instances
3. **Stable** - Category names rarely change
4. **Aids disambiguation** - Helps distinguish IAM (controls) from IAM (cloud services)

## See Also

- [REGISTRY-JSON-FORMAT.md](REGISTRY-JSON-FORMAT.md) - Technical schema specification
- [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) - Rationale for design choices
- [registry/README.md](registry/README.md) - Registry structure overview
