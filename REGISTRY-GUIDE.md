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

### Preserve Source Identifier Formats

**Subpaths preserve the source's exact identifier format - including special characters.**

If Red Hat uses `RHSA-2026:0932` with a colon, we use `RHSA-2026:0932`. If ATT&CK uses `T1059.003` with a dot, we use `T1059.003`. No sanitization, no transformation.

| Source | Their Format | SecID Subpath |
|--------|--------------|---------------|
| Red Hat errata | `RHSA-2026:0932` | `#RHSA-2026:0932` ✓ (not `#RHSA-2026-0932`) |
| ATT&CK | `T1059.003` | `#T1059.003` ✓ |
| ISO 27001 | `A.8.1` | `#A.8.1` ✓ |
| NIST CSF | `PR.AC-1` | `#PR.AC-1` ✓ |

**Why this matters:**
- Practitioners recognize `RHSA-2026:0932` instantly - no translation needed
- Copy from SecID, paste into search engines - it works
- No information loss from character substitution
- The issuing authority chose the format; we defer to them

## Domain-Name Namespaces

Namespaces are **domain names** of the organizations that publish security knowledge. This enables self-registration, scales without a central naming authority, and provides built-in ownership verification.

**Per-segment validation:** Namespaces may include `/`-separated path segments for platform sub-namespaces. Each segment between `/` must match:

`^[\p{L}\p{N}]([\p{L}\p{N}._-]*[\p{L}\p{N}])?$`

**Allowed characters per segment:**
- `a-z` (lowercase ASCII letters)
- `0-9` (ASCII digits)
- `-` (hyphen, not at start/end)
- `.` (period, as DNS label separator)
- Unicode letters (`\p{L}`) and numbers (`\p{N}`)

**`/` separates segments** within namespaces for platform sub-namespaces.

**Examples:**
```
mitre.org                ✓  Domain name
cloudsecurityalliance.org ✓  Long domain name
nist.gov                 ✓  Government domain
github.com/advisories    ✓  Platform sub-namespace (one path segment)
github.com/ModelContextProtocol-Security/vulnerability-db  ✓  Deep sub-namespace (two path segments)
aws.amazon.com           ✓  Subdomain
字节跳动.com              ✓  Unicode domain (ByteDance)
red_hat.com              ✗  Underscore not allowed in segment
```

**Namespace file location:** Namespace files are stored in a reverse-DNS directory hierarchy: `registry/<type>/<tld>/<domain>.md`
- Simple namespace: `registry/advisory/org/mitre.md`
- Sub-namespace: `registry/advisory/com/github/advisories.md` (directory + file)

**Why domain names:**

1. **Self-registration** - Domain owners prove ownership via DNS TXT records or ACME challenges. No central naming authority needed.

2. **Globally unique** - DNS already provides collision-free identifiers. No need for manual arbitration.

3. **Filesystem safety** - Domain names and path segments become file paths. Avoiding shell metacharacters ensures repos work in Git across all platforms.

4. **Unicode for internationalization** - Organizations worldwide should use native language domain names.

## Granularity and Hierarchy

Many sources have hierarchical structure. Use the granularity levels the source provides.

### Example: Cloud Controls Matrix (CCM)

| Level | Example | SecID |
|-------|---------|-------|
| Framework | CCM 4.0 | `secid:control/cloudsecurityalliance.org/ccm@4.0` |
| Domain | Identity & Access Management | `secid:control/cloudsecurityalliance.org/ccm@4.0#IAM` |
| Control | IAM-12 | `secid:control/cloudsecurityalliance.org/ccm@4.0#IAM-12` |

### Example: ISO 42001

| Level | Example | SecID |
|-------|---------|-------|
| Standard | ISO 42001 | `secid:control/iso.org/42001` |
| Annex | Annex B | `secid:control/iso.org/42001#B` |
| Section | B.1 | `secid:control/iso.org/42001#B.1` |
| Subsection | B.1.2 | `secid:control/iso.org/42001#B.1.2` |

### Example: GDPR

| Level | Example | SecID |
|-------|---------|-------|
| Regulation | GDPR | `secid:regulation/europa.eu/gdpr` |
| Chapter | Chapter III | `secid:regulation/europa.eu/gdpr#chapter-3` |
| Article | Article 17 | `secid:regulation/europa.eu/gdpr#article-17` |
| Paragraph | Article 17(1) | `secid:regulation/europa.eu/gdpr#article-17-1` |

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
secid:reference/doi.org/10.6028/NIST.AI.100-1
secid:reference/isbn.org/978-0-13-468599-1
secid:reference/arxiv.org/2303.08774
```

If a document has multiple identifiers (DOI and arXiv ID for the same paper), the equivalence relationship belongs in the relationship layer, not the registry.

### Frameworks with Weaknesses AND Controls

Some frameworks define both problems and solutions (like OWASP AI Exchange):

```
secid:weakness/owasp.org/ai-exchange#DIRECTPROMPTINJECTION   → The threat
secid:control/owasp.org/ai-exchange#INPUTVALIDATION          → The mitigation
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
registry/<type>/<tld>/<domain>.md
```

One file per namespace containing all sources from that organization:
- `registry/advisory/com/redhat.md` → Red Hat CVE, errata, bugzilla
- `registry/control/gov/nist.md` → NIST CSF, 800-53, AI RMF

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

1. **Critical for finding** - You can't use `secid:control/cloudsecurityalliance.org/ccm@4.0#IAM-12` without knowing what IAM means
2. **Class-level** - We describe categories, not instances
3. **Stable** - Category names rarely change
4. **Aids disambiguation** - Helps distinguish IAM (controls) from IAM (cloud services)

## Self-Registration (Future)

> **Current state:** Namespace registration is manual — submit a pull request. Automated self-registration is a planned future feature.

Domain-name namespaces are designed for eventual decentralized ownership verification. When automated registration is implemented, namespace owners will prove control without a central naming authority. This is designed for both **human operators** and **AI agents acting on behalf of organizations** — an agent managing security operations for a company should be able to register and maintain that organization's namespace programmatically, just as it might manage DNS records or certificates today.

### Domain Owners

Organizations that own a domain will prove namespace ownership via:

1. **DNS TXT record** - Add a TXT record to the domain:
   ```
   _secid.redhat.com  TXT  "secid-verify=<challenge-token>"
   ```

2. **ACME-style challenge** - Place a verification file at a well-known URL:
   ```
   https://redhat.com/.well-known/secid-verify/<challenge-token>
   ```

Either method proves the registrant controls the domain, which maps directly to the namespace (`redhat.com` → `registry/*/com/redhat/**`). These mechanisms are machine-friendly by design — AI agents can perform DNS updates and file placement without human intervention.

### Platform Sub-Namespace Owners

For platform sub-namespaces (e.g., `github.com/username`), the platform user (or their agent) proves control by placing a challenge file in their repository:

```
https://github.com/username/.secid-verify
```

The ownership chain follows left-to-right URL authority delegation:
- `github.com` is owned by GitHub (verified via DNS)
- `github.com/username` is delegated to the GitHub user (verified via repo challenge)
- `github.com/username/project` inherits from the user's namespace

### Ownership Scope

Verified owners manage their own registry paths. Ownership of `redhat.com` grants authority over:
- `registry/advisory/com/redhat.md`
- `registry/entity/com/redhat.md`
- Any future `registry/*/com/redhat/**` files

But NOT over sub-namespaces they don't control (e.g., a third party's `redhat.com/partner` would require separate verification).

## CODEOWNERS

Self-registration integrates with GitHub's CODEOWNERS mechanism for federated management:

```
# registry/*/com/redhat/**         @redhat-security-team
# registry/*/gov/nist/**           @nist-csrc
# registry/*/com/github/advisories/** @github-security
```

This enables:
- **Verified owners review their own files** - Changes to `redhat.com.md` require Red Hat approval
- **Sub-namespace delegation** - `github.com/advisories` can have different owners than `github.com`
- **Scalable governance** - No central bottleneck for reviewing namespace changes

### Pre-Seeding

Before self-registration opens, high-value namespaces should be claimed proactively:

| Priority | Namespaces | Reason |
|----------|-----------|--------|
| Critical | `mitre.org`, `nist.gov`, `cisa.gov` | Core vulnerability infrastructure |
| High | `redhat.com`, `microsoft.com`, `google.com`, `apple.com` | Major CNAs |
| High | `owasp.org`, `iso.org`, `cisecurity.org` | Major frameworks |
| Medium | `europa.eu`, `govinfo.gov` | Regulatory bodies |
| Medium | `doi.org`, `arxiv.org`, `isbn.org` | Identifier systems |

Pre-seeded namespaces are transferred to verified domain owners upon successful self-registration.

## Migration from Short Names

SecID previously used short names for namespaces (`mitre`, `nist`, `redhat`). These have been replaced with domain-name namespaces (`mitre.org`, `nist.gov`, `redhat.com`).

**Why the change:**
- Short names create collision risks at scale (10,000+ namespaces)
- No ownership verification mechanism
- Required a central naming authority

**For the complete old→new mapping**, see [NAMESPACE-MAPPING.md](NAMESPACE-MAPPING.md).

**Quick reference for common namespaces:**

| Old | New |
|-----|-----|
| `mitre` | `mitre.org` |
| `nist` | `nist.gov` |
| `redhat` | `redhat.com` |
| `github` (advisory) | `github.com/advisories` |
| `github` (entity) | `github.com` |
| `csa` | `cloudsecurityalliance.org` |
| `owasp` | `owasp.org` |
| `iso` | `iso.org` |

## See Also

- [REGISTRY-JSON-FORMAT.md](REGISTRY-JSON-FORMAT.md) - Technical schema specification
- [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) - Rationale for design choices
- [EDGE-CASES.md](EDGE-CASES.md) - Domain-name namespace edge cases
- [NAMESPACE-MAPPING.md](NAMESPACE-MAPPING.md) - Complete short-name to domain-name mapping
- [registry/README.md](registry/README.md) - Registry structure overview
