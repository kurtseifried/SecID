# Design Decisions

This document captures key design decisions and the reasoning behind them.

## Identifiers Are Just Identifiers

### The Principle

SecID separates concerns into layers:

| Layer | What it does | Status |
|-------|--------------|--------|
| **Identifiers** | Name things | Specified |
| **Registry** | Define what exists, how to resolve | Current |
| **Relationships** | Connect things | Future |
| **Overlays** | Enrich without mutating | Future |

The identifier specification defines how to write a SecID string. That's it. Everything else - relationships between identifiers, enrichments, corrections, history - is layered on top, separately.

### Why This Matters

Early drafts mixed these concerns. The registry files included:
- `replaced_by: ibmredhat` - succession tracking
- `past_names: [redhat]` - historical names
- Detailed relationship data

This felt natural ("keep everything about an entity in one place") but created problems:

**1. Scope creep in the spec**

If the identifier spec defines relationship types, we have to get them right before shipping. But we don't know what relationships people actually need yet.

**2. Registry becomes stateful**

Adding `replaced_by` means registry files track history and change over time. Now you need versioning, conflict resolution, update processes. The registry stops being a simple "what exists" definition.

**3. Premature optimization**

Designing the relationship layer requires answering hard questions:
- Directionality (one-way or bidirectional?)
- Provenance (who said this? when?)
- Conflicts (what if sources disagree?)

We could guess at answers, but we'd probably guess wrong. Better to wait until usage teaches us.

### The PURL Model

Package URL (PURL) takes the same approach. PURL defines how to write a package identifier:

```
pkg:npm/lodash@4.17.21
```

PURL doesn't define:
- How packages relate to vulnerabilities
- How to track package renames
- What metadata to attach

Those concerns are handled by other systems (OSV, GHSA, etc.) that *use* PURLs. PURL is just the identifier.

SecID follows this pattern. **SecID uses PURL grammar with `secid:` as the scheme** - just as PURL uses `pkg:`, SecID uses `secid:`. Everything after `secid:` follows PURL grammar exactly (`type/namespace/name`):

```
secid:advisory/mitre/cve#CVE-2024-1234
```

What you can say *about* that identifier - relationships, enrichments, history - is a separate concern.

### What We Gain

**Simpler spec**: The identifier specification is just grammar and types. Ship it, stabilize it, done.

**Flexibility**: Relationship and overlay layers can be designed later, informed by actual usage.

**Clean separation**: The registry defines "what exists." The data layers define "how things connect." Different concerns, different update cadences, different governance.

**No premature commitment**: We're not locked into relationship semantics we designed before understanding the problem.

### What We Defer

The relationship and overlay layers are documented as exploratory thinking (see [RELATIONSHIPS.md](RELATIONSHIPS.md) and [OVERLAYS.md](OVERLAYS.md)). They capture what we're considering, not what we've decided.

We'll design these layers when:
1. The registry has enough content to make relationships valuable
2. We have concrete use cases requiring queryable connections
3. Usage patterns reveal what's actually needed

### Summary

**Identifiers are just identifiers.** They name things. Everything else - connections, enrichments, history - is layered on top, designed separately, shipped when ready.

This keeps the core spec simple and lets us learn before committing to complexity we might get wrong.

---

## Why No UUIDs?

### The Problem

How do you handle name changes? Companies get acquired, products get rebranded, advisory prefixes evolve:

- Red Hat → IBM Red Hat
- VMware → Broadcom VMware
- RHSA-* → hypothetically IBMRHSA-*

If someone wrote `secid:advisory/redhat/errata#RHSA-2024-1234` in a paper, a database, or a tool, what happens when "redhat" becomes "ibmredhat"?

### The UUID Proposal

One solution: give every namespace a stable UUID that never changes.

```
secid:advisory/550e8400-e29b-41d4-a716-446655440000/RHSA-2024-1234
```

The human-readable name ("redhat" or "ibmredhat") becomes just a display label. The UUID is the true identifier. Names can change; UUIDs are forever.

This is how some systems handle stability. It's not wrong.

### Why We Rejected It

**Nobody would use the UUID.**

In practice, people would write:
```
secid:advisory/redhat/errata#RHSA-2024-1234
```

Not:
```
secid:advisory/550e8400-e29b-41d4-a716-446655440000/RHSA-2024-1234
```

The human-readable form is what gets typed, copied, shared, and remembered. The UUID would exist in the spec but sit unused in reality.

This means:
- Added complexity in the spec (now we have UUIDs to manage)
- Added complexity in tooling (resolve UUID ↔ name mappings)
- No actual benefit (people still use names, names still change)

We'd have all the costs of UUIDs with none of the benefits.

### The Better Solution

**Handle succession through relationships, not through opaque IDs.**

When a namespace is renamed:

1. **Both names remain valid identifiers**
   - `secid:advisory/redhat/errata#RHSA-2024-1234` works
   - `secid:advisory/ibmredhat/RHSA-2024-1234` also works

2. **The relationship layer records the change**
   ```
   ibmredhat renamedFrom redhat
   ```

3. **Resolvers follow the chain**
   - Query for `redhat` → find the rename → resolve via `ibmredhat`
   - Old references never break
   - New references use the current name

### The Tradeoffs

| Approach | Pros | Cons |
|----------|------|------|
| **UUIDs** | Theoretically stable | Nobody uses them; added complexity |
| **Relationships** | Human-readable; matches actual usage | Requires relationship layer; resolver must follow chains |

We chose relationships because:
- Identifiers stay human-readable
- Matches how people actually write and share identifiers
- Complexity is in the resolver, not in every identifier string
- Follows the "identifiers are just identifiers" principle

### PURL Precedent

Package URL (PURL) faces the same challenge. Package ecosystems rename, reorganize, get acquired. PURL doesn't use UUIDs either - it uses human-readable names and relies on the ecosystem to handle transitions.

SecID follows the same philosophy.

### Summary

UUIDs solve a real problem (name stability) but in a way that doesn't match how people actually use identifiers. Relationships solve the same problem in a way that keeps identifiers human-readable and lets the infrastructure handle succession.

**Stability through relationships, not through opaque IDs.**

---

## Entity Naming: Follow the Source

### The Principle

When naming entities (vendors, products, services), **use what the owner calls it**.

This applies to:
- Vendor/organization namespaces
- Product and service names within namespaces
- Acronyms and abbreviations

### Why This Matters

**Simplicity**: No need to invent naming schemes. The vendor already named their product.

**Recognizability**: Users searching for "ROSA" should find `entity/redhat/rosa`, not `entity/redhat/openshift-aws-managed-service`.

**Reduced ambiguity**: The vendor's naming is authoritative. We're not guessing.

**Less maintenance**: When the vendor changes names, we follow. We're not maintaining our own parallel naming scheme.

### How It Works

**General concepts use common names:**
```
entity/redhat/openshift     # The OpenShift platform generally
entity/microsoft/windows    # Windows generally
```

**Variants use official product names:**
```
entity/redhat/rosa                # "ROSA" (Red Hat OpenShift Service on AWS)
entity/redhat/aro                 # "ARO" (Azure Red Hat OpenShift)
entity/redhat/openshift-dedicated # "OpenShift Dedicated"
```

Note: `rosa` not `openshift-rosa`. Red Hat calls it "ROSA", so we call it `rosa`.

### Disambiguation

When names collide (rare), use what makes sense:
- Geographic: `company-uk` vs `company-us`
- Parent company: `subsidiary-parentco`
- Product line: whatever the vendor uses

Don't invent generic suffixes like `-product` or `-service`. Use actual names.

### The Exception

If a source genuinely has no usable names (see next section), we may need to create identifiers. But for vendors and their products, follow the source.

---

## Open Question: Sources Without Native Identifiers

### The Problem

Some valuable data sources don't have clean identifiers. Consider:

- A spreadsheet of AI weaknesses with paragraph descriptions but no IDs
- A research database with titles but no short codes
- An incident tracker with timestamps and descriptions only

How do we reference entries in these sources?

### Options Under Consideration

**Option 1: Use titles as-is**
```
weakness/aiweakdb/Buffer-Overflow-in-Memory-Allocation-Functions
```
- **Pro**: Exactly what the source calls it
- **Con**: Long, unwieldy, may need URL encoding, could change if source updates title

**Option 2: Slugify titles**
```
weakness/aiweakdb/buffer-overflow-memory-allocation
```
- **Pro**: URL-safe, readable, shorter
- **Con**: Loses precision, potential collisions, we're now transforming the source name

**Option 3: Content hash**
```
weakness/aiweakdb/a3f2b8c9
```
- **Pro**: Guaranteed unique, stable if content is stable
- **Con**: Meaningless to humans, changes if content changes

**Option 4: Assign sequential IDs**
```
weakness/aiweakdb/AIWD-001
```
- **Pro**: Short, clean, CVE-like
- **Con**: We become the ID authority, not the source. Governance burden.

**Option 5: Use row/position**
```
weakness/aiweakdb/row-42
```
- **Pro**: Traceable to source
- **Con**: Brittle if source reorders, position isn't meaningful

**Option 6: Namespace-defined scheme**
Each namespace documents how it creates IDs. Some might use titles, some hashes, some assigned IDs.
- **Pro**: Flexible, source-appropriate
- **Con**: Inconsistent across namespaces

### Considerations

**Is the source important enough?**
If a source has poor identifiers, maybe we shouldn't be referencing it at a granular level. Reference the source itself, not individual entries.

**Will the source improve?**
If a source might add proper IDs later, using temporary IDs creates migration headaches.

**What's the natural key?**
Most sources have *something* - titles, dates, positions. The most stable natural key is usually best.

**Who maintains the mapping?**
If we assign IDs, we're now responsible for stability. If we use source keys, the source is responsible.

### Current Thinking

1. **Prefer sources with existing IDs** - CWE, CVE, ATT&CK already solved this
2. **For important sources without IDs, use the most stable natural key** - usually title, slugified if needed
3. **Document the scheme in the namespace file** - make it explicit
4. **Accept some messiness** - relationships can help when IDs change
5. **Don't pre-solve** - wait for concrete use cases

### Not Decided

This is an open question. We'll decide when we have a concrete source that requires it, informed by the specifics of that source.

---

## Peer Identifier Schemes

### The Principle

SecID identifies things in the **security knowledge graph** - advisories, weaknesses, controls, entities, TTPs, regulations, and references.

Other identifier schemes handle their domains. We complement them, not replace them.

### Peer Schemes We Defer To

**Established schemes** - canonical, industry-standard identifiers with self-describing string formats:

| Scheme | Identifies | Example | Notes |
|--------|------------|---------|-------|
| `pkg:` | Packages | `pkg:npm/lodash@4.17.21` | PURL - the standard for packages |
| `CVSS:` | Severity scores | `CVSS:4.0/AV:N/AC:L/...` | Self-describing score vectors |
| `spdx:` | Licenses | `spdx:MIT`, `spdx:Apache-2.0` | SPDX license identifiers |
| `doi:` | Research papers | `doi:10.48550/arXiv.2303.08774` | Digital Object Identifiers |
| `swh:` | Source code | `swh:1:cnt:94a9ed...` | Software Heritage immutable refs |

Note: To be a peer scheme, it needs a **self-identifying string format**. Standards that exist but don't have their own identifier syntax (like OWASP AIVSS) are referenced as entities (`secid:entity/owasp/aivss`) rather than peer schemes.

### Why Not Wrap Them?

These schemes are already self-identifying. Writing `secid:package:npm/lodash` when `pkg:npm/lodash` exists would be:
- Redundant
- Confusing (two ways to say the same thing)
- Fighting established standards

Instead, use them as peers:

```yaml
advisory: secid:advisory/mitre/cve#CVE-2024-1234
affects: pkg:pypi/langchain@0.1.0
severity: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H
classified_as: secid:weakness/mitre/cwe#CWE-94
license: spdx:MIT
paper: doi:10.48550/arXiv.2303.08774
```

### Filling Gaps (If Needed)

If a peer scheme has gaps we need to cover, we could create a compatible namespace:

```
secid:license:spdx/MIT              → translates to → spdx:MIT
secid:license:spdx/Custom-Corp-1.0  → covers gap SPDX doesn't have
```

This approach:
- Uses the same values as the peer scheme where they exist
- Extends coverage for things the peer doesn't cover
- Maintains compatibility

We haven't needed this yet. If we do, the namespace file would document the translation.

### Deprecated Schemes

**CPE** (`cpe:2.3:a:vendor:product:...`) - Being phased out. CVE/NVD moving to PURL for affected product identification. We don't plan to support CPE.

---

## AI-First Design

### The Principle

SecID is **AI-first**. The primary consumer is AI agents that need to understand, navigate, and work with security knowledge. Human usability and traditional software integration are important but secondary.

This shapes everything about how we design responses and documentation.

### What AI-First Means

When an AI encounters a SecID like `secid:advisory/redhat/cve#CVE-2026-0544`, it should be able to:

1. **Look it up** - Query the registry or API
2. **Understand what it is** - Not just "a URL" but what kind of data, why it matters, how it differs from alternatives
3. **Know when to use it** - Guidance on when this source is appropriate vs others
4. **Fetch and parse it** - URLs, formats, libraries, code hints
5. **Work with the data** - Prompting hints, key fields to extract, common pitfalls

This is more than metadata. It's **instructions for AI** on how to be effective with security knowledge.

### Registry Format

Registry files use Obsidian-style format: YAML frontmatter + Markdown body.

```yaml
---
namespace: redhat
type: advisory
# ... structured fields
---

# Red Hat Advisory Namespace

[Rich explanatory content for AI/human consumption]

## What This Is
Red Hat CVE pages include their own severity analysis...

## When To Use This
Use this when you need Red Hat-specific impact...

## Parsing Hints
CSAF documents use the VEX profile. Key fields...
```

This format is:
- **Human-readable** - Open in any text editor or Obsidian
- **AI-readable** - Markdown is native to LLMs
- **Machine-parseable** - YAML frontmatter for structured access
- **Git-friendly** - Text diffs work well

### API Responses (Future)

The API will serve registry content in multiple ways:

1. **As-is** - Return the Markdown file directly (AI-native)
2. **JSON** - Structured format for traditional software integration

Both return the same information. JSON provides schemas and programmatic access for systems that need it.

### Not Everything Has a URL

Some SecIDs identify concepts or entities that don't have a canonical URL:
- An organization that has no website
- A defunct product
- An emerging standard not yet published

These entries still provide value through explanatory text, relationships, and context - even without a resolvable URL. We prefer URLs when available (less to maintain), but don't require them.

### Example: What AI Gets

Query: `secid:advisory/redhat/cve#CVE-2026-0544`

Response includes:
- **what**: "Red Hat's analysis of this CVE. Unlike the upstream CVE record, includes Red Hat severity rating, affected product matrix, and RHEL/OpenShift-specific remediation."
- **when_to_use**: "Use for Red Hat-specific impact. For canonical description, use secid:advisory/mitre/cve#CVE-2026-0544."
- **urls**: Links to HTML page, CSAF/VEX JSON, API endpoint
- **parsing**: "CSAF uses VEX profile. Python: `pip install csaf`. Key fields: `/vulnerabilities/[]/product_status/fixed`"
- **ai_guidance**: "Red Hat severity may differ from NVD CVSS - both are valid perspectives representing different risk contexts."

The AI can now autonomously fetch, parse, interpret, and explain this data.

### Why AI-First?

Security knowledge is complex, fragmented, and constantly evolving. Humans struggle to navigate it. Traditional software can parse it but can't understand context.

AI can do both - but only if we give it the context it needs. SecID is building the foundation for AI agents that genuinely understand security, not just process security data.

