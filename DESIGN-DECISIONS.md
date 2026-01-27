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

## Namespace Transitions: Case by Case

### The Problem

What happens when organizations change? Companies get acquired, rebrand, merge, or shut down:
- Red Hat acquired by IBM
- VMware acquired by Broadcom
- Sun Microsystems absorbed into Oracle

If someone wrote `secid:advisory/redhat/errata#RHSA-2024:1234`, what happens when Red Hat's organizational structure changes?

### Why We Don't Pre-Design This

The temptation is to design a comprehensive namespace transition system upfront. But real-world transitions are messy and unpredictable:

**Example: IBM acquires Red Hat**

IBM acquired Red Hat, but:
- Red Hat brand continues
- Red Hat security infrastructure unchanged
- RHSA/RHBA/RHEA identifiers still work
- CVE database still at access.redhat.com

Nothing needed to change in SecID. If we'd pre-built a transition system, we'd have built for a problem that didn't materialize.

**Contrast: If IBM fully absorbed Red Hat**

If IBM killed the Red Hat brand and migrated everything to IBM infrastructure:
- Old `secid:advisory/redhat/*` identifiers stay valid forever (like old URLs)
- New advisories use `secid:advisory/ibm/*`
- Relationship layer records: `ibm/errata renamedFrom redhat/errata`
- Resolvers follow the chain

### The Approach

**Handle transitions when they happen, not before.**

1. **Old identifiers are forever** - Once a SecID exists, it exists. We don't break existing references.

2. **New structure gets new identifiers** - If an organization fundamentally changes, new namespaces reflect the new reality.

3. **Relationships connect old and new** - The relationship layer (when built) handles `renamedFrom`, `succeeds`, `aliases`.

4. **Case by case decisions** - Each transition is unique. We evaluate when it happens, with real information, not hypotheticals.

### What About Retired Standards?

A standard being retired is enrichment data, not a namespace change:
- The namespace still exists (historical references remain valid)
- The enrichment layer notes: "retired as of 2024, superseded by X"
- We might also note: "still widely used despite retirement" or "effectively replaced by Y even though not officially retired"

This is metadata about the thing, not a change to its identity.

### Why This Works

This approach mirrors how the internet handles domain changes and URL transitions. Old URLs don't disappear - they redirect, return 404, or keep working. The web is littered with historical references that still resolve.

SecID follows the same philosophy: identifiers are stable, context is layered on top.

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

## Security Tools: Entity + Control Pattern

### The Principle

Security tools that provide security checks should be documented in **both** entity and control:

| Type | What it documents | Example content |
|------|-------------------|-----------------|
| `entity` | What the tool IS | Product description, capabilities, access methods |
| `control` | What security checks it PROVIDES | Specific checks, detections, mappings |

### Why Two Files?

A security scanner is both a **thing** (software you can install, an API you can call) and a **source of security checks** (detections, validations, tests).

Consider MCPShark Smart Scan:
- As an **entity**: It's a security scanner with CLI, API, and dashboard access methods
- As a **control source**: It provides specific security checks like `agent-analysis`, `privilege-escalation-detection`, `owasp-mapping`

Users might want to:
1. Reference the tool itself → `secid:entity/mcpshark/smart`
2. Reference a specific security check the tool provides → `secid:control/mcpshark/smart#agent-analysis`

Both are valid, different use cases.

### How It Works

**Entity file** (`registry/entity/<vendor>/<tool>.md`):
- What the tool is and does
- Access methods (CLI, API, dashboard)
- Integration capabilities (CI/CD, webhooks)
- What it scans (targets, formats)

**Control file** (`registry/control/<vendor>/<tool>.md`):
- Security checks as `#subpath` identifiers
- Check descriptions and categories
- Mappings to standards (OWASP, CIS, etc.)
- Severity levels and remediation guidance

### Example: MCPShark Smart Scan

```
secid:entity/mcpshark/smart                        → The Smart Scan tool itself
secid:control/mcpshark/smart#agent-analysis        → Agent security assessment check
secid:control/mcpshark/smart#owasp-mapping         → OWASP LLM Top 10 mapping check
secid:control/mcpshark/smart#privilege-escalation-detection → Privilege escalation detector
```

### This Pattern Applies To

Any security tool with defined checks:
- **Vulnerability scanners**: Trivy, Grype, Snyk
- **SAST tools**: Semgrep, CodeQL
- **Cloud security**: Prowler, ScoutSuite
- **AI/MCP scanners**: MCPShark Smart Scan
- **Compliance scanners**: OpenSCAP, InSpec

### Related Pattern: Weakness + Control Pairing

Some frameworks define both weaknesses AND controls (like OWASP AI Exchange):

```
secid:weakness/owasp/ai-exchange#DIRECTPROMPTINJECTION     → The threat
secid:control/owasp/ai-exchange#PROMPTINJECTIONIOHANDLING  → The mitigation
```

Document in both types when the source provides both perspectives.

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

---

## Unified `secid:` Scheme

### The Decision

SecID uses a single scheme (`secid:`) with multiple types, rather than separate schemes per type.

We chose:
```
secid:advisory/mitre/cve#CVE-2024-1234
secid:weakness/mitre/cwe#CWE-79
secid:control/nist/csf@2.0#PR.AC-1
```

Over alternatives like:
```
advisory:mitre/cve#CVE-2024-1234
weakness:mitre/cwe#CWE-79
control:nist/csf@2.0#PR.AC-1
```

### Why Unified?

**PURL grammar compatibility.** PURL uses `pkg:type/namespace/name`. We use `secid:type/namespace/name`. Same grammar, different scheme. This means existing PURL tooling and mental models transfer directly.

**Branding and searchability.** `secid:` is a consistent prefix. You can search a codebase for `secid:` and find all security identifier references. With type-as-scheme, you'd need to know all the schemes.

**No premature fragmentation.** We don't know yet which types will grow large enough to warrant their own scheme. Starting unified means we can split later with data, not speculation.

**Simpler tooling.** One scheme to parse, validate, and resolve. One regex pattern. One URL handler.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| **Unified `secid:`** (chosen) | PURL compatibility, searchable, simple | Less type-specific |
| **Type-as-scheme** (`advisory:`, `weakness:`) | Shorter identifiers | Fragments tooling, multiple schemes to register |
| **Hybrid** (split later) | Flexibility | Complexity when/if we split |
| **Registry-as-scheme** (`corpid:`, `secid:`) | Federation | Loses unified search |

### Future Flexibility

If a type grows significantly beyond security scope (e.g., a generic `conference:` scheme), we can split it off. Criteria for splitting:

- Type becomes >50% non-security content
- Clear community that doesn't need security context
- Branding confusion ("why is my conference talk a security ID?")

Until then, we stay unified.

### What About Aliases?

If someone wants `advisory:mitre/cve#CVE-2024-1234` to work alongside `secid:advisory/mitre/cve#CVE-2024-1234`, that's an **enrichment layer concern**, not a spec concern. The enrichment database can store:

```yaml
secid:advisory/mitre/cve#CVE-2024-1234:
  sameAs:
    - advisory:mitre/cve#CVE-2024-1234
    - cve:CVE-2024-1234
    - https://cve.org/CVERecord?id=CVE-2024-1234
```

The spec defines one canonical form. Aliases are data.

---

## Qualifiers Are for Disambiguation, Not Metadata

### The Principle

PURL qualifiers (`?key=value`) exist for **disambiguation**—distinguishing between two otherwise-identical things. They are not a general-purpose metadata store.

### Appropriate Use

```
pkg:npm/lodash@4.17.21?arch=x86_64       # Same package, different architecture
secid:advisory/vendor/product?lang=ja    # Same advisory, Japanese translation
```

The qualifier changes *which specific thing* you're identifying.

### Anti-Pattern: Metadata in Qualifiers

```
# DON'T DO THIS
secid:talk/defcon/32#hacking-iot?speaker=John%20Smith&time=2026-08-05T14:00&room=101&rating=5
```

This is tempting but wrong:

**1. Identifiers become unstable.** Speaker name spelled wrong? Time changed? Now your identifier changed.

**2. No canonical form.** Is it `speaker` or `presenter` or `talk_giver`? Everyone picks differently.

**3. Encoding nightmare.** `"Dr. José O'Brien-Smith, PhD"` in a URL qualifier is painful.

**4. Defeats the purpose.** If the identifier contains all the data, why have a data layer?

**5. Bloated identifiers.** URLs become unreadable, uncopyable, unloggable.

### The Rule

**The identifier is the minimal unique handle. Everything else goes in the data layer.**

```
# The identifier
secid:talk/defcon/32#smith-hacking-iot

# The data layer
secid:talk/defcon/32#smith-hacking-iot:
  speaker: "John Smith"
  title: "Hacking IoT: A Deep Dive"
  scheduled: "2026-08-05T14:00Z"
  room: "Mandalay Bay L"
```

The identifier doesn't change when metadata is corrected. The data layer can be updated, enriched, and queried without touching the identifier.

---

## Follow the Source for Subpaths

### The Principle

When referencing specific items within a database or framework, **use whatever identifier the source uses**.

### How It Works

If BlackHat's schedule uses `talk-2847`:
```
secid:talk/blackhat/2026#talk-2847
```

If their website uses URL slugs like `/briefings/smith-hacking-iot`:
```
secid:talk/blackhat/2026#smith-hacking-iot
```

If CVE uses `CVE-2024-1234`:
```
secid:advisory/mitre/cve#CVE-2024-1234
```

### Why This Matters

**Stability.** The source's identifiers are stable (or at least, the source is responsible for stability, not us).

**Traceability.** You can look at the identifier and find the source directly.

**No governance burden.** We're not inventing and maintaining a parallel ID system.

**Recognition.** Users familiar with the source recognize the identifiers.

### What If There's No Good ID?

Some sources don't have clean identifiers. See "Open Question: Sources Without Native Identifiers" above. The short answer: prefer sources with IDs, use the most stable natural key when forced, and document the scheme.

### Don't Invent When You Don't Need To

The temptation is to create our own cleaner, shorter, more consistent IDs. Resist it. The source's messy IDs are the source's problem. Our job is to point to them reliably.

---

## Reference System, Not Numbering Authority

### The Principle

**SecID provides a grammar and registry for referencing security knowledge. SecID does not assign identifiers—those come from their respective authorities.**

This is a deliberate, foundational constraint.

### What This Means

| SecID Does | SecID Does NOT Do |
|------------|-------------------|
| Provide a grammar (`secid:type/namespace/name#subpath`) | Assign CVE-2024-1234 (MITRE does that) |
| Maintain a registry of identifier *systems* | Assign GHSA-xxxx-yyyy (GitHub does that) |
| Define how to reference existing identifiers | Assign CWE-79 (MITRE does that) |
| Resolve identifiers to URLs | Assign AVID-2025-V001 (AVID does that) |

### The PURL Analogy

This mirrors how Package URL (PURL) works:
- PURL doesn't assign `lodash@4.17.21` — npm does
- PURL provides `pkg:npm/lodash@4.17.21` as a consistent reference

Similarly:
- SecID doesn't assign `CVE-2024-1234` — MITRE does
- SecID provides `secid:advisory/mitre/cve#CVE-2024-1234` as a consistent reference

### "I Have a Vulnerability and Need an ID"

If someone asks SecID to assign an identifier for their vulnerability, the answer is:

> "SecID can't help with that directly. You need to get an identifier from an appropriate authority:
> - **CVE**: Request from MITRE or a CNA
> - **GHSA**: Report through GitHub Security Advisories
> - **AVID**: Submit to the AI Vulnerability Database
> - **Your own system**: Create your own advisory namespace with your own IDs
>
> Once your advisory has an identifier from an authority, SecID provides a consistent way to reference it. If you create 'FooSec Advisories' with ID 'FSA-2025-001', we can add your namespace to the registry, and `secid:advisory/foosec/fsa#FSA-2025-001` becomes a valid reference."

### Why This Constraint?

**1. Separation of concerns.** Assigning identifiers and referencing identifiers are different jobs requiring different governance structures. Mixing them creates conflicts.

**2. Respect for authorities.** MITRE, NIST, OWASP, and others have earned authority in their domains through years of work. SecID complements them, not competes.

**3. Avoiding scope creep.** If SecID assigned IDs, we'd need:
   - Policies for what qualifies
   - Dispute resolution processes
   - Editorial review
   - Long-term maintenance commitments

   That's a different project.

**4. Enabling trust.** Organizations can adopt SecID knowing it won't try to become a competing authority in their domain.

### What If We Need an AI Vulnerability Database?

If the security community needs a new identifier system (e.g., for AI vulnerabilities not covered by existing authorities), that should be a separate project with its own governance. SecID would then reference it, just like we reference CVE, GHSA, and AVID.

The clean separation: SecID is the grammar and registry for referencing. Identifier assignment is someone else's job.

---

## Registry Architecture: Hierarchical, One File Per Namespace

### The Principle

The registry uses a flat, hierarchical structure where **every level is queryable** and **each namespace is a single file** containing all its sources.

### The Hierarchy

```
secid:advisory                          → registry/advisory.md
secid:advisory/redhat                   → registry/advisory/redhat.md
secid:advisory/redhat/cve               → section within redhat.md
secid:advisory/redhat/cve#CVE-2026-1234 → resolved URL from rules in redhat.md
```

Every level returns useful information:

| Query | Returns |
|-------|---------|
| `secid:advisory` | Type definition — what advisories are |
| `secid:advisory/redhat` | Namespace definition — what Red Hat publishes |
| `secid:advisory/redhat/cve` | Source definition — Red Hat CVE pages, root URL |
| `secid:advisory/redhat/cve#CVE-2026-1234` | Resolved URL to specific entry |

### File Structure

```
registry/
  advisory.md                 ← Type definition (what is an advisory?)
  advisory/
    redhat.md                 ← Namespace: ALL Red Hat sources in ONE file
    mitre.md                  ← Namespace: MITRE CVE
    github.md                 ← Namespace: GHSA
  weakness.md                 ← Type definition (what is a weakness?)
  weakness/
    mitre.md                  ← Namespace: CWE
    owasp.md                  ← Namespace: ALL OWASP taxonomies in ONE file
  control.md                  ← Type definition
  control/
    nist.md                   ← Namespace: ALL NIST frameworks in ONE file
    iso.md                    ← Namespace: ALL ISO standards in ONE file
  entity.md                   ← Type definition
  entity/
    redhat.md                 ← Organization definition
    mitre.md                  ← Organization definition
```

### Why One File Per Namespace (No Subdirectories)

**Rejected alternative:**
```
registry/advisory/redhat/_index.md
registry/advisory/redhat/cve.md
registry/advisory/redhat/errata.md
```

**Why we don't do this:**

1. **Most namespaces have few sources.** Red Hat has ~4 (cve, errata, bugzilla). MITRE has ~1 (cve). Splitting into multiple files adds complexity without benefit.

2. **KV store simplicity.** The API uses a key-value store. One namespace = one key = one file. No need to reassemble multiple files.

3. **All rules in one place.** When maintaining a namespace, everything is in one file — no hunting across subdirectories.

4. **Future scaling.** If the directory gets too full, use alphabetical subdirectories (`registry/advisory/r/redhat.md`), not per-source files.

### Namespace File Format

Each namespace file contains:
- Frontmatter with namespace metadata
- Sections for each source with ID patterns and URL templates
- Narrative documentation

```yaml
---
namespace: redhat
full_name: "Red Hat"
website: "https://redhat.com"
type: vendor
status: active
---

# Red Hat (Advisory Namespace)

Red Hat provides multiple advisory and vulnerability tracking systems.

## Sources

### cve

Red Hat CVE pages with Red Hat-specific severity analysis.

| Field | Value |
|-------|-------|
| id_pattern | `CVE-\d{4}-\d{4,}` |
| url_template | `https://access.redhat.com/security/cve/{id}` |
| example | `secid:advisory/redhat/cve#CVE-2025-10725` |

### errata

Red Hat Errata advisories (RHSA, RHBA, RHEA).

| Field | Value |
|-------|-------|
| id_pattern | `RH[SBEA]A-\d{4}:\d+` |
| url_template | `https://access.redhat.com/errata/{id}` |
| example | `secid:advisory/redhat/errata#RHSA-2025:1234` |
```

### KV Store Design

The API uses a simple key-value lookup:

```
Request: secid:advisory/redhat/cve#CVE-2025-1234

1. Parse: type=advisory, namespace=redhat, name=cve, subpath=CVE-2025-1234
2. KV lookup: key="advisory/redhat" → returns redhat.md content
3. Find "cve" section, get id_pattern and url_template
4. Validate subpath against id_pattern
5. Apply url_template: https://access.redhat.com/security/cve/CVE-2025-1234
```

For type queries:
```
Request: secid:advisory

1. Parse: type=advisory (no namespace)
2. KV lookup: key="advisory" → returns advisory.md content
3. Return type definition
```

### Regex Patterns: PCRE2 Safe Subset

ID patterns use **PCRE2** syntax with a safe subset for compatibility.

#### Why PCRE2, Not PCRE (PCRE1)?

PCRE2 is the successor to the original PCRE library. We chose PCRE2 because:

| Aspect | PCRE1 | PCRE2 |
|--------|-------|-------|
| **Maintenance** | Deprecated since 2017 | Actively maintained |
| **Security** | Had various CVEs over time | Improved security, better fuzzing |
| **API** | Complex, inconsistent | Cleaner, more consistent API |
| **Unicode** | Bolt-on support | Native Unicode support (UTF-8/16/32) |
| **JIT** | Optional, separate | Built-in JIT compiler |
| **Memory** | Static limits | Dynamic memory management |
| **Backtracking** | Harder to control | Better ReDoS protection |

**Key reasons for SecID:**

1. **Industry convergence** - Python 3.11+ uses PCRE2 internally, PHP 7.3+ uses PCRE2, many modern tools default to it
2. **ReDoS protection** - Better backtracking limits prevent regex denial-of-service attacks
3. **Future-proof** - PCRE1 is end-of-life; specifying PCRE2 aligns with where implementations are going
4. **Unicode-native** - Security identifiers increasingly include international characters

#### The Safe Subset

We use a **safe subset** of PCRE2 for maximum compatibility:

- **Works in**: Python `re`, JavaScript, Go `regexp`, Rust `regex`, Java `Pattern`
- **Avoid**: lookahead/lookbehind, backreferences, possessive quantifiers, recursive patterns
- **Goal**: Simple patterns that work everywhere, no regex DoS risk

Most patterns are straightforward:
```
CVE-\d{4}-\d{4,}
CWE-\d+
T\d{4}(\.\d{3})?
RH[SBEA]A-\d{4}:\d+
GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}
```

The safe subset will be formally defined after stress-testing with real-world patterns. The principle: if a pattern requires advanced PCRE2 features, it's probably too complex for an ID pattern.

### Enrichment and Relationship Data

Enrichment and relationship data live in **separate repositories**, not in the SecID registry:

```
secid-registry/           ← This repo: identifiers and resolution
  registry/
    advisory/redhat.md

secid-data/               ← Separate repo: enrichment data
  advisory/
    redhat/
      cve/
        CVE-2025-1234.md  ← Enrichment for specific CVE

secid-relationships/      ← Separate repo: relationship data
  ...
```

**Why separate?**

1. **Different update cadences.** Registry changes rarely; enrichment data changes constantly.
2. **Different governance.** Registry is curated; enrichment may be community-contributed.
3. **Different sizes.** Registry is small (~hundreds of files); enrichment could be millions.
4. **Clean separation.** Follows "identifiers are just identifiers" principle.

