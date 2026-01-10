# SecID Implementation Roadmap

This document describes what we're building, in what order, and why - including how the building process itself teaches us about the problem space.

## What We're Building

SecID isn't just a spec - it's a stack of capabilities built on that spec:

```
┌─────────────────────────────────────────────────┐
│  Applications (future)                          │
│  - AI vulnerability database                    │
│  - Security knowledge graph UI                  │
│  - Cross-database search                        │
├─────────────────────────────────────────────────┤
│  Enrichment & Analysis                          │
│  - Gap analysis (what's missing?)               │
│  - Quality scoring                              │
│  - Trend detection                              │
├─────────────────────────────────────────────────┤
│  Overlays                                       │
│  - Normalization (clean up messy data)          │
│  - Cross-references (link related things)       │
│  - Warnings (flag issues)                       │
├─────────────────────────────────────────────────┤
│  Relationships                                  │
│  - CVE ↔ GHSA ↔ OSV aliases                     │
│  - CVE → CWE weakness mappings                  │
│  - Weakness → Control mitigations               │
│  - Technique → Weakness exploits                │
├─────────────────────────────────────────────────┤
│  Entity Registry                                │
│  - Organizations, databases, standards          │
│  - Products, frameworks, tools                  │
│  - Ecosystem participation declarations         │
├─────────────────────────────────────────────────┤
│  Specification                                  │
│  - Identifier format                            │
│  - Ecosystem definitions                        │
│  - Naming conventions                           │
└─────────────────────────────────────────────────┘
```

Each layer builds on the one below. We're starting from the bottom.

## Phased Approach: Two Parallel Tracks

**Identifiers are just identifiers.** We're building in two parallel tracks:

### Track 1: Content & Data

| Phase | Focus | Status |
|-------|-------|--------|
| **1.1** | Specification | **Current** |
| **1.2** | Registry (namespaces, seed data) | **Current** |
| **1.3** | Relationship Layer | Planned - design informed by usage |
| **1.4** | Overlay Layer | Planned - design informed by usage |
| **1.5** | Applications (knowledge graph UI, cross-database search) | Future |

### Track 2: Technical Components

| Phase | Focus | Status |
|-------|-------|--------|
| **2.1** | Parser libraries (Python, JavaScript, Go, etc.) | Planned |
| **2.2** | Validators (schema, format, duplicate detection) | Planned |
| **2.3** | CLI tools (parse, validate, resolve) | Planned |
| **2.4** | API (REST/GraphQL for registry and resolution) | Planned |
| **2.5** | Resolution service (SecID → URL/resource) | Future |

### How the Tracks Interact

```
Content Track:     Spec ──→ Registry ──→ Relationships ──→ Overlays ──→ Applications
                     │         │              │               │              │
                     ▼         ▼              ▼               ▼              ▼
Technical Track:  Parsers ──→ Validators ──→ CLI ─────────→ API ─────────→ Resolution
```

The tracks reinforce each other:
- Parsers enable people to use SecIDs in their tools
- Validators ensure registry quality
- API makes the registry programmatically accessible
- Applications consume both content and technical components

### Why Defer the Data Layers?

The relationship and overlay layers involve design decisions that benefit from real-world usage:

- **Directionality**: Are relationships one-way or bidirectional?
- **Cardinality**: One-to-one, one-to-many, many-to-many?
- **Provenance**: Who asserted this? When? Based on what?
- **Conflict resolution**: What if two sources disagree?
- **Storage format**: JSONL? Graph database? SQLite?

Rather than guess upfront, we're building the identifier system and registry first. Actual usage will reveal:
- What relationships people actually need
- What enrichments are most valuable
- Where conflicts arise and how to resolve them

See [RELATIONSHIPS.md](RELATIONSHIPS.md) and [OVERLAYS.md](OVERLAYS.md) for current thinking on these layers.

## Future Layers (Design Pending)

### Relationship Layer

The spec is just syntax. The real value will come from relationships - connecting CVEs to GHSAs, weaknesses to controls, techniques to mitigations.

Without relationships, we're just another list. With relationships, we'd enable:
- "Show me all SQL injection vulns in Python packages"
- "What controls mitigate this ATT&CK technique?"
- "Which CVEs have GHSA but no NVD enrichment?"

**Status**: Deferred until usage informs design. See [RELATIONSHIPS.md](RELATIONSHIPS.md) for exploratory thinking.

### Overlay Layer

Overlays would let us improve data without modifying sources - adding cross-references, flagging quality issues, supplementing delayed enrichment.

**Status**: Deferred until usage informs design. See [OVERLAYS.md](OVERLAYS.md) for exploratory thinking.

### Why We're Waiting

These layers involve design decisions that benefit from real-world usage:
- Directionality and cardinality
- Provenance and conflict resolution
- Storage formats and query patterns

Rather than guess, we're building the identifier system and registry first. Usage will teach us what's actually needed.

## Initial Entity Seeding Strategy

### Why Start with Hundreds/Thousands of Entities?

The initial seeding serves multiple purposes:

1. **Stress test the spec**: Do our naming conventions hold up? Are there edge cases we missed?

2. **Learn the landscape**: What databases exist? How do they relate? What's the coverage?

3. **Build the graph**: Relationships need entities on both ends. More entities = richer graph.

4. **Demonstrate value**: A spec with 10 examples is theoretical. A spec with 1000 entities is useful.

5. **Attract contributors**: People contribute to living projects, not empty frameworks.

### Seeding Phases

**Phase 1: Core Security Infrastructure (50-100 entities)**

The foundations everything else references:

| Category | Examples | Why First |
|----------|----------|-----------|
| Vuln databases | CVE, NVD, GHSA, OSV, CNVD, EUVD | Core references |
| Weakness taxonomies | CWE, OWASP Top 10 | Vulnerability classification |
| Attack frameworks | ATT&CK, ATLAS, CAPEC | Threat modeling |
| Scoring systems | CVSS, EPSS | Severity/priority |
| Organizations | MITRE, NIST, FIRST, OWASP | Governance/authority |

*Status: Largely complete in current files*

**Phase 2: AI/ML Security Ecosystem (100-200 entities)**

Deep coverage of AI security landscape:

| Category | Examples | Why |
|----------|----------|-----|
| AI vendors | OpenAI, Anthropic, Google, Meta | Products to track |
| AI products | GPT-4, Claude, Gemini, Llama | Vulnerability targets |
| AI frameworks | LangChain, LlamaIndex, AutoGPT | Supply chain |
| AI security tools | Garak, PyRIT, Promptfoo | Testing ecosystem |
| AI standards | NIST AI RMF, ISO 42001 | Compliance landscape |
| AI research | Adversarial ML papers, jailbreak repos | Knowledge sources |

*Why prioritize AI?* This is our eventual differentiator. Deep AI coverage establishes expertise.

**Phase 3: Vendor Security Programs (200-500 entities)**

Major vendors and their security infrastructure:

| Category | Examples | Why |
|----------|----------|-----|
| Vendor PSIRTs | Microsoft, Google, Red Hat, Cisco | Advisory sources |
| Bug bounty programs | HackerOne, Bugcrowd hosted programs | Disclosure channels |
| Vendor advisories | MSRC, RHSA, DSA | Enrichment sources |
| Cloud security | AWS Security Hub, Azure Defender | Platform-specific |

*Why vendors?* Vendor advisories are a massive source of vulnerability data that often has richer context than NVD.

**Phase 4: Broader Security Ecosystem (500-1000+ entities)**

Long tail of security knowledge:

| Category | Examples | Why |
|----------|----------|-----|
| Security tools | Nmap, Metasploit, Burp Suite | Referenced in vulns |
| Security standards | PCI-DSS, HIPAA, SOC 2 | Compliance mapping |
| Threat intel | MISP, OpenCTI, threat feeds | Future: threat intelligence |
| Research groups | Google P0, Microsoft MSTIC | Attribution |
| Conferences | DEF CON, Black Hat, RSA | Community nodes |

### What We Learn From Seeding

The act of adding entities teaches us:

**Naming edge cases:**
- What about `AT&T`? → `att` (remove special chars)
- What about `CERT/CC` vs `US-CERT`? → Need aliasing strategy
- What about acquired companies? → Historical entities need tracking

**Relationship patterns:**
- Most vulns have CWE mappings... AI vulns are newer and still being classified
- GHSA cross-references CVE... except for ecosystem-specific issues
- Multiple sources may provide different severity assessments... need reconciliation tracking

**Coverage status:**
- CWE has 4 AI-specific entries (e.g., CWE-1427 for prompt injection), gaps remain
- ATT&CK and ATLAS continue expanding
- AI security taxonomies are still maturing

**Data quality observations:**
- Processing backlogs can delay enrichment data
- Cross-references between databases occasionally need correction
- Different sources may assess severity differently

This learning feeds back into spec refinement and overlay priorities.

## Concrete Deliverables

### Near-term (Building Now)

1. **Entity registry**: 50+ core entities with rich documentation
2. **Relationship seed**: Manual CVE↔GHSA↔CWE mappings for ~100 vulns
3. **Spec validation**: Confirm naming conventions work for edge cases

### Medium-term (Next Phase)

1. **Automated harvesting**: Scripts to extract relationships from GHSA, OSV
2. **Framework mappings**: OWASP LLM Top 10 ↔ ATLAS ↔ CWE
3. **Overlay infrastructure**: Format and storage for overlays
4. **500+ entities**: Cover AI ecosystem comprehensively

### Longer-term (Future Phases)

1. **Web interface**: Browse and search the knowledge graph
2. **API**: Programmatic access to entities and relationships
3. **AI vulnerability database**: New vulnerability data for AI-specific issues
4. **Community contributions**: External entity/relationship PRs

## Success Indicators

How we know the seeding is working:

| Indicator | Meaning |
|-----------|---------|
| Naming conventions stable | No major spec changes needed |
| Relationships form clusters | Graph has meaningful structure |
| Edge cases documented | Spec handles exceptions gracefully |
| External interest | Others want to contribute entities |
| Queries work | Can answer real security questions |

## Open Questions for Seeding

Things we'll learn as we add entities:

1. **Versioning**: How to handle when NVD API changes?
2. **Deprecation**: What happens when a database shuts down?
3. **Conflicts**: What if GHSA and NVD disagree on CVE mapping?
4. **Automation balance**: How much can be auto-generated vs curated?
5. **Update frequency**: How often do entity files need refresh?

These will be answered empirically, not theoretically.

