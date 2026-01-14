# SecID Future Vision: Federated Knowledge Infrastructure

**Status**: Internal discussion document
**Date**: January 2025
**Distribution**: Limited - CSA internal

---

## Executive Summary

SecID started as an identifier scheme for security knowledge. This document explores a broader vision: **SecID as the identity layer for a federated knowledge graph with AI-native capabilities**.

The core insight is simple:

1. **Identifier schema** - Stable references using PURL grammar
2. **Overlay data from multiple sources** - Public, organizational, personal
3. **Conflicts are features, not bugs** - Disagreements are signals, not errors

Everything else follows from these three principles.

---

## The Foundation: What SecID Already Provides

SecID provides stable, canonical identifiers for security knowledge:

```
secid:advisory/mitre/cve#CVE-2024-1234
secid:weakness/mitre/cwe#CWE-79
secid:control/nist/800-53@r5#AC-1
secid:ttp/mitre/attack#T1059.003
```

The grammar is PURL-compatible: `secid:type/namespace/name[@version][?qualifiers][#subpath]`

**Current types**: advisory, weakness, ttp, control, regulation, entity, reference

**Current capability**: Given an identifier, resolve to URL(s) where the resource lives.

---

## The Evolution: Entity as Universal Reference

### Expanding Entity Scope

The `entity` type currently covers organizations, products, and services. We expand it to cover **anything that needs to be referenced**:

| What | Example |
|------|---------|
| Organizations | `secid:entity/mitre` |
| Products | `secid:entity/redhat/rhel` |
| Services | `secid:entity/aws/s3` |
| **Concepts** | `secid:entity/glossary/model-context-protocol` |
| **Definitions** | `secid:entity/mitre/vulnerability` |

### Concepts as Entities

General knowledge concepts get a `glossary` namespace:

```
secid:entity/glossary/model-context-protocol
secid:entity/glossary/prompt-injection
secid:entity/glossary/retrieval-augmented-generation
secid:entity/glossary/agent-to-agent-protocol
```

Aliases handled in registry:
```yaml
id: model-context-protocol
aliases: [MCP, "Model Context Protocol"]
```

In documentation: `[MCP](secid:entity/glossary/model-context-protocol)`

### Definitions as Entities

Different organizations define the same terms differently. Make this explicit:

```
secid:entity/mitre/vulnerability      # MITRE's broad definition
secid:entity/redhat/vulnerability     # Red Hat's operational definition
secid:entity/nist/vulnerability       # NIST's definition
```

**Example**: MITRE scores an NFS vulnerability as CRITICAL (remote code execution). Red Hat scores it MEDIUM (their threat model assumes NFS isn't internet-exposed per hardening guidelines). Both are valid within their definition of "vulnerability."

This disagreement is now **referenceable data**:

```yaml
secid: secid:advisory/mitre/cve#CVE-2024-XXXX
severity:
  - definition: secid:entity/mitre/vulnerability
    score: CRITICAL
    rationale: "Remote code execution, no auth required"
  - definition: secid:entity/redhat/vulnerability
    score: MEDIUM
    rationale: "Requires NFS exposure to untrusted networks"
```

### Subpaths as Perspectives

The subpath component enables multiple views of the same concept:

```
secid:entity/glossary/model-context-protocol           # The concept
secid:entity/glossary/model-context-protocol#security  # Security perspective
secid:entity/glossary/model-context-protocol#wikipedia # External reference
secid:entity/glossary/model-context-protocol#roadmap   # Future direction
```

---

## The Data Layer: Federated Overlays

### Multiple Registries, One Identifier

The same SecID can resolve against multiple data sources:

```
┌─────────────────────────────────────────────────────────────┐
│                     SecID Identifier                        │
│           secid:entity/glossary/model-context-protocol      │
└─────────────────────────────────────────────────────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
    ┌──────────┐      ┌──────────┐      ┌──────────┐
    │  Public  │      │   Org    │      │ Personal │
    │ Registry │      │ Registry │      │ Registry │
    ├──────────┤      ├──────────┤      ├──────────┤
    │ canonical│      │ internal │      │ my notes │
    │ url, desc│      │ assessment│     │ research │
    │          │      │ risk: HIGH│      │ links    │
    └──────────┘      └──────────┘      └──────────┘
```

### What Each Layer Contributes

| Layer | Contains | Example |
|-------|----------|---------|
| **Public** | Canonical data, URLs, shared definitions | Wikipedia link, official docs |
| **Organization** | Internal assessments, policies, incidents | "CSA rates HIGH for enterprise" |
| **Personal** | Your research, notes, predictions | Conversation links, GitHub repos |

### Merge Semantics

Client software merges data from configured sources:

```json
{
  "secid": "secid:entity/glossary/model-context-protocol",
  "sources": {
    "public": {
      "description": "Protocol for LLM-tool integration",
      "canonical_url": "https://modelcontextprotocol.io/"
    },
    "csa-internal": {
      "risk_level": "HIGH",
      "assessment": "Tool injection risks significant for enterprise"
    },
    "personal": {
      "notes": "Need to investigate auth layer requirements",
      "research_links": ["https://github.com/...", "https://claude.ai/share/..."]
    }
  }
}
```

---

## The Key Insight: Conflicts Are Signals

### Traditional Approach (Wrong)

Most systems try to resolve conflicts:
- Pick one authoritative source
- Merge into single "truth"
- Hide disagreements from users

This loses information.

### Our Approach (Right)

Conflicts are **valuable data**:

```json
{
  "secid": "secid:entity/glossary/model-context-protocol",
  "conflicts": [
    {
      "field": "risk_level",
      "values": {
        "public": "MEDIUM",
        "csa-internal": "HIGH"
      },
      "explanation": "CSA rates higher due to enterprise deployment context"
    }
  ]
}
```

**For AI**: "There are two perspectives on risk. Public sources say MEDIUM, but CSA's internal assessment is HIGH because they're considering enterprise deployment scenarios where the attack surface is larger."

**For humans**: Dashboard shows both ratings with context, not a false single answer.

### Why This Matters

- **Different contexts, different truths** - MITRE and Red Hat both have valid vulnerability definitions
- **Expertise surfaces** - Your personal notes might catch something public sources missed
- **Transparency** - Users see where information comes from
- **AI reasoning** - AI can explain nuance instead of false confidence

---

## Knowledge Graph Integration

### SecID as Node Identity

Knowledge graph nodes are tagged with SecIDs:

```yaml
node:
  secid: secid:entity/glossary/model-context-protocol
  properties:
    type: protocol
    vendor: Anthropic
    status: emerging
  source: public
```

### Edges Reference SecIDs

Relationships connect SecID-identified nodes:

```yaml
edge:
  from: secid:entity/glossary/model-context-protocol
  to: secid:weakness/owasp/llm-top10@2.0#LLM01
  relationship: vulnerable-to
  properties:
    attack_vector: tool-injection
  source: csa-internal
```

### Reverse Lookup

Query a SecID, get all associated nodes and edges:

```
GET secid:entity/glossary/model-context-protocol

Returns:
- All nodes tagged with this SecID (from all sources)
- All edges where this SecID is source or target
- Merged with provenance
```

SecID becomes a **portable query** that works against any compliant knowledge graph.

### Cross-Reference Between Security and General Knowledge

Security knowledge links to general concepts:

```yaml
# In SecID security data
secid: secid:weakness/owasp/llm-top10@2.0#LLM01
related_concepts:
  - secid:entity/glossary/model-context-protocol
  - secid:entity/glossary/prompt-injection
```

General concepts link back:

```yaml
# In glossary
secid: secid:entity/glossary/model-context-protocol
security_relevant:
  - secid:weakness/owasp/llm-top10@2.0#LLM01
  - secid:ttp/mitre/atlas#AML.T0043
```

Bidirectional references, stored wherever appropriate.

---

## AI-First Design

### What AI-First Means Here

AI is not just a consumer of this system. AI is:

1. **A user** - Queries the knowledge graph
2. **A contributor** - Proposes new nodes/edges
3. **A synthesizer** - Merges perspectives intelligently
4. **A maintainer** - Identifies gaps, staleness, inconsistencies

### AI Capabilities Enabled

**Research Partner**
```
"What do we know about MCP security?"

AI traverses graph, finds:
- Your previous research (3 conversations, 1 repo)
- CSA internal assessment (HIGH risk)
- Related weaknesses (LLM01)
- Gap: No mapping to ATLAS techniques yet
```

**Knowledge Builder**
```
"Based on our conversation, I propose:
- New edge: MCP → vulnerable-to → AML.T0043
- Evidence: This conversation
- Source: personal

Create this entry?"
```

**Perspective Synthesizer**
```
"This CVE has three severity ratings:
- MITRE: CRITICAL (their broad definition)
- Red Hat: MEDIUM (their operational definition)
- Your notes: 'Actually HIGH in misconfigured environments'

Real-world risk depends on deployment context."
```

**Gap Finder**
```
"Weekly knowledge graph health:
- 3 nodes not updated in 90 days
- 2 concepts missing CSA assessment
- 1 potential duplicate detected"
```

**Context Loader**
```
When you start a conversation about MCP, AI automatically loads:
- Your previous research
- Org assessments
- Related security data
- Open questions from last session
```

### Multi-Agent Collaboration

Multiple AI agents share the knowledge graph as common ground:

- Agent A (Research): Adds findings to graph
- Agent B (Code Review): Queries graph for known issues
- Agent C (Report Writer): Synthesizes from graph

All reference the same SecIDs → coherent collaboration across agents.

---

## Implementation Considerations

### What Changes in SecID

Minimal spec changes required:

1. **Clarify `entity` scope** - Explicitly include concepts and definitions
2. **Add `glossary` namespace** - For shared concept definitions
3. **Document multi-registry model** - How clients merge sources
4. **Subpath semantics** - Perspectives and facets

The core identifier grammar stays unchanged.

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client / API                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           Merge & Conflict Preservation              │   │
│  │         (maintains provenance, surfaces conflicts)   │   │
│  └─────────────────────────────────────────────────────┘   │
│              │              │              │                │
│              ▼              ▼              ▼                │
│       ┌──────────┐   ┌──────────┐   ┌──────────┐          │
│       │  Public  │   │   Org    │   │ Personal │          │
│       │ Registry │   │ Registry │   │ Registry │          │
│       │ (GitHub) │   │ (GitHub) │   │ (local)  │          │
│       └──────────┘   └──────────┘   └──────────┘          │
└─────────────────────────────────────────────────────────────┘
```

Each registry is text files (YAML frontmatter + Markdown), Git-friendly, AI-readable.

### Data Format

Nodes (registry files):
```yaml
---
secid: secid:entity/glossary/model-context-protocol
type: entity
namespace: glossary
name: model-context-protocol
aliases: [MCP]
canonical_url: https://modelcontextprotocol.io/
wikipedia: https://en.wikipedia.org/wiki/Model_Context_Protocol

related_secids:
  - secid:weakness/owasp/llm-top10@2.0#LLM01
---

# Model Context Protocol

[Description, context, notes...]
```

Edges (relationship files or embedded):
```yaml
edges:
  - to: secid:weakness/owasp/llm-top10@2.0#LLM01
    relationship: vulnerable-to
    evidence: "Tool injection attack vector"
```

---

## What This Enables

### For Individuals
- Personal knowledge graph with stable references
- Layer your research on public knowledge
- AI remembers your context across sessions

### For Organizations
- Shared internal assessments
- Consistent terminology via SecID references
- AI-assisted knowledge management

### For the Community
- Federated knowledge without central control
- Multiple perspectives preserved, not flattened
- AI-native infrastructure for security knowledge

### For AI Systems
- Stable references that persist across conversations
- Rich context beyond training data
- Explicit handling of uncertainty and disagreement

---

## Summary

**The vision**: SecID evolves from an identifier scheme to the identity layer for federated knowledge graphs.

**The mechanism**:
1. Identifier schema (PURL grammar, already done)
2. Overlay data from multiple sources (public → org → personal)
3. Conflicts preserved as signals, not resolved away

**The outcome**: AI-native knowledge infrastructure where:
- References are stable
- Perspectives are layered
- Disagreements inform rather than confuse
- AI and humans collaborate on knowledge building

---

## Next Steps

This document is for internal discussion. Before broader publication:

1. Validate the expanded `entity` scope with stakeholders
2. Prototype multi-registry merge in client tooling
3. Test with real-world knowledge graph (MCP, agent security concepts)
4. Develop AI integration patterns
5. Assess governance implications of federated model

---

*This document represents exploratory thinking about SecID's future direction. It does not represent committed roadmap items or official CSA positions.*
