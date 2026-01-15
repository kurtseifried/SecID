---
type: weakness
namespace: mit
name: ai-risk-repository
full_name: "MIT AI Risk Repository"
operator: "secid:entity/mit"

urls:
  website: "https://airisk.mit.edu"
  index: "https://airisk.mit.edu/"
  database: "https://airisk.mit.edu/risks"
  causal_taxonomy: "https://airisk.mit.edu/causal-taxonomy"
  domain_taxonomy: "https://airisk.mit.edu/domain-taxonomy"
  lookup: "https://airisk.mit.edu/risks"

id_pattern: ".*"
versions:
  - "2025"

examples:
  - "secid:weakness/mit/ai-risk-repository#discrimination"
  - "secid:weakness/mit/ai-risk-repository#privacy-violation"
  - "secid:weakness/mit/ai-risk-repository#misuse-military"

status: active
---

# MIT AI Risk Repository

The most comprehensive AI risk taxonomy, containing 1,700+ risks organized across 7 domains and 24 subdomains. Curated from 74 existing frameworks by MIT FutureTech.

## Format

```
secid:weakness/mit/ai-risk-repository#RISK-CATEGORY
secid:weakness/mit/ai-risk-repository#discrimination
secid:weakness/mit/ai-risk-repository#autonomous-weapons
```

## Why MIT AI Risk Repository Matters

- **1,700+ risks** - Most comprehensive collection
- **74 frameworks synthesized** - Aggregates existing work
- **Academic rigor** - MIT research backing
- **Dual taxonomies** - Both causal and domain-based
- **Incident tracking** - Links risks to real incidents

## Domain Taxonomy (7 Domains)

| Domain | Subdomains | Risk Count |
|--------|------------|------------|
| **Discrimination & Toxicity** | Bias, hate speech, stereotyping | ~200 |
| **Privacy & Security** | Data exposure, surveillance, hacking | ~250 |
| **Misinformation** | Hallucination, deepfakes, manipulation | ~200 |
| **Malicious Actors** | Misuse, cyberattacks, weapons | ~300 |
| **Human-Computer Interaction** | Overreliance, addiction, manipulation | ~200 |
| **Socioeconomic & Environmental** | Job displacement, inequality, energy | ~250 |
| **AI System Safety** | Accidents, control loss, misalignment | ~300 |

## Causal Taxonomy

Risks are also classified by:

| Dimension | Categories |
|-----------|------------|
| **Entity** | AI system, human, organization, society |
| **Intentionality** | Intentional, unintentional |
| **Timing** | Pre-deployment, deployment, post-deployment |

## Components

| Component | Description |
|-----------|-------------|
| Risk Database | Searchable risk entries |
| AI Incident Tracker | Real-world incident mapping |
| Framework Crosswalk | Maps to other taxonomies |

## Relationship to Other Frameworks

| Framework | Relationship |
|-----------|--------------|
| OWASP Top 10s | MIT includes and extends |
| NIST AI RMF | MIT provides detailed risk taxonomy |
| MITRE ATLAS | MIT covers broader risks beyond security |
| EU AI Act | MIT maps to regulatory requirements |

## Notes

- Created by MIT FutureTech research group
- Updated continuously with new risks
- Links risks to documented incidents
- Useful for comprehensive risk assessment
