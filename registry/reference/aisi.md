---
type: reference
namespace: aisi
full_name: "AI Safety Institutes"
operator: "secid:entity/aisi"
website: "https://www.gov.uk/government/organisations/ai-safety-institute"
status: active

sources:
  uk:
    full_name: "UK AI Safety Institute"
    urls:
      website: "https://www.gov.uk/government/organisations/ai-safety-institute"
      research: "https://www.aisi.gov.uk/research"
    examples:
      - "secid:reference/aisi/uk"
      - "secid:reference/aisi/uk#inspect"

  us:
    full_name: "US AI Safety Institute"
    urls:
      website: "https://www.nist.gov/aisi"
      parent: "https://www.nist.gov/artificial-intelligence"
    examples:
      - "secid:reference/aisi/us"

  japan:
    full_name: "Japan AI Safety Institute"
    urls:
      website: "https://aisi.go.jp/en"
    examples:
      - "secid:reference/aisi/japan"

  international:
    full_name: "International Network of AI Safety Institutes"
    urls:
      website: "https://www.gov.uk/government/publications/international-network-of-ai-safety-institutes"
    examples:
      - "secid:reference/aisi/international"
---

# AI Safety Institutes

Government-backed AI safety research and evaluation institutes established following the 2023 Bletchley AI Safety Summit.

## Why AISIs Matter

Governments are building AI safety capacity:

- **Independent evaluation** - Third-party model assessments
- **Research** - Fundamental safety research
- **Standards** - Contributing to AI safety standards
- **International** - Coordinated global approach

## International Network

Following Bletchley, multiple countries established AISIs:
- UK (first, November 2023)
- US (within NIST)
- Japan
- Canada, France, Singapore, others following

---

## uk

The UK AI Safety Institute (AISI) was the first national AI safety institute, established after the Bletchley Summit.

### Format

```
secid:reference/aisi/uk
secid:reference/aisi/uk#inspect
```

### Key Activities

| Activity | Description |
|----------|-------------|
| **Model evaluations** | Pre-deployment safety testing |
| **Research** | Fundamental AI safety research |
| **Tools** | Open-source evaluation tools |
| **International** | Coordination with other AISIs |

### Inspect Framework

The UK AISI released Inspect, an open-source AI evaluation framework:
- Model capability testing
- Safety benchmark evaluation
- Reproducible assessments

### Evaluations Conducted

- GPT-4 (OpenAI)
- Claude (Anthropic)
- Gemini (Google)
- Other frontier models

### Notes

- Part of Department for Science, Innovation and Technology
- Announced November 2023
- First evaluations 2024
- Growing team of researchers

---

## us

The US AI Safety Institute (USAISI) operates within NIST.

### Format

```
secid:reference/aisi/us
```

### Mandate

| Area | Activities |
|------|------------|
| **Evaluations** | Guidelines for AI system testing |
| **Red teaming** | Adversarial evaluation guidance |
| **Standards** | AI safety standards development |
| **Coordination** | Federal AI safety coordination |

### Relationship to NIST

- Part of NIST's AI program
- Complements AI RMF
- Coordinates with NIST Trustworthy AI

### Priorities

- Developing evaluation methodologies
- Creating consensus standards
- Supporting agency AI safety
- International harmonization

### Notes

- Established 2024
- Within NIST structure
- Coordinates federal AI safety
- Works with UK AISI

---

## japan

Japan's AI Safety Institute focuses on evaluating AI systems deployed in Japan.

### Format

```
secid:reference/aisi/japan
```

### Focus Areas

| Area | Description |
|------|-------------|
| Evaluation | Testing AI systems for Japanese market |
| Guidelines | AI safety guidance for industry |
| Research | Safety research partnerships |
| Standards | Contributing to international standards |

### Coordination

- Works with METI (Ministry of Economy, Trade and Industry)
- Partners with international AISIs
- Engages Japanese AI companies

### Notes

- Established 2024
- Growing capability
- Focus on evaluation and standards
- Part of international network

---

## international

The International Network of AI Safety Institutes coordinates global AI safety efforts.

### Format

```
secid:reference/aisi/international
```

### Member Institutes

| Country | Status |
|---------|--------|
| UK | Operational |
| US | Operational |
| Japan | Operational |
| Canada | Establishing |
| France | Establishing |
| Singapore | Establishing |
| EU | Coordinating |

### Coordination Areas

- Shared evaluation methodologies
- Information sharing on risks
- Common terminology and standards
- Joint research projects

### Summit Origins

| Summit | Outcomes |
|--------|----------|
| Bletchley (2023) | Established need for AISIs |
| Seoul (2024) | Expanded network commitments |

### Notes

- Formalized post-Bletchley
- Growing membership
- Developing shared frameworks
- Regular coordination meetings
