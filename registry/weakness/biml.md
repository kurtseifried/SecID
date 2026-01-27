---
type: weakness
namespace: biml
full_name: "Berryville Institute of Machine Learning"
operator: "secid:entity/biml"
website: "https://berryvilleiml.com"
status: active

sources:
  ml-risks:
    full_name: "Berryville Institute ML Risk Framework"
    urls:
      website: "https://berryvilleiml.com/results/"
      index: "https://berryvilleiml.com/interactive/"
      taxonomy: "https://berryvilleiml.com/taxonomy/"
      interactive: "https://berryvilleiml.com/interactive/"
      lookup: "https://berryvilleiml.com/interactive/"
    id_pattern: "BIML-\\d+"
    versions:
      - "1.0"
    examples:
      - "secid:weakness/biml/ml-risks#BIML-01"
      - "secid:weakness/biml/ml-risks#BIML-42"

  llm-risks:
    full_name: "Berryville Institute LLM Risk Framework"
    urls:
      website: "https://berryvilleiml.com/results/"
      index: "https://berryvilleiml.com/results/#checks"
      paper: "https://berryvilleiml.com/docs/BIML-LLM81.pdf"
      lookup: "https://berryvilleiml.com/results/"
    id_pattern: "BIML-LLM-\\d+"
    versions:
      - "2024"
    examples:
      - "secid:weakness/biml/llm-risks#BIML-LLM-01"
      - "secid:weakness/biml/llm-risks#BIML-LLM-50"
---

# Berryville Institute of Machine Learning

BIML produces comprehensive ML/AI security risk frameworks, going deeper than Top 10 lists with detailed taxonomies.

## Why BIML Matters

BIML provides the most granular ML security risk analysis:

- **78 ML risks** - Comprehensive architectural risk taxonomy
- **81 LLM risks** - LLM-specific extension
- **Interactive explorer** - Browse and filter risks
- **Research-backed** - Academic foundation

## BIML vs Other Frameworks

| Framework | Approach |
|-----------|----------|
| OWASP Top 10 | 10 highest priority risks |
| BIML | Comprehensive enumeration |
| MITRE ATLAS | Attack techniques (TTPs) |
| BIML | Architectural risks |

## Key People

- Gary McGraw (Founder)
- Security research team

---

## ml-risks

A comprehensive taxonomy of 78 architectural security risks specific to machine learning systems.

### Format

```
secid:weakness/biml/ml-risks#BIML-NN
secid:weakness/biml/ml-risks#BIML-01
secid:weakness/biml/ml-risks#BIML-78
```

### Why BIML Matters

- **78 specific risks** - Not top 10, but comprehensive coverage
- **Architectural focus** - Risks in ML system design
- **Interactive explorer** - Browse risks by category
- **Research-backed** - Academic rigor

### Risk Categories

| Category | Count | Examples |
|----------|-------|----------|
| Data Collection | ~10 | Biased sampling, data leakage |
| Data Processing | ~12 | Feature engineering flaws |
| Model Training | ~15 | Overfitting, underfitting |
| Model Deployment | ~10 | Inference attacks, model drift |
| Operational | ~8 | Monitoring gaps, feedback loops |
| Security | ~15 | Adversarial attacks, model theft |
| Privacy | ~8 | Data exposure, membership inference |

### Relationship to Other Frameworks

| Framework | Relationship |
|-----------|--------------|
| OWASP ML Top 10 | BIML provides deeper taxonomy |
| MITRE ATLAS | BIML covers risks, ATLAS covers techniques |
| NIST AI 100-2 | Complementary, different scope |

### Notes

- Created by Gary McGraw and team
- Includes interactive risk explorer
- Separate LLM-specific framework (BIML-81)
- Focused on architectural/design risks vs runtime attacks

---

## llm-risks

A comprehensive taxonomy of 81 risks specific to Large Language Model systems, extending the original BIML ML risk framework.

### Format

```
secid:weakness/biml/llm-risks#BIML-LLM-NN
secid:weakness/biml/llm-risks#BIML-LLM-01
secid:weakness/biml/llm-risks#BIML-LLM-81
```

### Why LLM-Specific Risks?

LLMs introduce unique risks not covered by traditional ML frameworks:

- **Prompt-based interaction** - Attack surface through natural language
- **Emergent capabilities** - Unexpected behaviors at scale
- **Tool use** - Agents that can take real-world actions
- **Context windows** - Information leakage through context
- **Fine-tuning** - Transfer learning attack vectors

### Risk Categories

| Category | Focus |
|----------|-------|
| Prompt Handling | Injection, jailbreaks, extraction |
| Training Data | Poisoning, memorization, bias |
| Model Behavior | Hallucination, deception, manipulation |
| Deployment | API security, rate limiting, logging |
| Integration | RAG risks, tool use, agent risks |
| Governance | Compliance, monitoring, incident response |

### Relationship to Other Frameworks

| Framework | Comparison |
|-----------|------------|
| OWASP LLM Top 10 | BIML-81 provides more granular risks |
| BIML-78 (ML) | LLM-specific extension |
| MITRE ATLAS | BIML covers risks, ATLAS covers techniques |

### Notes

- 81 risks specific to LLM systems
- Extends the 78-risk ML framework
- Published 2024
- Covers full LLM lifecycle
