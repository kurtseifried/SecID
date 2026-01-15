---
type: weakness
namespace: biml
name: llm-risks
full_name: "Berryville Institute LLM Risk Framework"
operator: "secid:entity/biml"

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

status: active
---

# Berryville Institute LLM Risk Framework

A comprehensive taxonomy of 81 risks specific to Large Language Model systems, extending the original BIML ML risk framework.

## Format

```
secid:weakness/biml/llm-risks#BIML-LLM-NN
secid:weakness/biml/llm-risks#BIML-LLM-01
secid:weakness/biml/llm-risks#BIML-LLM-81
```

## Why LLM-Specific Risks?

LLMs introduce unique risks not covered by traditional ML frameworks:

- **Prompt-based interaction** - Attack surface through natural language
- **Emergent capabilities** - Unexpected behaviors at scale
- **Tool use** - Agents that can take real-world actions
- **Context windows** - Information leakage through context
- **Fine-tuning** - Transfer learning attack vectors

## Risk Categories

| Category | Focus |
|----------|-------|
| Prompt Handling | Injection, jailbreaks, extraction |
| Training Data | Poisoning, memorization, bias |
| Model Behavior | Hallucination, deception, manipulation |
| Deployment | API security, rate limiting, logging |
| Integration | RAG risks, tool use, agent risks |
| Governance | Compliance, monitoring, incident response |

## Relationship to Other Frameworks

| Framework | Comparison |
|-----------|------------|
| OWASP LLM Top 10 | BIML-81 provides more granular risks |
| BIML-78 (ML) | LLM-specific extension |
| MITRE ATLAS | BIML covers risks, ATLAS covers techniques |

## Notes

- 81 risks specific to LLM systems
- Extends the 78-risk ML framework
- Published 2024
- Covers full LLM lifecycle
