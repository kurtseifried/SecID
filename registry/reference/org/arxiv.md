---
namespace: arxiv.org
full_name: "arXiv Preprints"
type: reference

urls:
  website: "https://arxiv.org"
  api: "https://export.arxiv.org/api/query"
  lookup: "https://arxiv.org/abs/{id}"
  pdf: "https://arxiv.org/pdf/{id}.pdf"

id_pattern: "\\d{4}\\.\\d{4,5}"
examples:
  - "2303.08774"
  - "2307.03109"
  - "2402.05369"

status: active
---

# arXiv Namespace

Research preprints, particularly AI/ML security research.

## Format

```
secid:reference/arxiv.org/{id}
secid:reference/arxiv.org/2303.08774
```

## Resolution

```
https://arxiv.org/abs/{id}
https://arxiv.org/pdf/{id}.pdf
```

## Key Papers (AI Security)

| ID | Title | Authors |
|----|-------|---------|
| 2303.08774 | GPT-4 Technical Report | OpenAI |
| 2307.03109 | Jailbroken | Wei et al. |
| 2402.05369 | Sleeper Agents | Anthropic |
| 2312.06942 | Purple Llama CyberSecEval | Meta |
| 2401.06373 | Weak-to-Strong Generalization | OpenAI |

## Subpaths

```
secid:reference/arxiv.org/2303.08774#section-3
secid:reference/arxiv.org/2303.08774#appendix-a
```

## Relationships

```
secid:reference/arxiv.org/2307.03109 → about → secid:weakness/owasp.org/llm-top10#LLM01
secid:reference/arxiv.org/2402.05369 → about → secid:ttp/mitre.org/atlas#AML.T0051
```

## Notes

- ID format: YYMM.NNNNN (year-month.sequence)
- Preprints - not peer reviewed
- Primary source for AI security research
