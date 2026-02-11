---
type: advisory
namespace: partnershiponai.org
full_name: "Partnership on AI"
operator: "secid:entity/partnershiponai.org"
website: "https://partnershiponai.org"
status: active

sources:
  aiid:
    full_name: "AI Incident Database"
    urls:
      website: "https://incidentdatabase.ai"
      api: "https://incidentdatabase.ai/api"
      bulk_data: "https://github.com/responsible-ai-collaborative/aiid"
      lookup: "https://incidentdatabase.ai/cite/{id}"
    id_pattern: "\\d+"
    examples:
      - "secid:advisory/partnershiponai.org/aiid#1"
      - "secid:advisory/partnershiponai.org/aiid#100"
---

# Partnership on AI Advisory Sources

Partnership on AI is a nonprofit organization bringing together academics, civil society, industry, and media to study and formulate best practices for AI. They operate the AI Incident Database (AIID).

## Why Partnership on AI Matters

Partnership on AI documents real-world AI failures:

- **Historical record** - AI incidents dating back years
- **Pattern recognition** - Identifies recurring failure modes
- **Accountability** - Public record of AI harms
- **Learning** - Helps practitioners avoid past mistakes

The AI Incident Database is broader than pure security - it includes safety, bias, and ethical failures.

## ID Format

AIID uses simple numeric IDs:
```
https://incidentdatabase.ai/cite/1325/
```

Each incident may have multiple reports from different sources describing the same event.

## Scope

AIID covers incidents including:
- Autonomous vehicle accidents
- Facial recognition failures and misidentification
- Content moderation errors
- Algorithmic discrimination
- Healthcare AI mistakes
- Financial AI failures
- LLM misuse and jailbreaks

## Difference from AVID

| AIID | AVID |
|------|------|
| Incidents (what happened) | Vulnerabilities (what could happen) |
| Broader scope (safety, ethics) | Security-focused |
| News/report aggregation | Technical vulnerability details |

## Notes

- Maintained by the Responsible AI Collaborative
- Incidents are submitted by the community
- Useful for AI risk assessment and case studies
- Referenced in AI policy discussions

---

## aiid

Repository of AI system harms and failures, documenting real-world incidents where AI systems caused or nearly caused harm.

### Format

```
secid:advisory/partnershiponai.org/aiid#{incident-number}
```

### Resolution

```
https://incidentdatabase.ai/cite/{id}
```

### Why AIID Matters

AI security requires learning from real-world failures:
- **Historical record** - Documented AI incidents going back years
- **Harm taxonomy** - Categorized by type of harm and affected parties
- **Pattern recognition** - Enables identification of recurring failure modes
- **Accountability** - Public record of AI system failures

### Scope

AIID covers incidents including:
- Autonomous vehicle accidents
- Facial recognition failures
- Content moderation errors
- Algorithmic discrimination
- Healthcare AI mistakes
- Financial AI failures
- LLM misuse and jailbreaks

### Notes

- Incidents are numbered sequentially
- Each incident may have multiple reports from different sources
- Maintained by the Responsible AI Collaborative
- Broader than pure security - includes safety, bias, and ethical failures
