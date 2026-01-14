---
type: advisory
namespace: partnershiponai
name: aiid
full_name: "AI Incident Database"
operator: "secid:entity/partnershiponai"

urls:
  website: "https://incidentdatabase.ai"
  api: "https://incidentdatabase.ai/api"
  bulk_data: "https://github.com/responsible-ai-collaborative/aiid"
  lookup: "https://incidentdatabase.ai/cite/{id}"

id_pattern: "\\d+"
examples:
  - "secid:advisory/partnershiponai/aiid#1"
  - "secid:advisory/partnershiponai/aiid#100"

status: active
---

# AI Incident Database

Repository of AI system harms and failures, documenting real-world incidents where AI systems caused or nearly caused harm.

## Format

```
secid:advisory/partnershiponai/aiid#{incident-number}
```

## Resolution

```
https://incidentdatabase.ai/cite/{id}
```

## Why AIID Matters

AI security requires learning from real-world failures:
- **Historical record** - Documented AI incidents going back years
- **Harm taxonomy** - Categorized by type of harm and affected parties
- **Pattern recognition** - Enables identification of recurring failure modes
- **Accountability** - Public record of AI system failures

## Scope

AIID covers incidents including:
- Autonomous vehicle accidents
- Facial recognition failures
- Content moderation errors
- Algorithmic discrimination
- Healthcare AI mistakes
- Financial AI failures
- LLM misuse and jailbreaks

## Notes

- Incidents are numbered sequentially
- Each incident may have multiple reports from different sources
- Maintained by the Responsible AI Collaborative
- Broader than pure security - includes safety, bias, and ethical failures
