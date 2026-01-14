---
type: advisory
namespace: avid
name: avid
full_name: "AI Vulnerability Database"
operator: "secid:entity/avid"

urls:
  website: "https://avidml.org"
  api: "https://avidml.org/api"
  bulk_data: "https://github.com/avidml/avid-db"
  lookup: "https://avidml.org/database/vulnerability/{id}"

id_patterns:
  - pattern: "AVID-\\d{4}-V\\d+"
    type: "vulnerability"
  - pattern: "AVID-\\d{4}-R\\d+"
    type: "report"
examples:
  - "secid:advisory/avid/avid#AVID-2023-V001"
  - "secid:advisory/avid/avid#AVID-2025-R0001"

status: active
---

# AVID (AI Vulnerability Database)

Community-driven database cataloging vulnerabilities, failures, and risks specific to AI and machine learning systems.

## Format

```
secid:advisory/avid/avid#AVID-YYYY-VNNN   (vulnerabilities)
secid:advisory/avid/avid#AVID-YYYY-RNNNN  (reports)
```

## Resolution

```
https://avidml.org/database/vulnerability/{id}
```

## Why AVID Matters

Traditional vulnerability databases (CVE, NVD) weren't designed for AI-specific issues:
- **AI-native taxonomy** - Categories designed for ML/AI failure modes
- **Model-specific risks** - Prompt injection, training data poisoning, model theft
- **Structured reporting** - Machine-readable format for AI vulnerabilities
- **Community-driven** - Open contributions from AI security researchers

## Categories

AVID tracks several AI-specific vulnerability types:
- Prompt injection and jailbreaks
- Training data poisoning
- Model extraction/theft
- Adversarial examples
- Data leakage
- Bias and fairness issues

## Notes

- Complements MITRE ATLAS (techniques) with specific vulnerabilities
- Growing database as AI security research matures
- Integrates with OWASP LLM Top 10 categories
