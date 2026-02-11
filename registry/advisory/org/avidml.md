---
type: advisory
namespace: avidml.org
full_name: "AI Vulnerability Database"
operator: "secid:entity/avidml.org"
website: "https://avidml.org"
status: active

sources:
  avid:
    full_name: "AI Vulnerability Database"
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
      - "secid:advisory/avidml.org/avid#AVID-2023-V001"
      - "secid:advisory/avidml.org/avid#AVID-2025-R0001"
---

# AVID Advisory Sources

AVID is a community-driven database cataloging vulnerabilities, failures, and risks specific to AI and machine learning systems. It fills a gap left by traditional vulnerability databases like CVE, which weren't designed for AI-specific issues.

## Why AVID Matters

Traditional vulnerability databases don't capture AI-specific risks:

- **Prompt injection** - Manipulating LLM behavior through inputs
- **Training data poisoning** - Corrupting models through malicious data
- **Model extraction** - Stealing model weights or behavior
- **Adversarial examples** - Inputs designed to fool ML models
- **Bias and fairness** - Discriminatory model outputs

AVID provides structured tracking for these AI-native vulnerability classes.

## ID Format

AVID uses two ID types:
- **Vulnerabilities**: `AVID-YYYY-VNNN` (e.g., AVID-2023-V001)
- **Reports**: `AVID-YYYY-RNNNN` (e.g., AVID-2025-R0001)

## Relationship to Other AI Security Resources

AVID complements other AI security frameworks:

| Resource | Focus |
|----------|-------|
| AVID | Specific vulnerability instances |
| MITRE ATLAS | Attack techniques (TTPs) |
| OWASP LLM Top 10 | Risk categories |
| CWE | Weakness patterns (some AI-specific) |

## Notes

- AVID uses a taxonomy designed for ML/AI failure modes
- Database is community-driven with open contributions
- Growing coverage as AI security research matures
- Useful for AI red teaming and security assessments

---

## avid

Community-driven database cataloging vulnerabilities, failures, and risks specific to AI and machine learning systems.

### Format

```
secid:advisory/avidml.org/avid#AVID-YYYY-VNNN   (vulnerabilities)
secid:advisory/avidml.org/avid#AVID-YYYY-RNNNN  (reports)
```

### Resolution

```
https://avidml.org/database/vulnerability/{id}
```

### Why AVID Matters

Traditional vulnerability databases (CVE, NVD) weren't designed for AI-specific issues:
- **AI-native taxonomy** - Categories designed for ML/AI failure modes
- **Model-specific risks** - Prompt injection, training data poisoning, model theft
- **Structured reporting** - Machine-readable format for AI vulnerabilities
- **Community-driven** - Open contributions from AI security researchers

### Categories

AVID tracks several AI-specific vulnerability types:
- Prompt injection and jailbreaks
- Training data poisoning
- Model extraction/theft
- Adversarial examples
- Data leakage
- Bias and fairness issues

### Notes

- Complements MITRE ATLAS (techniques) with specific vulnerabilities
- Growing database as AI security research matures
- Integrates with OWASP LLM Top 10 categories
