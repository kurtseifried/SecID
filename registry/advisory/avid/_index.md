---
namespace: avid
full_name: "AI Vulnerability Database"
website: "https://avidml.org"
type: nonprofit
founded: 2022
---

# AI Vulnerability Database (AVID)

AVID is a community-driven database cataloging vulnerabilities, failures, and risks specific to AI and machine learning systems. It fills a gap left by traditional vulnerability databases like CVE, which weren't designed for AI-specific issues.

## Why AVID Matters

Traditional vulnerability databases don't capture AI-specific risks:

- **Prompt injection** - Manipulating LLM behavior through inputs
- **Training data poisoning** - Corrupting models through malicious data
- **Model extraction** - Stealing model weights or behavior
- **Adversarial examples** - Inputs designed to fool ML models
- **Bias and fairness** - Discriminatory model outputs

AVID provides structured tracking for these AI-native vulnerability classes.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `avid` | AI Vulnerability Database | AVID-2023-V001 |

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
