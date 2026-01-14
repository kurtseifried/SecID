---
type: weakness
namespace: owasp
name: ai-exchange
full_name: "OWASP AI Exchange"
operator: "secid:entity/owasp"

urls:
  website: "https://owaspai.org"
  lookup: "https://owaspai.org/goto/{id}/"

id_pattern: "[A-Z]+\\d*"

examples:
  - "secid:weakness/owasp/ai-exchange#INPUTVALIDATION"
  - "secid:weakness/owasp/ai-exchange#PROMPTINJECTION"
  - "secid:weakness/owasp/ai-exchange#DATAPOISON"

status: active
---

# OWASP AI Exchange

Comprehensive AI security knowledge base covering threats, controls, and best practices across the AI lifecycle.

## Format

```
secid:weakness/owasp/ai-exchange#CATEGORY
secid:weakness/owasp/ai-exchange#PROMPTINJECTION
secid:weakness/owasp/ai-exchange#MODELTHEFT
```

## Coverage Areas

The AI Exchange covers:

| Category | Description |
|----------|-------------|
| **Threats** | AI-specific attack vectors and risks |
| **Controls** | Security measures for AI systems |
| **Development** | Secure AI development practices |
| **Deployment** | Safe AI deployment considerations |
| **Governance** | AI security governance guidance |

## Key Threat Categories

| ID | Name |
|----|------|
| INPUTVALIDATION | Input validation failures |
| PROMPTINJECTION | Prompt injection attacks |
| DATAPOISON | Training data poisoning |
| MODELTHEFT | Model extraction and theft |
| EVASION | Adversarial evasion attacks |
| MODELLEAK | Model information leakage |
| OUTPUTHANDLING | Insecure output handling |

## Relationship to Other OWASP Projects

| Project | Relationship |
|---------|--------------|
| LLM Top 10 | AI Exchange provides deeper technical coverage |
| ML Top 10 | AI Exchange includes ML security as subset |
| ASVS | AI Exchange references traditional security controls |

## Notes

- Most comprehensive OWASP AI security resource
- Continuously updated with emerging threats
- Links to research, tools, and mitigations
- Maps to MITRE ATLAS and other frameworks
