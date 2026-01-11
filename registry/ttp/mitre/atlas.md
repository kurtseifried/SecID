---
type: ttp
namespace: mitre
name: atlas
full_name: "MITRE ATLAS"
operator: "secid:entity/mitre/atlas"

urls:
  website: "https://atlas.mitre.org"
  api: "https://atlas.mitre.org/api"
  lookup: "https://atlas.mitre.org/techniques/{id}"

id_patterns:
  - pattern: "AML\\.T\\d{4}(\\.\\d{3})?"
    type: "technique"
  - pattern: "AML\\.TA\\d{4}"
    type: "tactic"
  - pattern: "AML\\.CS\\d{4}"
    type: "case-study"

examples:
  - "secid:ttp/mitre/atlas#AML.T0043"
  - "secid:ttp/mitre/atlas#AML.T0051"
  - "secid:ttp/mitre/atlas#AML.TA0001"

status: active
---

# ATLAS (MITRE)

Adversarial Threat Landscape for AI Systems.

## Format

```
secid:ttp/mitre/atlas#AML.TNNNN       # Technique
secid:ttp/mitre/atlas#AML.TANNNN      # Tactic
```

## Key Techniques

| ID | Name |
|----|------|
| AML.T0043 | Prompt Injection |
| AML.T0051 | LLM Jailbreak |
| AML.T0040 | ML Supply Chain Compromise |
| AML.T0043.000 | Direct Prompt Injection |
| AML.T0043.001 | Indirect Prompt Injection |

## Relationships

```
secid:ttp/mitre/atlas#AML.T0043 → exploits → secid:weakness/mitre/cwe#CWE-1427
secid:ttp/mitre/atlas#AML.T0043 → exploits → secid:weakness/owasp/llm-top10#LLM01
```

## Notes

- AI/ML specific attack framework
- Modeled after ATT&CK structure
- Includes case studies of real attacks
