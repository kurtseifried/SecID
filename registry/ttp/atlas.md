---
namespace: atlas
full_name: "MITRE ATLAS"
type: ttp
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
  - "AML.T0043"
  - "AML.T0051"
  - "AML.TA0001"

status: active
---

# ATLAS Namespace

Adversarial Threat Landscape for AI Systems.

## Format

```
secid:ttp/atlas/AML.TNNNN       # Technique
secid:ttp/atlas/AML.TANNNN      # Tactic
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
ttp/atlas/AML.T0043 → exploits → weakness/cwe/CWE-1427
ttp/atlas/AML.T0043 → exploits → weakness/owasp-llm/LLM01
```

## Notes

- AI/ML specific attack framework
- Modeled after ATT&CK structure
- Includes case studies of real attacks
