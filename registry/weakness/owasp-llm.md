---
namespace: owasp-llm
full_name: "OWASP Top 10 for LLM Applications"
type: weakness
operator: "secid:entity/owasp/llm-top-10"

urls:
  website: "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
  lookup: "https://genai.owasp.org/"

id_pattern: "LLM\\d{2}"
versions:
  - "2025"
  - "2023"

examples:
  - "LLM01"
  - "LLM02"
  - "LLM09"

status: active
---

# OWASP LLM Top 10 Namespace

Security risks specific to Large Language Model applications.

## Format

```
secid:weakness/owasp-llm/LLM0N@VERSION
secid:weakness/owasp-llm/LLM01           # Current version
```

## 2025 Edition

| ID | Name |
|----|------|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain Vulnerabilities |
| LLM04 | Data and Model Poisoning |
| LLM05 | Insecure Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

## Relationships

```
weakness/owasp-llm/LLM01 → maps_to → weakness/cwe/CWE-1427
weakness/owasp-llm/LLM01 → exploitedBy → ttp/atlas/AML.T0043
```

## Notes

- AI/ML specific weakness categories
- Maps to CWE and ATLAS
- Updated more frequently than traditional OWASP Top 10
