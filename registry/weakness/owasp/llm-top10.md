---
type: weakness
namespace: owasp
name: llm-top10
full_name: "OWASP Top 10 for LLM Applications"
operator: "secid:entity/owasp"

urls:
  website: "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
  index: "https://genai.owasp.org/llm-top-10/"
  v2_list: "https://genai.owasp.org/llm-top-10/"
  v1_list: "https://owasp.org/www-project-top-10-for-large-language-model-applications/Archive/0_1_vulns/"
  lookup: "https://genai.owasp.org/llmrisk/{id}/"

id_pattern: "LLM\\d{2}"
versions:
  - "2.0"
  - "1.0"

examples:
  - "secid:weakness/owasp/llm-top10@2.0#LLM01"
  - "secid:weakness/owasp/llm-top10@2.0#LLM02"
  - "secid:weakness/owasp/llm-top10#LLM01"

status: active
---

# OWASP LLM Top 10 Namespace

Security risks specific to Large Language Model applications.

## Format

```
secid:weakness/owasp/llm-top10[@VERSION]#ITEM
secid:weakness/owasp/llm-top10@2.0#LLM01
secid:weakness/owasp/llm-top10#LLM01           # Current version
```

## 2025 Edition (v2.0)

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
secid:weakness/owasp/llm-top10#LLM01 → maps_to → secid:weakness/mitre/cwe#CWE-1427
secid:weakness/owasp/llm-top10#LLM01 → exploitedBy → secid:ttp/mitre/atlas#AML.T0043
```

## Notes

- AI/ML specific weakness categories
- Maps to CWE and ATLAS
- Updated more frequently than traditional OWASP Top 10

