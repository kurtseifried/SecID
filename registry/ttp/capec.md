---
namespace: capec
full_name: "Common Attack Pattern Enumeration and Classification"
type: ttp
operator: "secid:entity/mitre/capec"

urls:
  website: "https://capec.mitre.org"
  lookup: "https://capec.mitre.org/data/definitions/{num}.html"

id_pattern: "CAPEC-\\d+"
examples:
  - "CAPEC-66"
  - "CAPEC-242"
  - "CAPEC-86"

status: active
---

# CAPEC Namespace

Attack patterns that describe common methods of exploitation.

## Format

```
secid:ttp/capec/CAPEC-NNN
```

## Resolution

```
https://capec.mitre.org/data/definitions/{num}.html
```

## Key Attack Patterns

| ID | Name |
|----|------|
| CAPEC-66 | SQL Injection |
| CAPEC-86 | XSS Through HTTP Headers |
| CAPEC-242 | Code Injection |

## Relationships

```
ttp/capec/CAPEC-66 → exploits → weakness/cwe/CWE-89
```

## Notes

- Higher abstraction than ATT&CK
- Links to CWEs (weakness exploited)
- Includes prerequisites and mitigations
