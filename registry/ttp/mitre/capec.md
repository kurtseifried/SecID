---
type: ttp
namespace: mitre
name: capec
full_name: "Common Attack Pattern Enumeration and Classification"
operator: "secid:entity/mitre/capec"

urls:
  website: "https://capec.mitre.org"
  lookup: "https://capec.mitre.org/data/definitions/{num}.html"

id_pattern: "CAPEC-\\d+"
examples:
  - "secid:ttp/mitre/capec#CAPEC-66"
  - "secid:ttp/mitre/capec#CAPEC-242"
  - "secid:ttp/mitre/capec#CAPEC-86"

status: active
---

# CAPEC (MITRE)

Attack patterns that describe common methods of exploitation.

## Format

```
secid:ttp/mitre/capec#CAPEC-NNN
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
secid:ttp/mitre/capec#CAPEC-66 → exploits → secid:weakness/mitre/cwe#CWE-89
```

## Notes

- Higher abstraction than ATT&CK
- Links to CWEs (weakness exploited)
- Includes prerequisites and mitigations
