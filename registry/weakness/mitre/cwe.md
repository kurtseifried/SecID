---
type: weakness
namespace: mitre
name: cwe
full_name: "Common Weakness Enumeration"
operator: "secid:entity/mitre/cwe"

urls:
  website: "https://cwe.mitre.org"
  api: "https://cwe.mitre.org/data/index.html"
  lookup: "https://cwe.mitre.org/data/definitions/{num}.html"

id_pattern: "CWE-\\d+"
examples:
  - "secid:weakness/mitre/cwe#CWE-79"
  - "secid:weakness/mitre/cwe#CWE-89"
  - "secid:weakness/mitre/cwe#CWE-1427"

status: active
---

# CWE (MITRE)

The canonical software weakness taxonomy, operated by MITRE.

## Format

```
secid:weakness/mitre/cwe#CWE-NNN
```

## Resolution

```
https://cwe.mitre.org/data/definitions/{num}.html
```

## Subpaths

Reference sections within a CWE entry:

```
secid:weakness/mitre/cwe#CWE-79/extended-description
secid:weakness/mitre/cwe#CWE-79/potential-mitigations
secid:weakness/mitre/cwe#CWE-79/detection-methods
secid:weakness/mitre/cwe#CWE-79/observed-examples
```

## Key CWEs

| CWE | Name |
|-----|------|
| CWE-79 | Cross-site Scripting (XSS) |
| CWE-89 | SQL Injection |
| CWE-22 | Path Traversal |
| CWE-78 | OS Command Injection |
| CWE-1427 | Improper Neutralization of Input During LLM Interaction |

## Notes

- Hierarchical taxonomy (views, categories, weaknesses)
- Referenced by CVE, NVD, and most vulnerability databases
- CWE-1400s include AI/ML weaknesses

