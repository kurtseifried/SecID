---
namespace: cwe
full_name: "Common Weakness Enumeration"
type: weakness
operator: "secid:entity/mitre/cwe"

urls:
  website: "https://cwe.mitre.org"
  api: "https://cwe.mitre.org/data/index.html"
  lookup: "https://cwe.mitre.org/data/definitions/{num}.html"

id_pattern: "CWE-\\d+"
examples:
  - "CWE-79"
  - "CWE-89"
  - "CWE-1427"

status: active
---

# CWE Namespace

The canonical software weakness taxonomy.

## Format

```
secid:weakness/cwe/CWE-NNN
```

## Resolution

```
https://cwe.mitre.org/data/definitions/{num}.html
```

## Subpaths

```
secid:weakness/cwe/CWE-79#extended-description
secid:weakness/cwe/CWE-79#potential-mitigations
secid:weakness/cwe/CWE-79#detection-methods
secid:weakness/cwe/CWE-79#observed-examples
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
