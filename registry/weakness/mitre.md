---
type: weakness
namespace: mitre
full_name: "MITRE Corporation"
operator: "secid:entity/mitre"
website: "https://www.mitre.org"
status: active

sources:
  cwe:
    full_name: "Common Weakness Enumeration"
    urls:
      website: "https://cwe.mitre.org"
      api: "https://cwe.mitre.org/data/index.html"
      lookup: "https://cwe.mitre.org/data/definitions/{num}.html"
    id_pattern: "CWE-\\d+"
    examples:
      - "secid:weakness/mitre/cwe#CWE-79"
      - "secid:weakness/mitre/cwe#CWE-89"
      - "secid:weakness/mitre/cwe#CWE-1427"
---

# MITRE Weakness Taxonomies

MITRE operates CWE, the canonical weakness taxonomy referenced by virtually all vulnerability databases.

## Why MITRE CWE Matters

CWE is the foundation of weakness classification:

- **Industry standard** - Referenced by CVE, NVD, and all major vuln databases
- **Hierarchical taxonomy** - Views, categories, and specific weaknesses
- **Comprehensive** - 900+ weakness types
- **AI coverage** - CWE-1400s cover AI/ML weaknesses

## CWE Structure

| Level | Purpose | Example |
|-------|---------|---------|
| Views | Organize by perspective | CWE-1000 (Research) |
| Categories | Group related weaknesses | CWE-19 (Data Processing) |
| Weaknesses | Specific flaw types | CWE-79 (XSS) |

## AI-Specific CWEs

| CWE | Name |
|-----|------|
| CWE-1426 | Improper Validation of Generative AI Output |
| CWE-1427 | Improper Neutralization of Input for LLM Prompting |
| CWE-1434 | Insecure ML Model Inference Parameters |

---

## cwe

The canonical software weakness taxonomy, operated by MITRE.

### Format

```
secid:weakness/mitre/cwe#CWE-NNN
```

### Resolution

```
https://cwe.mitre.org/data/definitions/{num}.html
```

### Subpaths

Reference sections within a CWE entry:

```
secid:weakness/mitre/cwe#CWE-79/extended-description
secid:weakness/mitre/cwe#CWE-79/potential-mitigations
secid:weakness/mitre/cwe#CWE-79/detection-methods
secid:weakness/mitre/cwe#CWE-79/observed-examples
```

### Key CWEs

| CWE | Name |
|-----|------|
| CWE-79 | Cross-site Scripting (XSS) |
| CWE-89 | SQL Injection |
| CWE-22 | Path Traversal |
| CWE-78 | OS Command Injection |
| CWE-1427 | Improper Neutralization of Input During LLM Interaction |

### Notes

- Hierarchical taxonomy (views, categories, weaknesses)
- Referenced by CVE, NVD, and most vulnerability databases
- CWE-1400s include AI/ML weaknesses
