---
namespace: mitre
full_name: "MITRE Corporation"
website: "https://www.mitre.org"
type: nonprofit
founded: 1958
headquarters: "McLean, Virginia, USA"
---

# MITRE (Weakness Namespace)

MITRE operates CWE, the canonical weakness taxonomy referenced by virtually all vulnerability databases.

## Why MITRE CWE Matters

CWE is the foundation of weakness classification:

- **Industry standard** - Referenced by CVE, NVD, and all major vuln databases
- **Hierarchical taxonomy** - Views, categories, and specific weaknesses
- **Comprehensive** - 900+ weakness types
- **AI coverage** - CWE-1400s cover AI/ML weaknesses

## Weakness Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `cwe` | Common Weakness Enumeration | CWE-79, CWE-89 |

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

## Notes

- CWE is referenced by NVD for all CVEs
- Hierarchical structure enables precise classification
- AI/ML coverage expanding (CWE-1400 series)
- Maps to OWASP, SANS, and other taxonomies
