---
type: weakness
namespace: avid
full_name: "AI Vulnerability Database"
operator: "secid:entity/avid"
website: "https://avidml.org"
status: active

sources:
  taxonomy:
    full_name: "AVID Vulnerability Taxonomy"
    urls:
      website: "https://avidml.org/taxonomy"
      api: "https://avidml.org/api"
      github: "https://github.com/avidml/avid-taxonomy"
    id_pattern: "AVID-\\d{4}-\\w+"
    examples:
      - "secid:weakness/avid/taxonomy#AVID-2023-V001"
      - "secid:weakness/avid/taxonomy#AVID-2023-R001"
---

# AVID AI Vulnerability Database

AVID (AI Vulnerability Database) is a community-driven knowledge base focused on AI/ML security vulnerabilities. It provides both a taxonomy for classifying AI vulnerabilities and a database of reported issues.

## Why AVID Matters

AVID fills a critical gap in AI security:

- **Structured taxonomy** - Systematic classification of AI/ML vulnerabilities
- **Community-driven** - Open contributions from researchers
- **Cross-references** - Links to CVEs, ATLAS, and other sources
- **Real-world focus** - Based on actual reported vulnerabilities

## Taxonomy Structure

AVID organizes vulnerabilities into categories:

| Category | Description |
|----------|-------------|
| **Security** | Traditional security vulnerabilities in AI systems |
| **Ethics** | Bias, fairness, and ethical concerns |
| **Performance** | Reliability and robustness issues |

## Relationship to Other Sources

| Source | Relationship |
|--------|--------------|
| MITRE ATLAS | AVID references ATLAS techniques |
| CVE/NVD | AVID entries may have associated CVEs |
| OWASP | Complementary coverage of AI risks |

---

## taxonomy

The AVID Vulnerability Taxonomy provides structured classification for AI/ML security issues.

### Format

```
secid:weakness/avid/taxonomy#AVID-YYYY-XNNN
```

Where X indicates the category (V for vulnerability, R for risk, etc.).

### Resolution

```
https://avidml.org/database/{id}
```

### Taxonomy Categories

| Prefix | Category | Examples |
|--------|----------|----------|
| V | Vulnerabilities | Security flaws in AI systems |
| R | Risks | Potential harm scenarios |
| E | Ethics | Bias and fairness issues |

### Why Use AVID Taxonomy

- **AI-specific** - Purpose-built for AI/ML vulnerabilities
- **Structured** - Consistent classification scheme
- **Actionable** - Links to mitigations and references
- **Growing** - Active community contributions

### Notes

- AVID is maintained by the AVID ML community
- Complements rather than replaces CVE/CWE
- Useful for AI-specific vulnerability tracking
- Integrates with other AI security frameworks
