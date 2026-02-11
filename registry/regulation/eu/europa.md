---
namespace: europa.eu
full_name: "European Union"
type: regulation

urls:
  website: "https://eur-lex.europa.eu"
  lookup: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:{celex}"

examples:
  - "gdpr"
  - "ai-act"
  - "nis2"
  - "dora"

status: active
---

# EU Namespace

European Union regulations and directives.

## Format

```
secid:regulation/europa.eu/{law}
secid:regulation/europa.eu/gdpr#art-32
```

## Key Regulations

| ID | Full Name | Type |
|----|-----------|------|
| gdpr | General Data Protection Regulation | Regulation |
| ai-act | EU AI Act | Regulation |
| nis2 | Network and Information Security Directive 2 | Directive |
| dora | Digital Operational Resilience Act | Regulation |
| cra | Cyber Resilience Act | Regulation |
| dsa | Digital Services Act | Regulation |
| dma | Digital Markets Act | Regulation |

## Subpaths (GDPR example)

```
secid:regulation/europa.eu/gdpr#art-32          # Article 32
secid:regulation/europa.eu/gdpr#art-32.1        # Paragraph 1
secid:regulation/europa.eu/gdpr#art-32.1.a      # Subparagraph (a)
secid:regulation/europa.eu/gdpr#chapter-4       # Chapter IV
secid:regulation/europa.eu/gdpr#recital-78      # Recital 78
```

## Notes

- Regulations apply directly in member states
- Directives require national implementation
- EU AI Act effective August 2025
