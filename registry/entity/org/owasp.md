---

type: "entity"
namespace: "owasp.org"

common_name: "OWASP"
full_name: "Open Worldwide Application Security Project"

urls:
  website: "https://owasp.org"

names:
  top-10:
    full_name: "OWASP Top 10"
    urls:
      website: "https://owasp.org/www-project-top-ten/"
    issues_type: "weakness"
    issues_namespace: "owasp-top10"
  llm-top-10:
    full_name: "OWASP Top 10 for LLM Applications"
    urls:
      website: "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
      github: "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications"
    issues_type: "weakness"
    issues_namespace: "owasp-llm"
  aivss:
    full_name: "AI Vulnerability Scoring System"
    description: "Scoring system for AI-specific vulnerabilities (extends CVSS concepts for AI)"
    urls:
      website: "https://aivss.owasp.org"
    versions:
      - "0.5"
    notes: "No self-identifying string format yet; reference via entity, not as peer scheme"

wikidata: "Q1142418"
status: "active"
established: 2001
---


# OWASP

OWASP is a nonprofit foundation focused on improving software security. Key projects:

- **Top 10** - Web application security risks
- **LLM Top 10** - AI/LLM application security risks
- **AIVSS** - AI Vulnerability Scoring System
- **ASVS** - Application Security Verification Standard
- **Testing Guide** - Security testing methodology

## Names in This Namespace

| Name | Full Name | Type |
|------|-----------|------|
| `top10` | OWASP Top 10 | Issues `secid:weakness/owasp.org/top10#*` |
| `llm-top10` | OWASP Top 10 for LLM Applications | Issues `secid:weakness/owasp.org/llm-top10#*` |
| `aivss` | AI Vulnerability Scoring System | Scoring standard (no string format yet) |

## Examples

```
secid:entity/owasp.org/top10        # OWASP Top 10 project
secid:entity/owasp.org/llm-top10    # OWASP LLM Top 10 project
secid:entity/owasp.org/aivss        # AIVSS project generally
secid:entity/owasp.org/aivss@0.5    # AIVSS version 0.5 specification
```
