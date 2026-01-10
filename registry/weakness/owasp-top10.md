---
namespace: owasp-top10
full_name: "OWASP Top 10"
type: weakness
operator: "secid:entity/owasp/top-10"

urls:
  website: "https://owasp.org/www-project-top-ten/"
  lookup: "https://owasp.org/Top10/A{num}_{year}_{name}/"

id_pattern: "A\\d{2}(-\\d{4})?"
versions:
  - "2021"
  - "2017"
  - "2013"

examples:
  - "A01-2021"
  - "A03-2021"
  - "A01"

status: active
---

# OWASP Top 10 Namespace

The most critical web application security risks.

## Format

```
secid:weakness/owasp-top10/A0N@YYYY
secid:weakness/owasp-top10/A0N           # Current version
```

## 2021 Edition

| ID | Name |
|----|------|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification and Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging and Monitoring Failures |
| A10 | Server-Side Request Forgery |

## Notes

- Updated every 3-4 years
- Version matters: A01@2021 ≠ A01@2017
- Maps to CWEs
