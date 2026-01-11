---
type: weakness
namespace: owasp
name: top10
full_name: "OWASP Top 10"
operator: "secid:entity/owasp"

urls:
  website: "https://owasp.org/www-project-top-ten/"
  lookup: "https://owasp.org/Top10/A{num}_{year}_{name}/"

id_pattern: "A\\d{2}"
versions:
  - "2021"
  - "2017"
  - "2013"

examples:
  - "secid:weakness/owasp/top10@2021#A01"
  - "secid:weakness/owasp/top10@2021#A03"
  - "secid:weakness/owasp/top10#A01"

status: active
---

# OWASP Top 10 Namespace

The most critical web application security risks.

## Format

```
secid:weakness/owasp/top10[@YEAR]#ITEM
secid:weakness/owasp/top10@2021#A03
secid:weakness/owasp/top10#A01           # Current version
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
- Version matters: top10@2021#A01 ≠ top10@2017#A01
- Maps to CWEs

