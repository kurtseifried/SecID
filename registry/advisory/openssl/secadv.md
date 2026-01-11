---
type: advisory
namespace: openssl
name: secadv
full_name: "OpenSSL Security Advisory"
operator: "secid:entity/openssl"

urls:
  website: "https://www.openssl.org/news/secadv/"
  lookup: "https://www.openssl.org/news/secadv/{date}.txt"

id_patterns:
  - pattern: "CVE-\\d{4}-\\d{4,}"
    description: "CVE identifier"
  - pattern: "\\d{8}"
    description: "Advisory date (YYYYMMDD)"

examples:
  - "secid:advisory/openssl/secadv#CVE-2024-0727"
  - "secid:advisory/openssl/secadv#CVE-2014-0160"
  - "secid:advisory/openssl/secadv#20240125"

status: active
---

# OpenSSL Security Advisory

OpenSSL project security advisories.

## Format

```
secid:advisory/openssl/secadv#CVE-YYYY-NNNN
secid:advisory/openssl/secadv#YYYYMMDD
```

Can reference by CVE or advisory date.

## Resolution

```
secid:advisory/openssl/secadv#CVE-2014-0160
  → https://www.openssl.org/news/secadv/20140407.txt (Heartbleed)
```

## Notable Vulnerabilities

| CVE | Name | Date |
|-----|------|------|
| CVE-2014-0160 | Heartbleed | 2014-04-07 |
| CVE-2014-0224 | CCS Injection | 2014-06-05 |
| CVE-2015-0291 | ClientHello DoS | 2015-03-19 |
| CVE-2022-3602 | X.509 buffer overflow | 2022-11-01 |

## Notes

- OpenSSL vulnerabilities have widespread impact
- Critical infrastructure dependency
- Advisories grouped by date, may contain multiple CVEs
