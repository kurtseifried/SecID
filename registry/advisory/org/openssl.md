---
type: advisory
namespace: openssl.org
full_name: "OpenSSL Project"
operator: "secid:entity/openssl.org"
website: "https://openssl-library.org"
status: active

sources:
  secadv:
    full_name: "OpenSSL Security Advisory"
    urls:
      website: "https://openssl-library.org/news/secadv/"
      lookup: "https://openssl-library.org/news/secadv/{date}.txt"
      legacy: "https://www.openssl.org/news/secadv/"
    id_patterns:
      - pattern: "CVE-\\d{4}-\\d{4,}"
        description: "CVE identifier"
      - pattern: "\\d{8}"
        description: "Advisory date (YYYYMMDD)"
    examples:
      - "secid:advisory/openssl.org/secadv#CVE-2024-0727"
      - "secid:advisory/openssl.org/secadv#CVE-2014-0160"
      - "secid:advisory/openssl.org/secadv#20240125"
---

# OpenSSL Advisory Sources

OpenSSL is a widely-used open-source cryptographic library implementing SSL/TLS protocols. It's a critical dependency for most internet infrastructure.

## Why OpenSSL Matters for Security

OpenSSL is everywhere:

- **Web servers** - Apache, nginx, etc. use OpenSSL for HTTPS
- **Programming languages** - Python, Ruby, PHP link against OpenSSL
- **Applications** - curl, git, databases, and countless others
- **Operating systems** - Default TLS library on most Linux distributions

An OpenSSL vulnerability can affect nearly every internet-connected system.

## Notable Vulnerabilities

| CVE | Name | Impact |
|-----|------|--------|
| CVE-2014-0160 | **Heartbleed** | Memory disclosure, one of the most famous vulnerabilities |
| CVE-2014-0224 | CCS Injection | Man-in-the-middle attacks |
| CVE-2022-3602 | X.509 buffer overflow | Potential code execution |

## Advisory Format

OpenSSL advisories are published as text files by date:
```
https://openssl-library.org/news/secadv/20140407.txt  (Heartbleed)
```

Multiple CVEs may be grouped in a single dated advisory.

## Notes

- OpenSSL 3.x is the current major version; 1.1.1 reached end-of-life
- LibreSSL and BoringSSL are forks with different security properties
- The OpenSSL project moved to openssl-library.org (openssl.org redirects)

---

## secadv

OpenSSL project security advisories.

### Format

```
secid:advisory/openssl.org/secadv#CVE-YYYY-NNNN
secid:advisory/openssl.org/secadv#YYYYMMDD
```

Can reference by CVE or advisory date.

### Resolution

```
secid:advisory/openssl.org/secadv#CVE-2014-0160
  -> https://www.openssl.org/news/secadv/20140407.txt (Heartbleed)
```

### Notable Vulnerabilities

| CVE | Name | Date |
|-----|------|------|
| CVE-2014-0160 | Heartbleed | 2014-04-07 |
| CVE-2014-0224 | CCS Injection | 2014-06-05 |
| CVE-2015-0291 | ClientHello DoS | 2015-03-19 |
| CVE-2022-3602 | X.509 buffer overflow | 2022-11-01 |

### Notes

- OpenSSL vulnerabilities have widespread impact
- Critical infrastructure dependency
- Advisories grouped by date, may contain multiple CVEs
