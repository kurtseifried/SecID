---
namespace: openssl
full_name: "OpenSSL Project"
website: "https://openssl-library.org"
type: opensource
founded: 1998
---

# OpenSSL Project

OpenSSL is a widely-used open-source cryptographic library implementing SSL/TLS protocols. It's a critical dependency for most internet infrastructure.

## Why OpenSSL Matters for Security

OpenSSL is everywhere:

- **Web servers** - Apache, nginx, etc. use OpenSSL for HTTPS
- **Programming languages** - Python, Ruby, PHP link against OpenSSL
- **Applications** - curl, git, databases, and countless others
- **Operating systems** - Default TLS library on most Linux distributions

An OpenSSL vulnerability can affect nearly every internet-connected system.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `secadv` | Security Advisories | CVE-2014-0160, 20140407 |

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
