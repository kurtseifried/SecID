---
type: advisory
namespace: aws
name: alas
full_name: "Amazon Linux Security Advisories"
operator: "secid:entity/aws"

urls:
  website: "https://alas.aws.amazon.com"
  api: "https://alas.aws.amazon.com/AL2/alas.rss"
  lookup: "https://alas.aws.amazon.com/{id}.html"

id_patterns:
  - pattern: "ALAS-\\d{4}-\\d+"
    system: "Amazon Linux 1"
    url: "https://alas.aws.amazon.com/{id}.html"
  - pattern: "ALAS2-\\d{4}-\\d+"
    system: "Amazon Linux 2"
    url: "https://alas.aws.amazon.com/AL2/{id}.html"
  - pattern: "ALAS2023-\\d{4}-\\d+"
    system: "Amazon Linux 2023"
    url: "https://alas.aws.amazon.com/AL2023/{id}.html"

examples:
  - "secid:advisory/aws/alas#ALAS2-2024-2400"
  - "secid:advisory/aws/alas#ALAS2023-2024-500"

status: active
---

# Amazon Linux Security Advisories (ALAS)

Security advisories for Amazon Linux distributions used in AWS EC2 and container environments.

## Format

```
secid:advisory/aws/alas#ALAS2-YYYY-NNNN
secid:advisory/aws/alas#ALAS2023-YYYY-NNN
```

## Resolution

URL varies by Amazon Linux version:
- AL1: `https://alas.aws.amazon.com/ALAS-YYYY-NNNN.html`
- AL2: `https://alas.aws.amazon.com/AL2/ALAS2-YYYY-NNNN.html`
- AL2023: `https://alas.aws.amazon.com/AL2023/ALAS2023-YYYY-NNN.html`

## Why ALAS Matters

Amazon Linux is the default OS for many AWS workloads:
- **EC2 instances** - Default AMI option
- **ECS/EKS containers** - Base images
- **Lambda** - Underlying runtime environment
- **Optimized for AWS** - Patching coordinated with AWS services

## Notes

- ALAS IDs include the distribution version prefix
- RSS feeds available for each distribution
- Cross-references CVE IDs where applicable
