---
type: advisory
namespace: aws
full_name: "Amazon Web Services"
operator: "secid:entity/aws"
website: "https://aws.amazon.com"
status: active

sources:
  security-bulletins:
    full_name: "AWS Security Bulletins"
    urls:
      website: "https://aws.amazon.com/security/security-bulletins/"
      rss: "https://aws.amazon.com/security/security-bulletins/feed/"
    examples:
      - "secid:advisory/aws/security-bulletins#AWS-2024-001"

  alas:
    full_name: "Amazon Linux Security Advisories"
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
---

# AWS Advisory Sources

AWS is the world's largest cloud computing platform, offering hundreds of services including compute (EC2), storage (S3), databases, and more. AWS Security handles vulnerabilities in AWS services and Amazon Linux.

## Why AWS Matters for Security

AWS runs a significant portion of the internet:

- **EC2** - Virtual machines
- **S3** - Object storage
- **Lambda** - Serverless compute
- **IAM** - Identity and access management
- **Amazon Linux** - AWS's Linux distribution

AWS infrastructure vulnerabilities can affect thousands of organizations.

## ALAS (Amazon Linux Security Advisories)

ALAS advisories cover Amazon Linux distributions:
- **ALAS-** - Amazon Linux 1 (legacy)
- **ALAS2-** - Amazon Linux 2
- **ALAS2023-** - Amazon Linux 2023

Format: `ALAS2-YYYY-NNNN`

## Shared Responsibility Model

AWS security follows shared responsibility:
- **AWS responsibility** - Security OF the cloud (infrastructure)
- **Customer responsibility** - Security IN the cloud (data, applications)

AWS security bulletins cover AWS's responsibility; customers must handle their own workload security.

## Notes

- AWS Security Bulletins cover service-level issues
- Amazon Linux is optimized for EC2 but runs elsewhere
- AWS Inspector provides vulnerability scanning for EC2/containers
- Many "AWS vulnerabilities" are actually customer misconfigurations

---

## security-bulletins

AWS Security Bulletins cover security issues affecting AWS services and infrastructure.

### Format

```
secid:advisory/aws/security-bulletins#<bulletin-id>
```

### Coverage

| Category | Examples |
|----------|----------|
| **Service vulnerabilities** | S3, EC2, Lambda issues |
| **Infrastructure** | Underlying AWS platform |
| **Third-party components** | Log4j, OpenSSL in AWS services |
| **Cross-service issues** | Shared component vulnerabilities |

### Why AWS Security Bulletins Matter

Bulletins cover AWS's responsibility in the shared model:
- **Service-level CVEs** - Vulnerabilities in AWS services
- **Patch notifications** - When AWS has patched infrastructure
- **Customer action required** - When customers need to update
- **Mitigation guidance** - Workarounds and recommendations

### Notable Bulletins

| Issue | Impact |
|-------|--------|
| Log4Shell | AWS services using Log4j |
| OpenSSL | Services with affected versions |
| Container escapes | EKS, ECS implications |

### Notes

- Covers AWS services, not customer workloads
- May reference CVEs but includes AWS-specific context
- RSS feed available for notifications
- Different from ALAS (Amazon Linux advisories)

---

## alas

Security advisories for Amazon Linux distributions used in AWS EC2 and container environments.

### Format

```
secid:advisory/aws/alas#ALAS2-YYYY-NNNN
secid:advisory/aws/alas#ALAS2023-YYYY-NNN
```

### Resolution

URL varies by Amazon Linux version:
- AL1: `https://alas.aws.amazon.com/ALAS-YYYY-NNNN.html`
- AL2: `https://alas.aws.amazon.com/AL2/ALAS2-YYYY-NNNN.html`
- AL2023: `https://alas.aws.amazon.com/AL2023/ALAS2023-YYYY-NNN.html`

### Why ALAS Matters

Amazon Linux is the default OS for many AWS workloads:
- **EC2 instances** - Default AMI option
- **ECS/EKS containers** - Base images
- **Lambda** - Underlying runtime environment
- **Optimized for AWS** - Patching coordinated with AWS services

### Notes

- ALAS IDs include the distribution version prefix
- RSS feeds available for each distribution
- Cross-references CVE IDs where applicable
