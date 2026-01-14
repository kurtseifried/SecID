---
namespace: aws
full_name: "Amazon Web Services"
website: "https://aws.amazon.com"
type: corporation
founded: 2006
headquarters: "Seattle, Washington, USA"
parent: "Amazon.com, Inc."
---

# Amazon Web Services (AWS)

AWS is the world's largest cloud computing platform, offering hundreds of services including compute (EC2), storage (S3), databases, and more. AWS Security handles vulnerabilities in AWS services and Amazon Linux.

## Why AWS Matters for Security

AWS runs a significant portion of the internet:

- **EC2** - Virtual machines
- **S3** - Object storage
- **Lambda** - Serverless compute
- **IAM** - Identity and access management
- **Amazon Linux** - AWS's Linux distribution

AWS infrastructure vulnerabilities can affect thousands of organizations.

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `alas` | Amazon Linux Security Advisories | ALAS2-2024-2400 |

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
