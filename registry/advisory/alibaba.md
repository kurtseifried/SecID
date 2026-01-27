---
type: advisory
namespace: alibaba
full_name: "Alibaba Cloud"
operator: "secid:entity/alibaba"
website: "https://www.alibabacloud.com"
status: active

sources:
  security:
    full_name: "Alibaba Security"
    urls:
      website: "https://security.alibaba.com"
      cloud-security: "https://www.alibabacloud.com/trust-center"
      security-center: "https://www.alibabacloud.com/product/security-center"
    examples:
      - "secid:advisory/alibaba/security"
---

# Alibaba Cloud Advisory Sources

Alibaba Cloud (Aliyun) is the largest cloud provider in China and a major global cloud platform.

## Advisory Status: Limited

Alibaba Cloud does not publish a formal public security advisory bulletin in English. Security resources include:

- **Alibaba Security portal** - security.alibaba.com
- **Trust Center** - Compliance and security overview
- **Security Center product** - Customer vulnerability management

## Available Security Resources

| Resource | URL | Description |
|----------|-----|-------------|
| Alibaba Security | security.alibaba.com | Security research and disclosure |
| Trust Center | alibabacloud.com/trust-center | Compliance and security |
| Security Center | alibabacloud.com/product/security-center | Vulnerability management service |

## Alibaba Cloud Security Center

For customers, Alibaba Cloud offers Security Center which:
- Detects vulnerabilities in customer workloads
- Uses Alibaba Cloud Vulnerability Scoring System (based on CVSS)
- Provides one-click fixes for some vulnerabilities
- Adds detection rules within 14×24 hours of vendor notices

## Vulnerability Scoring

Alibaba Cloud developed their own scoring system:
- Based on CVSS
- Incorporates real-world attack scenarios
- Considers exploit maturity
- Severity levels: Critical, High, Medium, Low

## Bug Bounty

Alibaba Group operates security research programs:
- Vulnerability reporting at security.alibaba.com
- Covers Alibaba ecosystem products
- Chinese language primary

## Why Limited English Advisories?

- Primary market is China
- Chinese-language resources more comprehensive
- Security Center focuses on customer workload security
- Infrastructure security managed internally

## Notes

- Major cloud provider in Asia-Pacific
- Security Center is a paid product for customers
- Chinese language security portal more detailed
- No public CVE-style advisory bulletin found
