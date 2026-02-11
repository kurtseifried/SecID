---
type: advisory
namespace: tencent.com
full_name: "Tencent"
operator: "secid:entity/tencent.com"
website: "https://www.tencent.com"
status: active

sources:
  tsrc:
    full_name: "Tencent Security Response Center"
    urls:
      website: "https://en.security.tencent.com/"
      report: "https://en.security.tencent.com/index.php/report/add"
    examples:
      - "secid:advisory/tencent.com/tsrc#vulnerability-id"

  cloud:
    full_name: "Tencent Cloud Security Advisory"
    urls:
      website: "https://www.tencentcloud.com/document/product/627/38433"
      console: "https://console.tencentcloud.com/security"
    examples:
      - "secid:advisory/tencent.com/cloud#advisory-id"
---

# Tencent Advisory Sources

Tencent is one of the world's largest technology companies, operating WeChat, QQ, Tencent Cloud, and many other services primarily in China and Asia.

## Why Tencent Matters for Security

Tencent's products have massive user bases:

- **WeChat** - Over 1 billion users
- **QQ** - Major messaging platform
- **Tencent Cloud** - Major cloud provider in China
- **Gaming** - Largest gaming company globally
- **RapidJSON** - Widely used open-source JSON library

## Tencent Security Response Center (TSRC)

TSRC handles vulnerability disclosure and bug bounty:
- Operates threat bounty program
- Coordinates with security researchers
- Monitors and analyzes vulnerabilities
- Helps developers fix issues

## Notes

- Tencent is a CVE Numbering Authority (CNA)
- WeChat vulnerabilities can have widespread impact
- Tencent Cloud serves major Chinese enterprises
- RapidJSON is used in many third-party projects

---

## tsrc

Tencent Security Response Center handles vulnerability reports and coordinates fixes.

### Format

```
secid:advisory/tencent.com/tsrc#<vulnerability-id>
```

### Coverage

| Product | Description |
|---------|-------------|
| WeChat | Messaging and social platform |
| QQ | Messaging platform |
| Tencent Games | Gaming platforms |
| Other products | Various Tencent services |

### Bug Bounty Program

TSRC operates a vulnerability reward program:
- Accepts reports for all Tencent products
- Rewards based on severity and impact
- Coordinated disclosure process

### Notable Vulnerabilities

| Product | Issue Type |
|---------|------------|
| WeChat | RCE via custom browser (2024) |
| RapidJSON | Integer overflow/underflow |
| Various | Privilege escalation |

### Notes

- English portal available
- Reports accepted from global researchers
- Response typically within business days

---

## cloud

Tencent Cloud security advisories covering cloud service vulnerabilities.

### Format

```
secid:advisory/tencent.com/cloud#<advisory-id>
```

### Coverage

| Service | Description |
|---------|-------------|
| CVM | Cloud Virtual Machine |
| TKE | Tencent Kubernetes Engine |
| COS | Cloud Object Storage |
| WAF | Web Application Firewall |

### Advisory Types

| Type | Description |
|------|-------------|
| Service vulnerabilities | Issues in Tencent Cloud services |
| Infrastructure | Underlying platform issues |
| Third-party components | Log4j, OpenSSL, etc. |

### Notes

- Part of Tencent Cloud documentation
- Covers cloud-specific security issues
- Customer notification system available
