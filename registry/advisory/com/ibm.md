---
type: advisory
namespace: ibm.com
full_name: "IBM Corporation"
operator: "secid:entity/ibm.com"
website: "https://www.ibm.com"
status: active

sources:
  security-bulletin:
    full_name: "IBM Security Bulletins"
    urls:
      website: "https://www.ibm.com/support/pages/bulletin/"
      search: "https://www.ibm.com/support/pages/bulletin/"
      overview: "https://www.ibm.com/trust/security-bulletins"
    examples:
      - "secid:advisory/ibm.com/security-bulletin#bulletin-id"

  cloud:
    full_name: "IBM Cloud Security Bulletins"
    urls:
      website: "https://cloud.ibm.com/status/security"
    examples:
      - "secid:advisory/ibm.com/cloud#bulletin-id"

  psirt:
    full_name: "IBM Product Security Incident Response"
    urls:
      website: "https://www.ibm.com/trust/security-vulnerability-management"
      report: "https://www.ibm.com/support/pages/ibm-security-vulnerability-management"
    examples:
      - "secid:advisory/ibm.com/psirt"

  xforce:
    full_name: "IBM X-Force Exchange"
    urls:
      website: "https://exchange.xforce.ibmcloud.com/"
      vulnerabilities: "https://exchange.xforce.ibmcloud.com/vulnerabilities"
    examples:
      - "secid:advisory/ibm.com/xforce#vulnerability-id"
---

# IBM Advisory Sources

IBM is a major enterprise technology company with products spanning cloud, AI, middleware, databases, and systems.

## Why IBM Matters for Security

IBM products are core enterprise infrastructure:

- **IBM Cloud** - Enterprise cloud platform
- **WebSphere** - Application server
- **Db2** - Enterprise database
- **MQ** - Message queuing
- **Cloud Pak** - Kubernetes-based software suite
- **IBM i** - Midrange systems

## Security Bulletin Process

IBM communicates vulnerabilities through:
1. Security bulletins for product-specific issues
2. Targeted notifications for critical issues
3. X-Force Exchange for threat intelligence

## Notes

- IBM is a CVE Numbering Authority (CNA)
- Bulletins reference CVEs with IBM-specific context
- Cloud Pak updates often bundle multiple CVE fixes
- X-Force provides additional threat context

---

## security-bulletin

IBM Security Bulletins provide vulnerability information for IBM products.

### Format

```
secid:advisory/ibm.com/security-bulletin#<bulletin-id>
```

### Coverage

| Product Category | Examples |
|------------------|----------|
| Middleware | WebSphere, MQ, Integration Bus |
| Databases | Db2, Informix |
| Cloud Paks | Business Automation, Data, Integration |
| Systems | IBM i, AIX, z/OS |
| Security | QRadar, Guardium |

### Bulletin Contents

| Section | Description |
|---------|-------------|
| Summary | Brief description |
| Vulnerability Details | CVEs addressed |
| Affected Products | Versions impacted |
| Remediation | Patches and workarounds |
| References | Related resources |

### Search and Discovery

Query bulletins by:
- Product name
- CVE identifier
- Date range
- Severity

### Notes

- Searchable bulletin database
- Email notifications available
- PDF downloads for documentation
- Links to Fix Central for patches

---

## cloud

IBM Cloud security bulletins for cloud service vulnerabilities.

### Format

```
secid:advisory/ibm.com/cloud#<bulletin-id>
```

### Coverage

| Service | Description |
|---------|-------------|
| Kubernetes Service | IKS vulnerabilities |
| OpenShift | ROKS issues |
| Cloud Foundry | PaaS vulnerabilities |
| Virtual Servers | Infrastructure issues |
| Cloud Databases | Managed DB services |

### Resolution

Access at `https://cloud.ibm.com/status/security`

### Notes

- Real-time security status
- Covers IBM Cloud services
- Customer action items highlighted

---

## psirt

IBM Product Security Incident Response Team handles vulnerability coordination.

### Format

```
secid:advisory/ibm.com/psirt
```

### Process

1. Vulnerability reported to PSIRT
2. Analysis and triage
3. Fix development
4. Bulletin publication
5. Patch availability

### Reporting

Report vulnerabilities to IBM PSIRT:
- Email: psirt@us.ibm.com
- Web form on IBM Support

### Notes

- Coordinates with researchers
- Follows responsible disclosure
- Part of IBM Trust Center

---

## xforce

IBM X-Force Exchange provides threat intelligence and vulnerability data.

### Format

```
secid:advisory/ibm.com/xforce#<vulnerability-id>
```

### Coverage

| Content Type | Description |
|--------------|-------------|
| Vulnerabilities | CVE details and analysis |
| Threat actors | APT tracking |
| Malware | Malware analysis |
| Indicators | IoCs and TTPs |

### Features

- Vulnerability database
- Threat intelligence reports
- API access
- Community contributions

### Notes

- Free registration for access
- API for integration
- Broader than just IBM products
- Threat research publications
