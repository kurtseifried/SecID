---
type: advisory
namespace: huawei
full_name: "Huawei Technologies"
operator: "secid:entity/huawei"
website: "https://www.huawei.com"
status: active

sources:
  psirt:
    full_name: "Huawei PSIRT Security Advisories"
    urls:
      website: "https://www.huawei.com/en/psirt"
      all-bulletins: "https://www.huawei.com/en/psirt/all-bulletins"
      report: "https://www.huawei.com/en/psirt/report-vulnerabilities"
    id_pattern: "HWPSIRT-\\d{4}-\\d+"
    examples:
      - "secid:advisory/huawei/psirt#HWPSIRT-2024-12345"

  security-advisories:
    full_name: "Huawei Security Advisories"
    urls:
      website: "https://www.huawei.com/en/psirt/security-advisories"
      lookup: "https://www.huawei.com/en/psirt/security-advisories/{year}/"
    examples:
      - "secid:advisory/huawei/security-advisories#huawei-sa-xxxxx"

  security-notices:
    full_name: "Huawei Security Notices"
    urls:
      website: "https://www.huawei.com/en/psirt/security-notices"
    examples:
      - "secid:advisory/huawei/security-notices#huawei-sn-xxxxx"
---

# Huawei Advisory Sources

Huawei is a major global technology company producing telecommunications equipment, consumer electronics, and cloud services.

## Why Huawei Matters for Security

Huawei products are deployed globally:

- **Network Equipment** - Routers, switches, 5G infrastructure
- **Consumer Devices** - Smartphones, tablets, PCs
- **Enterprise** - Data center, storage, servers
- **Cloud** - Huawei Cloud services
- **Smart Devices** - IoT, smart home

## Huawei PSIRT

Huawei Product Security Incident Response Team:
- Responds to vulnerability reports
- Coordinates fixes with product teams
- Publishes advisories and notices
- Manages vulnerability lifecycle

## Advisory Types

| Type | Description |
|------|-------------|
| Security Advisory | Confirmed vulnerabilities requiring action |
| Security Notice | Informational security updates |
| Security Bulletin | Routine security information |

## Notes

- PSIRT email: psirt@huawei.com
- Follows coordinated disclosure
- Vulnerabilities managed until End of Support
- Critical/High severity fixes prioritized

---

## psirt

Huawei PSIRT manages vulnerability response and publishes all security bulletins.

### Format

```
secid:advisory/huawei/psirt#HWPSIRT-YYYY-NNNNN
```

### Coverage

| Product Category | Examples |
|------------------|----------|
| Network | Routers, switches, firewalls |
| Wireless | 5G, LTE, WiFi equipment |
| Consumer | Phones, tablets, laptops |
| Enterprise | Servers, storage, data center |
| Cloud | Huawei Cloud services |

### Vulnerability Response Process

1. **Receipt** - Report received by PSIRT
2. **Triage** - Initial assessment and prioritization
3. **Analysis** - Technical investigation
4. **Remediation** - Fix development
5. **Disclosure** - Advisory publication

### Severity Scoring

Huawei uses CVSS with additional context:
- SSR (Security Severity Rating): Critical, High, Medium, Low
- Critical/High vulnerabilities fixed promptly
- Remediation provided before End of Full Support

### Notes

- All bulletins: https://www.huawei.com/en/psirt/all-bulletins
- Report vulnerabilities: psirt@huawei.com
- PGP key available for encrypted reports

---

## security-advisories

Detailed security advisories for confirmed vulnerabilities.

### Format

```
secid:advisory/huawei/security-advisories#huawei-sa-<id>
```

### Advisory Contents

| Section | Description |
|---------|-------------|
| Summary | Vulnerability overview |
| Affected Products | Versions impacted |
| CVE | Associated CVE identifier |
| CVSS | Severity score |
| Impact | Potential consequences |
| Solution | Remediation steps |
| Acknowledgment | Reporter credit |

### 2024 Examples

| Product | Issue |
|---------|-------|
| Home Routers | Connection hijacking |
| PC Products | Interface access control |
| Smart Speakers | Memory overflow |

### Resolution

Advisories available at:
```
https://www.huawei.com/en/psirt/security-advisories/{year}/
```

### Notes

- Published when fix is available
- Include workarounds if applicable
- Coordinated with researchers

---

## security-notices

Informational security notices for general awareness.

### Format

```
secid:advisory/huawei/security-notices#huawei-sn-<id>
```

### Content Types

| Type | Description |
|------|-------------|
| Third-party issues | OpenSSL, Log4j, etc. |
| Industry alerts | Broader security trends |
| Best practices | Security recommendations |
| Updates | Product security enhancements |

### Notes

- May not have associated CVE
- Informational rather than action-required
- General security guidance
