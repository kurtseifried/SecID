---
type: control
namespace: cisecurity.org
full_name: "CIS Critical Security Controls"
operator: "secid:entity/cisecurity.org"
website: "https://www.cisecurity.org/controls"
status: active

sources:
  controls:
    full_name: "CIS Critical Security Controls"
    urls:
      website: "https://www.cisecurity.org/controls"
      lookup: "https://www.cisecurity.org/controls/v8"
    id_pattern: "\\d+\\.\\d+"
    versions:
      - "8.0"
      - "7.1"
    examples:
      - "secid:control/cisecurity.org/controls@8.0#1.1"
      - "secid:control/cisecurity.org/controls@8.0#4.1"
      - "secid:control/cisecurity.org/controls@8.0#16.1"
---

# CIS Control Frameworks

Prioritized security actions for cyber defense from the Center for Internet Security.

## Why CIS Matters for Controls

CIS Controls provide prioritized, actionable security guidance:

- **Prioritized by effectiveness** - Controls ordered by impact
- **Implementation groups** - Scaled for organization size
- **Mappings** - Links to NIST CSF, ISO 27001
- **Community-driven** - Consensus from practitioners

---

## controls

Prioritized security actions for cyber defense.

### Format

```
secid:control/cisecurity.org/controls[@VERSION]#N.N
secid:control/cisecurity.org/controls@8.0#1.1
```

### CIS Controls v8

| # | Control |
|---|---------|
| 1 | Inventory and Control of Enterprise Assets |
| 2 | Inventory and Control of Software Assets |
| 3 | Data Protection |
| 4 | Secure Configuration |
| 5 | Account Management |
| 6 | Access Control Management |
| 7 | Continuous Vulnerability Management |
| 8 | Audit Log Management |
| 9 | Email and Web Browser Protections |
| 10 | Malware Defenses |
| 11 | Data Recovery |
| 12 | Network Infrastructure Management |
| 13 | Network Monitoring and Defense |
| 14 | Security Awareness Training |
| 15 | Service Provider Management |
| 16 | Application Software Security |
| 17 | Incident Response Management |
| 18 | Penetration Testing |

### Implementation Groups

- IG1: Basic (essential cyber hygiene)
- IG2: Standard (growing organizations)
- IG3: Advanced (mature security programs)

### Notes

- Prioritized by effectiveness
- Maps to NIST CSF, ISO 27001
- Includes implementation guidance
