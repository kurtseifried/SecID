---
type: control
namespace: nist
full_name: "National Institute of Standards and Technology"
operator: "secid:entity/nist"
website: "https://www.nist.gov"
status: active

sources:
  800-53:
    full_name: "NIST SP 800-53 Security Controls"
    urls:
      website: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"
      lookup: "https://csrc.nist.gov/Projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home"
    id_pattern: "[A-Z]{2}-\\d+(\\.\\d+)?"
    versions:
      - "rev5"
      - "rev4"
    examples:
      - "secid:control/nist/800-53@rev5#AC-1"
      - "secid:control/nist/800-53@rev5#AC-2"
      - "secid:control/nist/800-53@rev5#SI-7"

  csf:
    full_name: "NIST Cybersecurity Framework"
    urls:
      website: "https://www.nist.gov/cyberframework"
      lookup: "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/"
    id_pattern: "[A-Z]{2}(\\.[A-Z]{2})?-\\d{2}"
    versions:
      - "2.0"
      - "1.1"
    examples:
      - "secid:control/nist/csf@2.0#GV.RM-01"
      - "secid:control/nist/csf@2.0#ID.AM-01"
      - "secid:control/nist/csf@2.0#PR.AC-01"
---

# NIST Control Frameworks

NIST produces authoritative security control frameworks used globally as references for cybersecurity requirements.

## Why NIST Matters for Controls

NIST provides the official US government perspective on security controls:

- **Authoritative** - Federal agency with regulatory influence
- **Research-backed** - Extensive technical research
- **Policy foundation** - Referenced in executive orders and regulations
- **International recognition** - Used globally as reference

---

## 800-53

Federal security and privacy controls.

### Format

```
secid:control/nist/800-53[@VERSION]#CONTROL-ID
secid:control/nist/800-53@rev5#AC-1
secid:control/nist/800-53#AC-1           # Current version
```

### Control Families

| Code | Family |
|------|--------|
| AC | Access Control |
| AT | Awareness and Training |
| AU | Audit and Accountability |
| CA | Assessment, Authorization |
| CM | Configuration Management |
| CP | Contingency Planning |
| IA | Identification and Authentication |
| IR | Incident Response |
| MA | Maintenance |
| MP | Media Protection |
| PE | Physical and Environmental |
| PL | Planning |
| PM | Program Management |
| PS | Personnel Security |
| PT | PII Processing |
| RA | Risk Assessment |
| SA | System and Services Acquisition |
| SC | System and Communications Protection |
| SI | System and Information Integrity |
| SR | Supply Chain Risk Management |

### Notes

- Mandatory for US federal systems
- Rev 5 includes privacy controls
- Basis for FedRAMP, FISMA compliance

---

## csf

Cybersecurity Framework for managing and reducing cyber risk.

### Format

```
secid:control/nist/csf[@VERSION]#CONTROL-ID
secid:control/nist/csf@2.0#GV.RM-01
secid:control/nist/csf#PR.AC-01          # Current version
```

### Functions (CSF 2.0)

| Code | Function |
|------|----------|
| GV | Govern |
| ID | Identify |
| PR | Protect |
| DE | Detect |
| RS | Respond |
| RC | Recover |

### Example Controls

| ID | Name |
|----|------|
| GV.RM-01 | Risk Management Strategy |
| ID.AM-01 | Asset Inventory |
| PR.AC-01 | Identity Management |

### Notes

- CSF 2.0 released 2024 (adds Govern function)
- Maps to other frameworks (ISO 27001, CIS)
- Includes implementation tiers
