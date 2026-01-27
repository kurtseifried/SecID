---
type: control
namespace: iso
full_name: "International Organization for Standardization"
operator: "secid:entity/iso"
website: "https://www.iso.org"
status: active

sources:
  27001:
    full_name: "ISO/IEC 27001 Information Security Management"
    urls:
      website: "https://www.iso.org/standard/27001"
      overview: "https://www.iso.org/isoiec-27001-information-security.html"
    id_pattern: "A\\.\\d+\\.\\d+"
    versions:
      - "2022"
      - "2013"
    examples:
      - "secid:control/iso/27001@2022#A.5.1"
      - "secid:control/iso/27001@2022#A.8.2"
      - "secid:control/iso/27001@2013#A.5.1.1"

  27002:
    full_name: "ISO/IEC 27002 Information Security Controls"
    urls:
      website: "https://www.iso.org/standard/75652.html"
      overview: "https://www.iso.org/standard/75652.html"
    id_pattern: "\\d+\\.\\d+(\\.\\d+)?"
    versions:
      - "2022"
      - "2013"
    examples:
      - "secid:control/iso/27002@2022#5.1"
      - "secid:control/iso/27002@2022#8.2"

  42001:
    full_name: "ISO/IEC 42001 AI Management System"
    urls:
      website: "https://www.iso.org/standard/81230.html"
    versions:
      - "2023"
    examples:
      - "secid:control/iso/42001@2023"

  23894:
    full_name: "ISO/IEC 23894 AI Risk Management"
    urls:
      website: "https://www.iso.org/standard/77304.html"
    versions:
      - "2023"
    examples:
      - "secid:control/iso/23894@2023"

  24028:
    full_name: "ISO/IEC 24028 AI Trustworthiness"
    urls:
      website: "https://www.iso.org/standard/77608.html"
    versions:
      - "2020"
    examples:
      - "secid:control/iso/24028@2020"

  24029:
    full_name: "ISO/IEC 24029 AI Robustness"
    urls:
      website: "https://www.iso.org/standard/77609.html"
    versions:
      - "2021"
    examples:
      - "secid:control/iso/24029@2021"
---

# ISO Information Security Standards

The International Organization for Standardization (ISO) publishes globally recognized information security standards. The ISO/IEC 27000 series is the most widely adopted information security management framework.

## Why ISO Matters for Controls

ISO 27001 is the global standard for information security management:

- **Certification standard** - Organizations get ISO 27001 certified
- **Compliance requirement** - Many contracts and regulations require ISO 27001
- **Global recognition** - Accepted worldwide, unlike some national standards
- **Comprehensive** - Covers organizational, technical, and physical controls

## ISO 27001 vs 27002

| Standard | Purpose |
|----------|---------|
| **ISO 27001** | Requirements for ISMS (certification standard) |
| **ISO 27002** | Implementation guidance for controls |

ISO 27001 Annex A contains the control objectives. ISO 27002 provides detailed implementation guidance for each control.

## 2022 vs 2013 Versions

The 2022 version restructured controls significantly:

| Version | Control Structure |
|---------|-------------------|
| **2013** | 14 domains, 114 controls (A.5 through A.18) |
| **2022** | 4 themes, 93 controls (organizational, people, physical, technological) |

Control numbering changed between versions - always specify version when referencing.

---

## 27001

ISO/IEC 27001 Information Security Management System requirements, including Annex A controls.

### Format

```
secid:control/iso/27001[@VERSION]#A.N.N
secid:control/iso/27001@2022#A.5.1
secid:control/iso/27001@2013#A.5.1.1
```

### 2022 Control Themes

| Theme | Prefix | Controls |
|-------|--------|----------|
| Organizational | A.5 | 37 controls |
| People | A.6 | 8 controls |
| Physical | A.7 | 14 controls |
| Technological | A.8 | 34 controls |

### Example Controls (2022)

| ID | Name |
|----|------|
| A.5.1 | Policies for information security |
| A.5.7 | Threat intelligence |
| A.6.3 | Information security awareness and training |
| A.7.4 | Physical security monitoring |
| A.8.2 | Privileged access rights |
| A.8.11 | Data masking |
| A.8.28 | Secure coding |

### 2013 Control Domains (Legacy)

| Domain | Name |
|--------|------|
| A.5 | Information Security Policies |
| A.6 | Organization of Information Security |
| A.7 | Human Resource Security |
| A.8 | Asset Management |
| A.9 | Access Control |
| A.10 | Cryptography |
| A.11 | Physical and Environmental Security |
| A.12 | Operations Security |
| A.13 | Communications Security |
| A.14 | System Acquisition, Development and Maintenance |
| A.15 | Supplier Relationships |
| A.16 | Information Security Incident Management |
| A.17 | Information Security Aspects of BCM |
| A.18 | Compliance |

### Resolution Notes

ISO standards are not freely available online - they must be purchased from ISO or national standards bodies. Some derivative resources (like ISO 27002 summaries) are available.

### Notes

- ISO 27001 is a certification standard - organizations can be certified
- Annex A controls are normative (required for certification)
- Version matters: 2022 restructured significantly from 2013
- Maps to NIST CSF, CIS Controls, and other frameworks

---

## 27002

ISO/IEC 27002 provides detailed implementation guidance for the controls referenced in ISO 27001 Annex A.

### Format

```
secid:control/iso/27002[@VERSION]#N.N
secid:control/iso/27002@2022#5.1
secid:control/iso/27002@2022#8.2
```

### Relationship to 27001

| Standard | Contains |
|----------|----------|
| ISO 27001 Annex A | Control objectives (what to do) |
| ISO 27002 | Implementation guidance (how to do it) |

The control numbering in 27002 matches Annex A, minus the "A." prefix:
- `secid:control/iso/27001@2022#A.5.1` - Control objective
- `secid:control/iso/27002@2022#5.1` - Implementation guidance

### Notes

- Not a certification standard (you certify to 27001, not 27002)
- Provides detailed implementation guidance
- Updated alongside 27001 (2022 is current)
- Useful for understanding how to implement controls
