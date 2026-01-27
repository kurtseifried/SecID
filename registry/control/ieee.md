---
type: control
namespace: ieee
full_name: "Institute of Electrical and Electronics Engineers"
operator: "secid:entity/ieee"
website: "https://www.ieee.org"
status: active

sources:
  ethically-aligned:
    full_name: "Ethically Aligned Design"
    urls:
      website: "https://ethicsinaction.ieee.org"
      document: "https://standards.ieee.org/industry-connections/ec/autonomous-systems/"
    versions:
      - "1.0"
    examples:
      - "secid:control/ieee/ethically-aligned#human-rights"
      - "secid:control/ieee/ethically-aligned#well-being"

  7000:
    full_name: "IEEE 7000 - Ethical System Design"
    urls:
      website: "https://standards.ieee.org/ieee/7000/6781/"
      overview: "https://sagroithics.ieee.org/ieee-7000/"
    versions:
      - "2021"
    examples:
      - "secid:control/ieee/7000@2021"

  7001:
    full_name: "IEEE 7001 - Transparency of Autonomous Systems"
    urls:
      website: "https://standards.ieee.org/ieee/7001/6929/"
    versions:
      - "2021"
    examples:
      - "secid:control/ieee/7001@2021"

  7002:
    full_name: "IEEE 7002 - Data Privacy Process"
    urls:
      website: "https://standards.ieee.org/ieee/7002/6220/"
    versions:
      - "2022"
    examples:
      - "secid:control/ieee/7002@2022"

  7010:
    full_name: "IEEE 7010 - Well-being Metrics for AI"
    urls:
      website: "https://standards.ieee.org/ieee/7010/10050/"
    versions:
      - "2020"
    examples:
      - "secid:control/ieee/7010@2020"
---

# IEEE AI Ethics Standards

IEEE develops standards for ethical AI and autonomous systems, providing practical frameworks for implementing AI ethics in engineering practice.

## Why IEEE Standards Matter

IEEE brings engineering rigor to AI ethics:

- **Engineering focus** - Practical, implementable standards
- **Global adoption** - IEEE standards used worldwide
- **Process-oriented** - How to design ethical systems
- **Comprehensive** - Multiple standards covering different aspects

## The 7000 Series

IEEE's 7000 series addresses ethical concerns in autonomous and intelligent systems:

| Standard | Focus |
|----------|-------|
| 7000 | Model process for ethical design |
| 7001 | Transparency |
| 7002 | Data privacy |
| 7010 | Well-being metrics |

---

## ethically-aligned

Ethically Aligned Design (EAD) is IEEE's foundational document on AI ethics, providing principles and recommendations.

### Format

```
secid:control/ieee/ethically-aligned#<principle>
```

### General Principles

| Principle | Description |
|-----------|-------------|
| **Human Rights** | AI should respect human rights |
| **Well-being** | Prioritize human well-being |
| **Data Agency** | Individuals control their data |
| **Effectiveness** | AI should be effective and safe |
| **Transparency** | AI operations should be understandable |
| **Accountability** | Clear responsibility for AI actions |
| **Awareness of Misuse** | Safeguards against misuse |
| **Competence** | AI developers should be competent |

### Notes

- First edition 2019
- Foundational document for 7000 series
- Broad stakeholder input
- Free to access

---

## 7000

IEEE 7000 - Model Process for Addressing Ethical Concerns During System Design.

### Format

```
secid:control/ieee/7000@2021
```

### What It Provides

A systematic process for:
1. Identifying stakeholders and ethical values
2. Prioritizing ethical concerns
3. Translating values into system requirements
4. Validating ethical requirements are met

### Process Steps

| Step | Activity |
|------|----------|
| 1 | Concept of operations development |
| 2 | Ethical values elicitation |
| 3 | Ethical requirements specification |
| 4 | Ethical risk analysis |
| 5 | Ethical validation |

### Notes

- Published 2021
- Process standard (not prescriptive controls)
- Applicable to any AI/autonomous system
- Certifiable process

---

## 7001

IEEE 7001 - Transparency of Autonomous Systems.

### Format

```
secid:control/ieee/7001@2021
```

### Transparency Levels

Defines levels of transparency for different stakeholders:
- Users
- Safety certifiers
- Incident investigators
- Legal/compliance

### Notes

- Published 2021
- Five levels of transparency
- Audience-specific requirements
- Supports accountability

---

## 7002

IEEE 7002 - Data Privacy Process.

### Format

```
secid:control/ieee/7002@2022
```

### Coverage

Process for engineering privacy into systems:
- Privacy requirements elicitation
- Privacy risk assessment
- Privacy-by-design implementation
- Privacy validation

### Notes

- Published 2022
- Complements GDPR/privacy regulations
- Engineering-focused approach

---

## 7010

IEEE 7010 - Well-being Metrics for Autonomous and Intelligent Systems.

### Format

```
secid:control/ieee/7010@2020
```

### Well-being Domains

| Domain | What It Measures |
|--------|------------------|
| Affect | Emotional impact |
| Community | Social connections |
| Culture | Cultural preservation |
| Education | Learning outcomes |
| Economy | Economic well-being |
| Environment | Environmental impact |
| Health | Physical and mental health |
| Human settlements | Quality of living spaces |
| Government | Civic engagement |
| Psychological well-being | Mental flourishing |
| Work | Job quality and satisfaction |

### Notes

- Published 2020
- Metrics for measuring AI impact on well-being
- Supports evidence-based AI governance
