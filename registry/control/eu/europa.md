---
type: control
namespace: europa.eu
full_name: "European Union"
operator: "secid:entity/europa.eu"
website: "https://digital-strategy.ec.europa.eu"
status: active

sources:
  altai:
    full_name: "Assessment List for Trustworthy AI"
    urls:
      website: "https://digital-strategy.ec.europa.eu/en/library/assessment-list-trustworthy-artificial-intelligence-altai-self-assessment"
      tool: "https://altai.insight-centre.org"
    versions:
      - "2020"
    examples:
      - "secid:control/europa.eu/altai@2020#human-agency"
      - "secid:control/europa.eu/altai@2020#transparency"

  ethics-guidelines:
    full_name: "Ethics Guidelines for Trustworthy AI"
    urls:
      website: "https://digital-strategy.ec.europa.eu/en/library/ethics-guidelines-trustworthy-ai"
    versions:
      - "2019"
    examples:
      - "secid:control/europa.eu/ethics-guidelines@2019"

  ai-act:
    full_name: "EU AI Act"
    urls:
      website: "https://artificialintelligenceact.eu"
      official: "https://eur-lex.europa.eu/eli/reg/2024/1689"
    versions:
      - "2024"
    examples:
      - "secid:control/europa.eu/ai-act@2024#high-risk"
      - "secid:control/europa.eu/ai-act@2024#prohibited"
---

# EU AI Governance Frameworks

The European Union has developed comprehensive AI governance frameworks, from ethics guidelines to binding regulation.

## Why EU Frameworks Matter

The EU sets global standards for AI governance:

- **Regulatory leader** - First comprehensive AI regulation (AI Act)
- **Rights-based** - Human rights and fundamental freedoms focus
- **Global influence** - "Brussels Effect" shapes global practices
- **Comprehensive** - Ethics, assessment tools, and law

## Framework Evolution

| Year | Framework |
|------|-----------|
| 2019 | Ethics Guidelines for Trustworthy AI |
| 2020 | ALTAI self-assessment tool |
| 2024 | AI Act (binding regulation) |

---

## altai

The Assessment List for Trustworthy AI (ALTAI) is a practical tool for operationalizing the EU's ethics guidelines.

### Format

```
secid:control/europa.eu/altai@2020#<requirement>
```

### Seven Key Requirements

| Requirement | Description |
|-------------|-------------|
| **Human Agency and Oversight** | Human control over AI systems |
| **Technical Robustness and Safety** | Resilient and safe AI |
| **Privacy and Data Governance** | Data protection and privacy |
| **Transparency** | Explainability and communication |
| **Diversity, Non-discrimination and Fairness** | Avoiding unfair bias |
| **Societal and Environmental Well-being** | Broader impact considerations |
| **Accountability** | Responsibility and auditability |

### Self-Assessment Questions

ALTAI provides detailed questions for each requirement:
- Over 100 assessment questions
- Practical implementation guidance
- Links to relevant standards and practices

### Notes

- Published 2020 by High-Level Expert Group on AI
- Implements 2019 Ethics Guidelines
- Voluntary self-assessment tool
- Basis for AI Act compliance preparation

---

## ethics-guidelines

The Ethics Guidelines for Trustworthy AI define what makes AI systems trustworthy.

### Format

```
secid:control/europa.eu/ethics-guidelines@2019
```

### Trustworthy AI Definition

AI should be:
1. **Lawful** - Complying with laws and regulations
2. **Ethical** - Respecting ethical principles
3. **Robust** - Technically and socially reliable

### Notes

- Published April 2019
- Created by High-Level Expert Group (52 experts)
- Foundation for ALTAI and AI Act
- Widely referenced globally

---

## ai-act

The EU AI Act is the world's first comprehensive AI regulation.

### Format

```
secid:control/europa.eu/ai-act@2024#<category>
```

### Risk Categories

| Category | Treatment |
|----------|-----------|
| **Prohibited** | Banned practices (social scoring, certain biometrics) |
| **High-risk** | Strict requirements, conformity assessment |
| **Limited-risk** | Transparency obligations |
| **Minimal-risk** | No specific requirements |

### High-Risk Categories

| Domain | Examples |
|--------|----------|
| Biometrics | Remote identification, emotion recognition |
| Critical infrastructure | Transport, energy, water |
| Education | Scoring, admission decisions |
| Employment | Recruitment, promotion decisions |
| Essential services | Credit scoring, emergency services |
| Law enforcement | Predictive policing, evidence evaluation |
| Migration | Border control, visa applications |
| Justice | Sentencing, legal research |

### Key Requirements (High-Risk)

- Risk management system
- Data governance
- Technical documentation
- Record-keeping
- Transparency to users
- Human oversight
- Accuracy, robustness, security

### Notes

- Entered into force August 2024
- Phased implementation through 2027
- Significant penalties (up to 7% global revenue)
- Creates European AI Office
