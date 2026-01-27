---
type: control
namespace: singapore
full_name: "Singapore Government"
operator: "secid:entity/singapore"
website: "https://www.imda.gov.sg"
status: active

sources:
  ai-verify:
    full_name: "AI Verify"
    urls:
      website: "https://aiverifyfoundation.sg"
      github: "https://github.com/aiverify-foundation/aiverify"
      toolkit: "https://aiverifyfoundation.sg/downloads"
    versions:
      - "2.0"
    examples:
      - "secid:control/singapore/ai-verify@2.0#transparency"
      - "secid:control/singapore/ai-verify@2.0#fairness"

  model-governance:
    full_name: "Model AI Governance Framework"
    urls:
      website: "https://www.pdpc.gov.sg/help-and-resources/2020/01/model-ai-governance-framework"
    versions:
      - "2.0"
    examples:
      - "secid:control/singapore/model-governance@2.0"
---

# Singapore AI Governance Frameworks

Singapore has developed practical AI governance frameworks emphasizing testing and self-regulation.

## Why Singapore Matters

Singapore leads in practical AI governance:

- **Pragmatic approach** - Testable, measurable governance
- **Open source** - AI Verify toolkit freely available
- **Industry-friendly** - Voluntary, not prescriptive
- **Regional influence** - Model for ASEAN nations

---

## ai-verify

AI Verify is an open-source AI governance testing framework and software toolkit.

### Format

```
secid:control/singapore/ai-verify@2.0#<principle>
```

### Testing Principles

| Principle | What It Tests |
|-----------|---------------|
| **Transparency** | Explainability of AI decisions |
| **Fairness** | Bias in outcomes across groups |
| **Robustness** | Resilience to perturbations |
| **Safety** | Operational safety measures |
| **Accountability** | Governance and oversight |

### Technical Testing

AI Verify provides automated tests for:

| Test Category | Coverage |
|---------------|----------|
| Fairness metrics | Demographic parity, equalized odds |
| Explainability | SHAP, LIME integration |
| Robustness | Adversarial perturbation testing |
| Data quality | Distribution analysis |

### Toolkit Components

1. **Developer tools** - Python SDK for testing
2. **Portal** - Web interface for non-technical users
3. **Reports** - Standardized governance reports
4. **Plugins** - Extensible test modules

### International Adoption

- ASEAN Guide on AI Governance based on AI Verify
- Partnerships with UK, US, and other nations
- Interoperability with ISO and NIST frameworks

### Notes

- Version 2.0 released 2024
- Open source under Apache 2.0
- Created by IMDA and PDPC
- Foundation includes global members

---

## model-governance

The Model AI Governance Framework provides principles and practices for responsible AI deployment.

### Format

```
secid:control/singapore/model-governance@2.0
```

### Guiding Principles

1. **Human-centric** - AI should benefit people
2. **Decisions are explainable** - Stakeholders understand AI
3. **AI systems are fair** - No unfair discrimination
4. **AI systems are safe** - Robust and secure

### Implementation Guidance

| Area | Guidance |
|------|----------|
| Internal governance | Roles, responsibilities, oversight |
| Risk management | Assessment and mitigation |
| Operations | Monitoring and response |
| Stakeholder engagement | Communication and feedback |

### Relationship to AI Verify

| Framework | Purpose |
|-----------|---------|
| Model Governance | What to do (principles) |
| AI Verify | How to test (technical validation) |

### Notes

- Version 2.0 published 2020
- Voluntary adoption framework
- Practical implementation examples
- Companion to AI Verify testing
