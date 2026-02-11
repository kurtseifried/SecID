---
type: control
namespace: cloudsecurityalliance.org
full_name: "Cloud Security Alliance"
operator: "secid:entity/cloudsecurityalliance.org"
website: "https://cloudsecurityalliance.org"
status: active

sources:
  ccm:
    full_name: "Cloud Controls Matrix"
    urls:
      website: "https://cloudsecurityalliance.org/research/cloud-controls-matrix"
      download: "https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4"
    versions:
      - "4.0"
    id_pattern: "[A-Z]{3}-\\d{2}"
    examples:
      - "secid:control/cloudsecurityalliance.org/ccm@4.0#IAM-01"
      - "secid:control/cloudsecurityalliance.org/ccm@4.0#DSP-07"

  aicm:
    full_name: "AI Controls Matrix"
    urls:
      website: "https://cloudsecurityalliance.org/artifacts/ai-controls-matrix"
      download: "https://cloudsecurityalliance.org/artifacts/ai-controls-matrix"
    versions:
      - "1.0"
    examples:
      - "secid:control/cloudsecurityalliance.org/aicm@1.0#AI-GOV-01"
      - "secid:control/cloudsecurityalliance.org/aicm@1.0#AI-DAT-03"

  ai-safety:
    full_name: "AI Safety Initiative"
    urls:
      website: "https://cloudsecurityalliance.org/research/working-groups/artificial-intelligence"
    examples:
      - "secid:control/cloudsecurityalliance.org/ai-safety"
---

# Cloud Security Alliance Controls

CSA provides cloud and AI security control frameworks widely used for compliance and security assessments.

## Why CSA Matters

CSA is the leading cloud security standards body:

- **Industry standard** - CCM used in thousands of organizations
- **Vendor neutral** - Not tied to specific cloud providers
- **AI expansion** - New AI Controls Matrix
- **STAR registry** - Public compliance attestations

---

## ccm

The Cloud Controls Matrix (CCM) is the de facto standard for cloud security controls.

### Format

```
secid:control/cloudsecurityalliance.org/ccm@4.0#XXX-NN
```

Three-letter domain code and two-digit control number.

### Control Domains

| Code | Domain |
|------|--------|
| AIS | Application & Interface Security |
| BCR | Business Continuity & Resilience |
| CCC | Change Control & Configuration |
| DSP | Data Security & Privacy |
| GRC | Governance, Risk & Compliance |
| HRS | Human Resources Security |
| IAM | Identity & Access Management |
| IPY | Interoperability & Portability |
| IVS | Infrastructure & Virtualization |
| LOG | Logging & Monitoring |
| SEF | Security Incident Management |
| STA | Supply Chain, Transparency, Accountability |
| TVM | Threat & Vulnerability Management |
| UEM | Universal Endpoint Management |

### Notes

- Version 4.0 released 2021
- Maps to ISO 27001, NIST, PCI-DSS
- Used for STAR certification
- 197 control objectives

---

## aicm

The AI Controls Matrix provides security controls specific to AI/ML systems.

### Format

```
secid:control/cloudsecurityalliance.org/aicm@1.0#AI-XXX-NN
```

### Control Domains

| Code | Domain |
|------|--------|
| AI-GOV | AI Governance |
| AI-DAT | Data Management |
| AI-MOD | Model Security |
| AI-OPS | AI Operations |
| AI-ETH | AI Ethics |
| AI-PRI | AI Privacy |
| AI-SEC | AI Security |

### Coverage

AICM addresses:
- Model training security
- Data poisoning prevention
- Inference security
- Model theft protection
- Bias and fairness controls
- AI supply chain security

### Relationship to CCM

| Matrix | Scope |
|--------|-------|
| CCM | General cloud security |
| AICM | AI-specific controls |

Use both for comprehensive AI cloud security.

### Notes

- Version 1.0 released 2024
- Complements CCM for AI workloads
- Aligns with NIST AI RMF
- Spreadsheet format available

---

## ai-safety

CSA's AI Safety Initiative brings together industry efforts on AI security.

### Format

```
secid:control/cloudsecurityalliance.org/ai-safety
```

### Working Group Activities

- AI Controls Matrix development
- AI security research papers
- Best practices documentation
- Industry collaboration

### Notes

- Part of CSA research program
- Open participation
- Regular publications and updates
