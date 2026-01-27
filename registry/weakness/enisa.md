---
type: weakness
namespace: enisa
full_name: "European Union Agency for Cybersecurity"
operator: "secid:entity/enisa"
website: "https://www.enisa.europa.eu"
status: active

sources:
  ml-threats:
    full_name: "Securing Machine Learning Algorithms"
    urls:
      website: "https://www.enisa.europa.eu/publications/securing-machine-learning-algorithms"
      pdf: "https://www.enisa.europa.eu/publications/securing-machine-learning-algorithms/@@download/fullReport"
    versions:
      - "2021"
    examples:
      - "secid:weakness/enisa/ml-threats@2021#evasion"
      - "secid:weakness/enisa/ml-threats@2021#poisoning"
      - "secid:weakness/enisa/ml-threats@2021#model-extraction"

  ai-framework:
    full_name: "Multilayer Framework for Good Cybersecurity Practices for AI"
    urls:
      website: "https://www.enisa.europa.eu/publications/multilayer-framework-for-good-cybersecurity-practices-for-ai"
      pdf: "https://www.enisa.europa.eu/publications/multilayer-framework-for-good-cybersecurity-practices-for-ai/@@download/fullReport"
    versions:
      - "2023"
    examples:
      - "secid:weakness/enisa/ai-framework@2023#data-integrity"
      - "secid:weakness/enisa/ai-framework@2023#model-security"
---

# ENISA AI Security Taxonomies

The European Union Agency for Cybersecurity (ENISA) publishes authoritative guidance on AI and machine learning security threats, serving as a reference for EU AI Act compliance.

## Why ENISA Matters

ENISA provides the EU's official cybersecurity perspective:

- **Regulatory authority** - EU's cybersecurity agency
- **Policy influence** - Informs EU AI Act implementation
- **Comprehensive** - Covers threats, controls, and best practices
- **Sector-specific** - Guidance for critical infrastructure

## Key Publications

| Publication | Year | Focus |
|-------------|------|-------|
| Securing ML Algorithms | 2021 | ML threat taxonomy |
| Multilayer AI Framework | 2023 | AI security practices |
| AI Threat Landscape | Ongoing | Emerging AI threats |

---

## ml-threats

ENISA's "Securing Machine Learning Algorithms" report provides a comprehensive taxonomy of ML security threats.

### Format

```
secid:weakness/enisa/ml-threats@2021#<threat-category>
```

### Threat Categories

| Category | Description |
|----------|-------------|
| **evasion** | Adversarial inputs at inference time |
| **poisoning** | Corrupting training data or process |
| **model-extraction** | Stealing model functionality |
| **model-inversion** | Reconstructing training data |
| **membership-inference** | Determining if data was in training set |
| **data-exfiltration** | Extracting sensitive data via model |

### Attack Taxonomy

| Phase | Attack Types |
|-------|--------------|
| Training | Data poisoning, backdoor injection |
| Inference | Evasion, adversarial examples |
| Model | Extraction, inversion, theft |
| Data | Membership inference, reconstruction |

### Threat Actors

ENISA identifies relevant threat actors:
- Nation states
- Cybercriminals
- Competitors (industrial espionage)
- Insiders
- Researchers (unintentional disclosure)

### Notes

- Published December 2021
- Targeted at ML practitioners and security teams
- Aligns with NIST AI 100-2 taxonomy
- Referenced in EU AI Act discussions

---

## ai-framework

ENISA's "Multilayer Framework for Good Cybersecurity Practices for AI" provides structured security guidance across the AI lifecycle.

### Format

```
secid:weakness/enisa/ai-framework@2023#<layer>
```

### Framework Layers

| Layer | Focus |
|-------|-------|
| **data** | Training data integrity and privacy |
| **model** | Model security and robustness |
| **infrastructure** | Compute and deployment security |
| **application** | Integration and API security |
| **governance** | Policies and processes |

### Security Domains

| Domain | Concerns |
|--------|----------|
| Data Integrity | Poisoning, corruption, quality |
| Model Security | Theft, tampering, adversarial robustness |
| Privacy | Data leakage, inference attacks |
| Availability | Resource exhaustion, denial of service |
| Supply Chain | Third-party models, dependencies |

### Lifecycle Coverage

The framework addresses security across:
1. **Design** - Threat modeling, security requirements
2. **Development** - Secure ML pipelines, testing
3. **Deployment** - Hardening, monitoring
4. **Operation** - Incident response, updates
5. **Decommissioning** - Secure disposal

### EU AI Act Alignment

The framework helps organizations prepare for:
- High-risk AI system requirements
- Conformity assessments
- Technical documentation
- Risk management obligations

### Notes

- Published 2023
- Designed for EU AI Act compliance
- Sector-agnostic but includes critical infrastructure focus
- Complements ENISA's broader cybersecurity guidance
