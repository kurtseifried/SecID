---
type: weakness
namespace: gpai
full_name: "General-Purpose AI Research"
operator: "secid:reference/arxiv"
website: "https://arxiv.org"
status: active

sources:
  risk-sources:
    full_name: "GPAI Risk Sources and Management Measures Catalog"
    urls:
      website: "https://arxiv.org/abs/2410.23472"
      index: "https://arxiv.org/abs/2410.23472"
      html: "https://arxiv.org/html/2410.23472v1"
      pdf: "https://arxiv.org/pdf/2410.23472"
    id_pattern: "[a-z-]+"
    versions:
      - "2024"
    examples:
      - "secid:weakness/gpai/risk-sources#training-data-risks"
      - "secid:weakness/gpai/risk-sources#deployment-risks"
      - "secid:weakness/gpai/risk-sources#societal-risks"
---

# GPAI Weakness Taxonomies

Risk taxonomies and catalogs specific to general-purpose AI systems, derived from academic research supporting AI governance and standards development.

## Why GPAI Research Matters

General-purpose AI systems (foundation models, large language models) present unique risks that require dedicated taxonomies. Academic research provides neutral, comprehensive catalogs that inform standards and regulations.

## Related Namespaces

| Namespace | Relationship |
|-----------|--------------|
| `secid:weakness/mit/ai-risk-repository` | Broader AI risk repository |
| `secid:weakness/owasp/llm-top10` | LLM-specific risks |
| `secid:control/nist/ai-rmf` | AI risk management framework |

---

## risk-sources

Extensive catalog of risk sources and risk management measures for general-purpose AI (GPAI) systems. First comprehensive documentation of both risks and mitigations, released under public domain license.

### Format

```
secid:weakness/gpai/risk-sources#RISK-CATEGORY
secid:weakness/gpai/risk-sources#training-data-risks
secid:weakness/gpai/risk-sources#societal-risks
```

### Why This Catalog Matters

- **First of its kind** - Extensive documentation of both risks AND management measures
- **Public domain license** - Free for direct use by stakeholders
- **EU AI Act aligned** - Designed to inform standards and codes of practice
- **Self-contained** - Descriptive and neutral to any regulatory framework

### Authors

Rokas Gipiskis, Ayrton San Joaquin, Ze Shen Chin, Adrian Regenfuss, Ariel Gil, Koen Holtman

### Risk Categories

| Category | Description |
|----------|-------------|
| **Technical Risks** | Model development and training risks |
| **Operational Risks** | Deployment and operation risks |
| **Societal Risks** | Broader social impact risks |

### Coverage

The catalog addresses risks across:
- Model development stages
- Training phases
- Deployment scenarios
- Systemic effects

### Target Audience

| Stakeholder | Use Case |
|-------------|----------|
| AI Providers | Identifying risks in their systems |
| Standards Experts | Writing safety standards |
| Researchers | Understanding risk landscape |
| Policymakers | Developing regulations |
| Regulators | Enforcement and oversight |

### Regulatory Context

Driven by need to inform standards and codes of practice for:
- EU AI Act implementation
- GPAI safety engineering requirements
- International AI governance efforts

### Management Measures

Unlike pure risk taxonomies, this catalog also documents:
- Established risk management methods
- Experimental mitigation approaches
- Practical implementation guidance

### Notes

- Published October 2024, updated November 2024
- Available on arXiv under public domain license
- Designed for direct incorporation into standards
- Complements NIST AI RMF and EU AI Act requirements
