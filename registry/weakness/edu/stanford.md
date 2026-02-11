---
type: weakness
namespace: stanford.edu
full_name: "Stanford Center for Research on Foundation Models"
operator: "secid:entity/stanford.edu"
website: "https://crfm.stanford.edu"
status: active

sources:
  air-bench:
    full_name: "AI Risk Benchmark 2024"
    urls:
      website: "https://github.com/stanford-crfm/air-bench-2024"
      paper: "https://arxiv.org/abs/2407.17436"
    versions:
      - "2024"
    examples:
      - "secid:weakness/stanford.edu/air-bench@2024#privacy-pii"
      - "secid:weakness/stanford.edu/air-bench@2024#manipulation-persuasion"

  helm-safety:
    full_name: "HELM Safety Benchmark"
    urls:
      website: "https://crfm.stanford.edu/helm/safety/latest"
      docs: "https://crfm.stanford.edu/helm/latest"
    versions:
      - "1.0"
    examples:
      - "secid:weakness/stanford.edu/helm-safety#toxicity"
      - "secid:weakness/stanford.edu/helm-safety#bias"
---

# Stanford CRFM Weakness Taxonomies

Stanford's Center for Research on Foundation Models (CRFM) develops comprehensive benchmarks and taxonomies for evaluating AI safety and risks.

## Why Stanford CRFM Matters

Stanford CRFM provides rigorous academic frameworks:

- **Research-backed** - Peer-reviewed methodologies
- **Comprehensive** - Broad coverage of AI risks
- **Regulation-aligned** - Maps to policy requirements
- **Reproducible** - Open benchmarks and datasets

## Key Contributions

| Project | Focus |
|---------|-------|
| **HELM** | Holistic Evaluation of Language Models |
| **AIR-Bench** | Regulation-aligned risk categories |
| **Safety Benchmarks** | Toxicity, bias, and harm evaluation |

---

## air-bench

AIR-Bench 2024 (AI Risk Benchmark) provides 314 risk categories aligned with AI regulations and policies worldwide.

### Format

```
secid:weakness/stanford.edu/air-bench@2024#<category>
```

### Why AIR-Bench Matters

AIR-Bench is unique in its regulatory alignment:

- **314 risk categories** - Comprehensive risk coverage
- **Regulation-mapped** - Aligned with EU AI Act, NIST AI RMF, etc.
- **Hierarchical** - Organized into domains and subdomains
- **Testable** - Includes evaluation prompts and criteria

### Risk Domains

| Domain | Description |
|--------|-------------|
| System & Operational Risks | Infrastructure and deployment risks |
| Content Safety | Harmful content generation |
| Societal Risks | Discrimination, manipulation |
| Legal & Rights | Privacy, IP, regulatory compliance |

### Risk Categories (Examples)

| Category ID | Description |
|-------------|-------------|
| privacy-pii | Personal information disclosure |
| manipulation-persuasion | Psychological manipulation |
| violence-incitement | Promoting violent acts |
| discrimination-bias | Unfair treatment based on protected characteristics |
| deception-fraud | Fraudulent content generation |
| illegal-activities | Assistance with unlawful acts |

### Regulatory Mapping

AIR-Bench maps to:
- EU AI Act risk categories
- NIST AI RMF
- White House AI Bill of Rights
- China's AI regulations

### Notes

- Published 2024 by Stanford CRFM
- Open dataset and methodology
- Useful for compliance evaluation
- Regular updates planned

---

## helm-safety

HELM Safety provides standardized evaluation of LLM safety across multiple dimensions.

### Format

```
secid:weakness/stanford.edu/helm-safety#<dimension>
```

### Safety Dimensions

| Dimension | What It Measures |
|-----------|------------------|
| toxicity | Harmful or offensive content generation |
| bias | Unfair treatment across demographic groups |
| truthfulness | Factual accuracy and hallucination |
| safety | Refusal of harmful requests |

### Resolution

Results available at:
```
https://crfm.stanford.edu/helm/safety/latest
```

### Why HELM Safety Matters

- **Standardized** - Consistent evaluation methodology
- **Comparative** - Enables model comparison
- **Transparent** - Open results and methodology
- **Comprehensive** - Multiple safety dimensions

### Notes

- Part of the broader HELM evaluation framework
- Used by model developers and researchers
- Results published for major models
- Methodology peer-reviewed
