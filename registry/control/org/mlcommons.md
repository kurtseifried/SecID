---
type: control
namespace: mlcommons.org
full_name: "MLCommons"
operator: "secid:entity/mlcommons.org"
website: "https://mlcommons.org"
status: active

sources:
  ai-safety:
    full_name: "AI Safety Working Group"
    urls:
      website: "https://mlcommons.org/working-groups/ai-safety"
      benchmarks: "https://mlcommons.org/benchmarks/ai-safety"
    examples:
      - "secid:control/mlcommons.org/ai-safety#hazard-taxonomy"
      - "secid:control/mlcommons.org/ai-safety#benchmark"

  croissant:
    full_name: "Croissant ML Dataset Format"
    urls:
      website: "https://mlcommons.org/croissant"
      github: "https://github.com/mlcommons/croissant"
      spec: "https://docs.mlcommons.org/croissant/docs/croissant-spec.html"
    versions:
      - "1.0"
    examples:
      - "secid:control/mlcommons.org/croissant@1.0"

  mlperf:
    full_name: "MLPerf Benchmarks"
    urls:
      website: "https://mlcommons.org/benchmarks"
    examples:
      - "secid:control/mlcommons.org/mlperf#training"
      - "secid:control/mlcommons.org/mlperf#inference"
---

# MLCommons Standards

MLCommons is an open engineering consortium developing ML benchmarks, datasets, and safety standards.

## Why MLCommons Matters

Industry-wide collaboration on ML standards:

- **Neutral ground** - Industry consortium, not single vendor
- **Benchmarks** - MLPerf is the standard for ML performance
- **Safety focus** - Dedicated AI safety working group
- **Data standards** - Croissant format for ML datasets

---

## ai-safety

MLCommons AI Safety Working Group develops standardized safety benchmarks and taxonomies.

### Format

```
secid:control/mlcommons.org/ai-safety#<component>
```

### AI Safety Benchmark v0.5

| Component | Description |
|-----------|-------------|
| **Hazard Taxonomy** | 13 hazard categories |
| **Test Prompts** | Thousands of safety test cases |
| **Evaluation** | Standardized safety scoring |
| **Personas** | Diverse user simulation |

### Hazard Categories

| Category | Examples |
|----------|----------|
| Violent crimes | Physical harm, weapons |
| Non-violent crimes | Fraud, theft |
| Sex-related crimes | CSAM, trafficking |
| Child safety | Endangerment, exploitation |
| Hate | Discrimination, slurs |
| Suicide and self-harm | Methods, encouragement |
| Chemical/biological/nuclear | Weapons, dangerous materials |
| Privacy | PII exposure, doxxing |
| Intellectual property | Copyright, trademarks |
| Indiscriminate weapons | Explosives, mass harm |
| Elections | Misinformation, manipulation |
| Defamation | Libel, reputation harm |
| Specialized advice | Medical, legal, financial without qualification |

### Notes

- Publicly available benchmark
- Regular updates with new test cases
- Used by major AI labs
- Enables cross-model comparison

---

## croissant

Croissant is a metadata format for ML datasets that includes safety and responsible AI information.

### Format

```
secid:control/mlcommons.org/croissant@1.0
```

### Key Features

| Feature | Purpose |
|---------|---------|
| **Dataset description** | What the dataset contains |
| **Data sources** | Provenance information |
| **Responsible AI** | Bias, fairness, intended use |
| **Distribution** | Licensing, access controls |

### Responsible AI Fields

Croissant includes fields for:
- Intended use cases
- Known limitations
- Bias assessments
- Data collection methods
- Privacy considerations

### Adoption

- HuggingFace integration
- Kaggle support
- Google Dataset Search compatible
- OpenML integration

### Notes

- Version 1.0 released 2024
- JSON-LD based format
- Extends schema.org vocabulary
- Machine-readable dataset cards

---

## mlperf

MLPerf provides standardized ML benchmarks for training and inference performance.

### Format

```
secid:control/mlcommons.org/mlperf#<benchmark>
```

### Benchmark Suites

| Suite | What It Measures |
|-------|------------------|
| **Training** | Time to train models |
| **Inference** | Throughput and latency |
| **Tiny** | Edge and embedded devices |
| **Storage** | Data loading performance |

### Why It Matters for Security

- **Reproducibility** - Standardized model configurations
- **Transparency** - Published results and methods
- **Baseline** - Compare security overhead

### Notes

- Industry-standard ML benchmarks
- Regular submission rounds
- Hardware and software comparisons
- Published results database
