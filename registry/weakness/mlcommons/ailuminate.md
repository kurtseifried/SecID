---
type: weakness
namespace: mlcommons
name: ailuminate
full_name: "MLCommons AILuminate Safety Benchmark"
operator: "secid:entity/mlcommons"

urls:
  website: "https://mlcommons.org/ailuminate/"
  index: "https://mlcommons.org/ailuminate/"
  paper: "https://arxiv.org/abs/2502.00862"

id_pattern: "[A-Z][a-z-]+"
versions:
  - "1.0"

examples:
  - "secid:weakness/mlcommons/ailuminate@1.0#violent-crimes"
  - "secid:weakness/mlcommons/ailuminate@1.0#hate-speech"
  - "secid:weakness/mlcommons/ailuminate@1.0#weapons"

status: active
---

# MLCommons AILuminate

Industry-standard AI safety and security benchmark assessing generative AI across 12 hazard categories. Developed collaboratively by 80+ organizations including Google, Microsoft, Meta, OpenAI, and academic institutions.

## Format

```
secid:weakness/mlcommons/ailuminate@1.0#HAZARD-CATEGORY
secid:weakness/mlcommons/ailuminate@1.0#violent-crimes
secid:weakness/mlcommons/ailuminate@1.0#hate-speech
```

## Why AILuminate Matters

- **Industry standard** - Collaborative effort across 80+ organizations
- **Comprehensive scale** - 59,624 test prompts, 477 test images, 109 models benchmarked
- **Multi-language** - English, French, Chinese support
- **Policy influence** - Supports standards bodies and policymakers

## 12 Hazard Categories

| Category | Description |
|----------|-------------|
| **Violent Crimes** | Content enabling physical harm |
| **Non-Violent Crimes** | Fraud, theft, cybercrime |
| **Sex-Related Crimes** | CSAM, trafficking, exploitation |
| **Child Safety** | Harms specifically targeting minors |
| **Hate Speech** | Discrimination, prejudice |
| **Privacy** | PII exposure, surveillance |
| **Specialized Advice** | Dangerous medical/legal/financial guidance |
| **Intellectual Property** | Copyright, trademark violations |
| **Indiscriminate Weapons** | WMD, mass casualty enabling |
| **Chemical/Bio/Nuclear** | CBRN-related risks |
| **Suicide/Self-Harm** | Content promoting self-injury |
| **Sexual Content** | Explicit material generation |

## Benchmark Components

| Component | Focus |
|-----------|-------|
| **Safety** | General chatbot system evaluation |
| **Security (Jailbreaks)** | Multimodal attack resistance testing |
| **Agentic** | Autonomous AI system reliability |

## Grading Scale

AILuminate uses a five-tier grading scale to rate model safety across hazard categories.

## Scale

- **59,624** test prompts
- **477** test images
- **109** models benchmarked
- **3** languages supported

## Notes

- Version 1.0 released 2025
- Created by MLCommons AI Safety working group
- Designed to guide development and inform purchasers
- Supports international standards organizations
