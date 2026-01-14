---
type: weakness
namespace: biml
name: ml-risks
full_name: "Berryville Institute ML Risk Framework"
operator: "secid:entity/biml"

urls:
  website: "https://berryvilleiml.com/results/"
  interactive: "https://berryvilleiml.com/interactive/"
  lookup: "https://berryvilleiml.com/interactive/"

id_pattern: "BIML-\\d+"
versions:
  - "1.0"

examples:
  - "secid:weakness/biml/ml-risks#BIML-01"
  - "secid:weakness/biml/ml-risks#BIML-42"

status: active
---

# Berryville Institute ML Risk Framework

A comprehensive taxonomy of 78 architectural security risks specific to machine learning systems, developed by the Berryville Institute of Machine Learning.

## Format

```
secid:weakness/biml/ml-risks#BIML-NN
secid:weakness/biml/ml-risks#BIML-01
secid:weakness/biml/ml-risks#BIML-78
```

## Why BIML Matters

BIML provides the most detailed ML risk taxonomy:

- **78 specific risks** - Not top 10, but comprehensive coverage
- **Architectural focus** - Risks in ML system design
- **Interactive explorer** - Browse risks by category
- **Research-backed** - Academic rigor

## Risk Categories

| Category | Count | Examples |
|----------|-------|----------|
| Data Collection | ~10 | Biased sampling, data leakage |
| Data Processing | ~12 | Feature engineering flaws |
| Model Training | ~15 | Overfitting, underfitting |
| Model Deployment | ~10 | Inference attacks, model drift |
| Operational | ~8 | Monitoring gaps, feedback loops |
| Security | ~15 | Adversarial attacks, model theft |
| Privacy | ~8 | Data exposure, membership inference |

## Relationship to Other Frameworks

| Framework | Relationship |
|-----------|--------------|
| OWASP ML Top 10 | BIML provides deeper taxonomy |
| MITRE ATLAS | BIML covers risks, ATLAS covers techniques |
| NIST AI 100-2 | Complementary, different scope |

## Notes

- Created by Gary McGraw and team
- Includes interactive risk explorer
- Separate LLM-specific framework (BIML-81)
- Focused on architectural/design risks vs runtime attacks
