---
type: weakness
namespace: owasp
name: ml-top10
full_name: "OWASP Machine Learning Security Top 10"
operator: "secid:entity/owasp"

urls:
  website: "https://owasp.org/www-project-machine-learning-security-top-10/"
  index: "https://mltop10.info/"
  github: "https://github.com/OWASP/www-project-machine-learning-security-top-10"
  lookup: "https://mltop10.info/#{id}/"

id_pattern: "ML\\d{2}"
versions:
  - "2023"

examples:
  - "secid:weakness/owasp/ml-top10#ML01"
  - "secid:weakness/owasp/ml-top10#ML05"
  - "secid:weakness/owasp/ml-top10@2023#ML01"

status: active
---

# OWASP Machine Learning Security Top 10

Security risks specific to Machine Learning systems, separate from the LLM Top 10.

## Format

```
secid:weakness/owasp/ml-top10[@VERSION]#ITEM
secid:weakness/owasp/ml-top10#ML01
secid:weakness/owasp/ml-top10@2023#ML01
```

## 2023 Edition

| ID | Name | Description |
|----|------|-------------|
| ML01 | Input Manipulation Attack | Adversarial examples that fool models |
| ML02 | Data Poisoning Attack | Corrupting training data |
| ML03 | Model Inversion Attack | Reconstructing training data from model |
| ML04 | Membership Inference Attack | Determining if data was in training set |
| ML05 | Model Theft | Extracting model weights or behavior |
| ML06 | AI Supply Chain Attacks | Compromising ML dependencies |
| ML07 | Transfer Learning Attack | Exploiting pre-trained model vulnerabilities |
| ML08 | Model Skewing | Biasing model behavior through data manipulation |
| ML09 | Output Integrity Attack | Manipulating model outputs |
| ML10 | Model Poisoning | Directly corrupting model parameters |

## Difference from LLM Top 10

| ML Top 10 | LLM Top 10 |
|-----------|------------|
| Broader ML systems (vision, classification, etc.) | Specifically Large Language Models |
| Focuses on model-level attacks | Focuses on application-level risks |
| More technical/research oriented | More deployment/integration oriented |

## Relationships

```
secid:weakness/owasp/ml-top10#ML01 → related_to → secid:ttp/mitre/atlas#AML.T0015
secid:weakness/owasp/ml-top10#ML02 → related_to → secid:weakness/owasp/llm-top10#LLM04
```

## Notes

- Focuses on traditional ML security (not just LLMs)
- Covers attacks at training and inference time
- Complements the LLM Top 10 for non-LLM systems
