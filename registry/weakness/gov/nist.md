---
type: weakness
namespace: nist.gov
full_name: "National Institute of Standards and Technology"
operator: "secid:entity/nist.gov"
website: "https://www.nist.gov"
status: active

sources:
  ai-100-2:
    full_name: "NIST AI 100-2 Adversarial Machine Learning Taxonomy"
    urls:
      website: "https://csrc.nist.gov/pubs/ai/100/2/e2025/final"
      index: "https://csrc.nist.gov/pubs/ai/100/2/e2025/final"
      pdf: "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf"
      lookup: "https://csrc.nist.gov/pubs/ai/100/2/e2025/final"
    id_pattern: "(Evasion|Poisoning|Privacy|Extraction).*"
    versions:
      - "E2025"
    examples:
      - "secid:weakness/nist.gov/ai-100-2#Evasion"
      - "secid:weakness/nist.gov/ai-100-2#DataPoisoning"
      - "secid:weakness/nist.gov/ai-100-2#MembershipInference"
---

# NIST Weakness Taxonomies

NIST produces authoritative security guidance and taxonomies, including AI/ML security frameworks.

## Why NIST Matters for Weaknesses

NIST provides the official US government perspective on security weaknesses:

- **Authoritative** - Federal agency with regulatory influence
- **Research-backed** - Extensive technical research
- **Policy foundation** - Referenced in executive orders and regulations
- **International recognition** - Used globally as reference

## NIST AI Security Publications

| Publication | Focus |
|-------------|-------|
| AI 100-2 | Adversarial ML attack taxonomy |
| AI RMF | AI Risk Management Framework |
| AI 600-1 | AI RMF Playbook |

---

## ai-100-2

The official NIST taxonomy for adversarial machine learning attacks. This is the authoritative US government classification of ML security threats.

### Format

```
secid:weakness/nist.gov/ai-100-2#CATEGORY
secid:weakness/nist.gov/ai-100-2#Evasion
secid:weakness/nist.gov/ai-100-2#DataPoisoning
```

### Attack Taxonomy

#### By Attack Stage

| Stage | Attack Types |
|-------|--------------|
| **Training Time** | Data Poisoning, Model Poisoning |
| **Inference Time** | Evasion, Extraction, Inference |

#### Attack Categories

| Category | Description | Subcategories |
|----------|-------------|---------------|
| **Evasion** | Attacks at inference time | Adversarial examples, perturbations |
| **Poisoning** | Attacks at training time | Data poisoning, model poisoning |
| **Privacy/Inference** | Extracting information about training data | Membership inference, attribute inference, model inversion |
| **Extraction** | Stealing model functionality | Model extraction, model stealing |

### Detailed Categories

#### Evasion Attacks
- Adversarial examples
- Physical adversarial examples
- Perturbation attacks

#### Poisoning Attacks
- **Data Poisoning**: Manipulating training data
- **Model Poisoning**: Directly manipulating model parameters
- Backdoor attacks
- Trojan attacks

#### Privacy Attacks
- **Membership Inference**: Was this data in the training set?
- **Attribute Inference**: What sensitive attributes does this data have?
- **Model Inversion**: Reconstruct training data from model

#### Extraction Attacks
- Model extraction
- Model stealing
- Functionality extraction

### Why NIST Matters

- Official US government taxonomy
- Used in federal AI security guidance
- Referenced by NIST AI RMF
- Basis for compliance requirements

### Notes

- First edition: January 2024
- Updates expected as field evolves
- Complements MITRE ATLAS (TTPs) with weakness taxonomy
- Referenced in AI executive orders and policy
