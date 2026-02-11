---
type: control
namespace: github.com/thu-coai
full_name: "SafetyBench"
operator: "secid:entity/tsinghua"
website: "https://github.com/thu-coai/SafetyBench"
status: active

sources:
  benchmark:
    full_name: "SafetyBench"
    urls:
      website: "https://github.com/thu-coai/SafetyBench"
      paper: "https://arxiv.org/abs/2309.07045"
    versions:
      - "2024"
    examples:
      - "secid:control/github.com/thu-coai/benchmark#offensiveness"
      - "secid:control/github.com/thu-coai/benchmark#ethics"
---

# SafetyBench

SafetyBench is a comprehensive benchmark for evaluating LLM safety across multiple harm categories, with support for Chinese and English.

## Why SafetyBench Matters

Multilingual safety evaluation:

- **Bilingual** - Chinese and English coverage
- **Comprehensive** - 7 safety categories
- **Large scale** - 11,435 multiple-choice questions
- **Diverse** - Multiple harm types

---

## benchmark

SafetyBench prescribes evaluation across seven safety categories.

### Format

```
secid:control/github.com/thu-coai/benchmark#<category>
```

### Seven Safety Categories

| Category | What It Tests |
|----------|---------------|
| **Offensiveness** | Insulting, offensive content |
| **Unfairness and bias** | Discrimination, stereotypes |
| **Physical health** | Dangerous health advice |
| **Mental health** | Harmful psychological content |
| **Illegal activities** | Crime facilitation |
| **Ethics and morality** | Moral reasoning |
| **Privacy and property** | Data and property protection |

### Offensiveness

| Test | Description |
|------|-------------|
| Hate speech | Group-targeted hostility |
| Insults | Personal attacks |
| Profanity | Inappropriate language |

### Unfairness and Bias

| Test | Description |
|------|-------------|
| Gender bias | Sex/gender discrimination |
| Racial bias | Ethnic discrimination |
| Religious bias | Faith-based discrimination |
| Other biases | Age, disability, etc. |

### Physical Health

| Test | Description |
|------|-------------|
| Dangerous advice | Harmful health recommendations |
| Drug information | Substance abuse |
| Self-harm | Physical harm facilitation |

### Mental Health

| Test | Description |
|------|-------------|
| Suicide | Self-harm encouragement |
| Depression | Harmful emotional content |
| Anxiety | Distress amplification |

### Illegal Activities

| Test | Description |
|------|-------------|
| Violence | Harm to others |
| Fraud | Financial crimes |
| Theft | Property crimes |
| Cybercrime | Digital offenses |

### Evaluation Format

- Multiple-choice questions
- Model selects safest response
- Automated scoring
- Per-category breakdown

### Notes

- 11,435 test questions
- Chinese and English versions
- Covers both LLMs and chat models
- Regular benchmark updates
