---
type: control
namespace: trustllmbenchmark.github.io
full_name: "TrustLLM Benchmark"
operator: "secid:entity/pku"
website: "https://trustllmbenchmark.github.io/TrustLLM-Website/"
status: active

sources:
  benchmark:
    full_name: "TrustLLM Benchmark"
    urls:
      website: "https://trustllmbenchmark.github.io/TrustLLM-Website/"
      github: "https://github.com/HowieHwong/TrustLLM"
      paper: "https://arxiv.org/abs/2401.05561"
      leaderboard: "https://trustllmbenchmark.github.io/TrustLLM-Website/leaderboard.html"
    versions:
      - "2024"
    examples:
      - "secid:control/trustllmbenchmark.github.io/benchmark#truthfulness"
      - "secid:control/trustllmbenchmark.github.io/benchmark#safety"
      - "secid:control/trustllmbenchmark.github.io/benchmark#fairness"
---

# TrustLLM Benchmark

TrustLLM provides a comprehensive framework for evaluating LLM trustworthiness across multiple dimensions.

## Why TrustLLM Matters

Holistic trust evaluation:

- **Multi-dimensional** - 6 key trustworthiness aspects
- **Comprehensive** - 30+ datasets integrated
- **Standardized** - Consistent evaluation methodology
- **Open** - Toolkit and data available

---

## benchmark

The TrustLLM benchmark prescribes evaluation across six trustworthiness dimensions.

### Format

```
secid:control/trustllmbenchmark.github.io/benchmark#<dimension>
```

### Six Dimensions of Trust

| Dimension | What It Tests |
|-----------|---------------|
| **Truthfulness** | Factual accuracy, hallucination resistance |
| **Safety** | Harmful content refusal, jailbreak resistance |
| **Fairness** | Bias across demographics, stereotypes |
| **Robustness** | Adversarial input handling |
| **Privacy** | PII protection, data leakage |
| **Machine Ethics** | Moral reasoning, ethical decisions |

### Truthfulness Tests

| Test | Description |
|------|-------------|
| Misinformation | Resistance to false claims |
| Hallucination | Factual grounding |
| Sycophancy | Resisting user pressure |
| Adversarial facts | Handling contradictions |

### Safety Tests

| Test | Description |
|------|-------------|
| Jailbreak | Resistance to bypass attempts |
| Toxicity | Harmful content generation |
| Misuse | Dual-use request handling |

### Fairness Tests

| Test | Description |
|------|-------------|
| Stereotype | Stereotype reinforcement |
| Disparagement | Group-based harm |
| Preference | Demographic bias |

### Robustness Tests

| Test | Description |
|------|-------------|
| Natural noise | Typos, variations |
| Out-of-distribution | Unusual inputs |
| Adversarial | Crafted perturbations |

### Privacy Tests

| Test | Description |
|------|-------------|
| Privacy awareness | Understanding privacy concepts |
| Privacy leakage | Revealing training data |
| Unlearning | Forgetting specific information |

### Machine Ethics Tests

| Test | Description |
|------|-------------|
| Implicit ethics | Unstated moral reasoning |
| Explicit ethics | Direct ethical questions |
| Emotional awareness | Emotional intelligence |

### Notes

- 30+ integrated datasets
- Automated evaluation pipeline
- Cross-model comparison enabled
- Regular benchmark updates
