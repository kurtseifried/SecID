---
type: control
namespace: jailbreakbench
full_name: "JailbreakBench"
operator: "secid:entity/jailbreakbench"
website: "https://jailbreakbench.github.io"
status: active

sources:
  benchmark:
    full_name: "JailbreakBench"
    urls:
      website: "https://jailbreakbench.github.io"
      github: "https://github.com/JailbreakBench/jailbreakbench"
      paper: "https://arxiv.org/abs/2404.01318"
      artifacts: "https://github.com/JailbreakBench/artifacts"
    versions:
      - "2024"
    examples:
      - "secid:control/jailbreakbench/benchmark#behaviors"
      - "secid:control/jailbreakbench/benchmark#defenses"
---

# JailbreakBench

JailbreakBench provides a standardized benchmark for evaluating LLM jailbreak attacks and defenses.

## Why JailbreakBench Matters

Standardized jailbreak evaluation:

- **Reproducible** - Consistent evaluation methodology
- **Comprehensive** - Tests attacks and defenses
- **Community-driven** - Open artifact repository
- **Evolving** - Tracks new attack methods

---

## benchmark

JailbreakBench prescribes standardized evaluation of jailbreak attacks and defenses.

### Format

```
secid:control/jailbreakbench/benchmark#<component>
```

### Components

| Component | Description |
|-----------|-------------|
| **Behaviors** | Harmful behaviors to elicit |
| **Attacks** | Jailbreak methods to test |
| **Defenses** | Mitigation techniques |
| **Evaluation** | Judging methodology |

### Behavior Categories

| Category | Examples |
|----------|----------|
| Harmful content | Violence, illegal activities |
| Misinformation | False claims, deception |
| Privacy violations | PII extraction |
| Malicious code | Malware, exploits |

### Attack Methods Evaluated

| Attack | Type |
|--------|------|
| GCG | Gradient-based |
| AutoDAN | Automated prompt |
| PAIR | Prompt iteration |
| TAP | Tree-based attack |
| Manual jailbreaks | Human-crafted |

### Defense Methods

| Defense | Approach |
|---------|----------|
| Perplexity filtering | Detecting adversarial prompts |
| Safety training | RLHF, constitutional AI |
| Input preprocessing | Prompt sanitization |
| Output filtering | Response classification |

### Evaluation Criteria

| Criterion | Description |
|-----------|-------------|
| Attack Success Rate | % of successful jailbreaks |
| False Positive Rate | Legitimate requests blocked |
| Defense overhead | Computational cost |

### Artifacts Repository

JailbreakBench maintains:
- Successful jailbreak prompts
- Defense configurations
- Model responses
- Evaluation results

### Notes

- Standardizes jailbreak research
- Enables fair comparison
- Tracks defense effectiveness
- Community contributions welcome
