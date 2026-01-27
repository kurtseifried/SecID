---
type: control
namespace: advbench
full_name: "AdvBench"
operator: "secid:entity/umd"
website: "https://github.com/llm-attacks/llm-attacks"
status: active

sources:
  benchmark:
    full_name: "AdvBench Harmful Behaviors"
    urls:
      website: "https://github.com/llm-attacks/llm-attacks"
      paper: "https://arxiv.org/abs/2307.15043"
      data: "https://github.com/llm-attacks/llm-attacks/tree/main/data/advbench"
    versions:
      - "2023"
    examples:
      - "secid:control/advbench/benchmark#harmful-behaviors"
      - "secid:control/advbench/benchmark#harmful-strings"
---

# AdvBench

AdvBench provides datasets for evaluating adversarial attacks on LLMs, originally developed for the GCG (Greedy Coordinate Gradient) attack paper.

## Why AdvBench Matters

Foundation for adversarial LLM research:

- **Influential** - Basis for GCG attack research
- **Standardized** - Common benchmark for jailbreak research
- **Widely used** - Cited in numerous papers
- **Practical** - Real harmful behavior categories

---

## benchmark

AdvBench prescribes evaluation of LLM susceptibility to adversarial jailbreak attacks.

### Format

```
secid:control/advbench/benchmark#<dataset>
```

### Datasets

| Dataset | Description |
|---------|-------------|
| **Harmful behaviors** | 520 harmful instructions |
| **Harmful strings** | Target harmful outputs |

### Harmful Behavior Categories

| Category | Examples |
|----------|----------|
| Violence | Instructions for causing harm |
| Illegal activities | Crime facilitation |
| Misinformation | Generating false content |
| Privacy violations | Extracting personal data |
| Malware | Creating malicious code |
| Fraud | Deception and scams |

### Use in Research

AdvBench is used to evaluate:

| Attack Type | What It Tests |
|-------------|---------------|
| GCG attacks | Gradient-based jailbreaks |
| Transfer attacks | Cross-model adversarial prompts |
| Defense effectiveness | Mitigation success rates |

### Evaluation Metrics

| Metric | Description |
|--------|-------------|
| Attack Success Rate | % harmful responses generated |
| Transfer rate | Success across different models |
| Query efficiency | Attempts needed for success |

### Relationship to Other Benchmarks

| Benchmark | Relationship |
|-----------|--------------|
| HarmBench | Builds on AdvBench, more comprehensive |
| JailbreakBench | Uses AdvBench behaviors |

### Notes

- 520 harmful behavior prompts
- Developed at UMD
- Foundation for jailbreak research
- Used in GCG, AutoDAN, and other attack papers
