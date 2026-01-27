---
type: control
namespace: ai2
full_name: "Allen Institute for AI"
operator: "secid:entity/ai2"
website: "https://allenai.org"
status: active

sources:
  decodingtrust:
    full_name: "DecodingTrust"
    urls:
      website: "https://decodingtrust.github.io"
      github: "https://github.com/AI-secure/DecodingTrust"
      paper: "https://arxiv.org/abs/2306.11698"
    versions:
      - "2024"
    examples:
      - "secid:control/ai2/decodingtrust#toxicity"
      - "secid:control/ai2/decodingtrust#privacy"

  realtoxicityprompts:
    full_name: "RealToxicityPrompts"
    urls:
      website: "https://allenai.org/data/real-toxicity-prompts"
      github: "https://github.com/allenai/real-toxicity-prompts"
      paper: "https://arxiv.org/abs/2009.11462"
    examples:
      - "secid:control/ai2/realtoxicityprompts"
---

# AI2 Safety Benchmarks

The Allen Institute for AI develops benchmarks for evaluating language model safety and trustworthiness.

## Why AI2 Benchmarks Matter

Foundational safety research:

- **Pioneering work** - RealToxicityPrompts was early toxicity benchmark
- **Comprehensive** - DecodingTrust covers 8 trust dimensions
- **Open science** - All data and code available
- **Influential** - Widely used in research and industry

---

## decodingtrust

DecodingTrust is a comprehensive trustworthiness evaluation for GPT models and other LLMs.

### Format

```
secid:control/ai2/decodingtrust#<perspective>
```

### Eight Trust Perspectives

| Perspective | What It Tests |
|-------------|---------------|
| **Toxicity** | Harmful content generation |
| **Stereotype bias** | Demographic stereotypes |
| **Adversarial robustness** | Perturbation resistance |
| **Out-of-distribution** | Handling novel inputs |
| **Robustness to prompts** | Adversarial prompt resistance |
| **Privacy** | Data leakage, PII handling |
| **Machine ethics** | Moral reasoning |
| **Fairness** | Equitable treatment |

### Toxicity Evaluation

| Test | Description |
|------|-------------|
| Standard prompts | Baseline toxicity |
| Adversarial prompts | Induced toxicity |
| System prompt effects | Instruction following |

### Stereotype Evaluation

| Test | Description |
|------|-------------|
| Agreement | Stereotype endorsement |
| Recognition | Identifying stereotypes |
| Selection | Choosing biased options |

### Privacy Evaluation

| Test | Description |
|------|-------------|
| Training data extraction | Memorization leakage |
| PII inference | Personal information exposure |
| Privacy understanding | Conceptual awareness |

### Adversarial Robustness

| Test | Description |
|------|-------------|
| AdvGLUE | Adversarial NLU tasks |
| AdvInstruction | Adversarial instructions |

### Notes

- Comprehensive 8-dimension evaluation
- Automated scoring pipeline
- GPT-3.5, GPT-4 baseline results
- Enables model comparison

---

## realtoxicityprompts

RealToxicityPrompts is a benchmark for measuring neural toxic degeneration in language models.

### Format

```
secid:control/ai2/realtoxicityprompts
```

### What It Prescribes

Test your model for:
- Toxic content generation from neutral prompts
- Toxicity amplification
- Effectiveness of detoxification methods

### Dataset

| Component | Description |
|-----------|-------------|
| Prompts | 100K sentence beginnings |
| Toxicity scores | Perspective API annotations |
| Continuations | Model-generated completions |

### Toxicity Categories

- Severe toxicity
- Sexually explicit
- Threat
- Profanity
- Identity attack
- Insult

### Evaluation Metrics

| Metric | Description |
|--------|-------------|
| Expected maximum toxicity | Worst-case generation |
| Toxicity probability | How often toxic output occurs |
| Detoxification effectiveness | Mitigation method success |

### Notes

- Foundational toxicity benchmark
- Used Perspective API for scoring
- Revealed toxicity in GPT-2, GPT-3
- Influenced model safety practices
