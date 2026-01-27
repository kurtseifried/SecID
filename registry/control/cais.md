---
type: control
namespace: cais
full_name: "Center for AI Safety"
operator: "secid:entity/cais"
website: "https://www.safe.ai"
status: active

sources:
  harmbench:
    full_name: "HarmBench"
    urls:
      website: "https://www.harmbench.org"
      github: "https://github.com/centerforaisafety/HarmBench"
      paper: "https://arxiv.org/abs/2402.04249"
    versions:
      - "2024"
    examples:
      - "secid:control/cais/harmbench#standard"
      - "secid:control/cais/harmbench#contextual"

  wmdp:
    full_name: "Weapons of Mass Destruction Proxy Benchmark"
    urls:
      website: "https://www.wmdp.ai"
      github: "https://github.com/centerforaisafety/wmdp"
      paper: "https://arxiv.org/abs/2403.03218"
    versions:
      - "2024"
    examples:
      - "secid:control/cais/wmdp#biosecurity"
      - "secid:control/cais/wmdp#cybersecurity"
---

# Center for AI Safety Benchmarks

CAIS develops benchmarks for evaluating AI safety, focusing on automated red teaming and dangerous capability assessment.

## Why CAIS Benchmarks Matter

Rigorous safety evaluation methodology:

- **Automated red teaming** - Scalable safety testing
- **Dangerous capabilities** - WMDP tests for harmful knowledge
- **Open source** - Reproducible evaluations
- **Research-backed** - Peer-reviewed methodology

---

## harmbench

HarmBench is a standardized benchmark for automated red teaming of LLMs.

### Format

```
secid:control/cais/harmbench#<category>
```

### What It Prescribes

Test your model against:
- Harmful behavior elicitation
- Jailbreak resistance
- Multiple attack methods

### Behavior Categories

| Category | Examples |
|----------|----------|
| **Chemical/Biological** | Weapons synthesis |
| **Cybercrime** | Malware, hacking |
| **Harassment** | Threats, bullying |
| **Illegal activities** | Fraud, theft |
| **Misinformation** | Fake news, deception |

### Attack Methods Tested

| Method | Description |
|--------|-------------|
| Direct request | Straightforward harmful requests |
| Jailbreaks | Bypass techniques (GCG, AutoDAN, etc.) |
| Contextual | Role-play, hypotheticals |

### Evaluation Metrics

- Attack Success Rate (ASR)
- Per-category breakdown
- Cross-model comparison

### Notes

- 510 harmful behaviors
- 7 attack methods
- Automated evaluation pipeline
- Used by major AI labs

---

## wmdp

The Weapons of Mass Destruction Proxy (WMDP) benchmark tests for dangerous dual-use knowledge.

### Format

```
secid:control/cais/wmdp#<domain>
```

### What It Prescribes

Test your model for:
- Biosecurity knowledge that could enable harm
- Cybersecurity knowledge for offensive use
- Chemical/radiological weapons knowledge

### Domains

| Domain | Coverage |
|--------|----------|
| **Biosecurity** | Pathogen enhancement, synthesis |
| **Cybersecurity** | Exploit development, malware |
| **Chemical** | Weapons synthesis, precursors |

### Methodology

- Multiple-choice questions
- Knowledge assessment (not generation)
- Proxy for dangerous capabilities
- Unlearning benchmark

### Use Cases

| Use | Description |
|-----|-------------|
| Pre-deployment | Assess model before release |
| Unlearning validation | Verify dangerous knowledge removed |
| Capability tracking | Monitor capability changes |

### Notes

- Proxy benchmark (tests knowledge, not actual harm)
- Enables capability evaluation without creating harm
- Used for model unlearning research
- Sensitive - access may be restricted
