---
type: control
namespace: meta
full_name: "Meta Platforms"
operator: "secid:entity/meta"
website: "https://ai.meta.com"
status: active

sources:
  purple-llama:
    full_name: "Purple Llama Project"
    urls:
      website: "https://github.com/meta-llama/PurpleLlama"
      blog: "https://ai.meta.com/blog/purple-llama-open-trust-safety-generative-ai/"
    examples:
      - "secid:control/meta/purple-llama#llama-guard"
      - "secid:control/meta/purple-llama#prompt-guard"
      - "secid:control/meta/purple-llama#code-shield"

  cyberseceval:
    full_name: "CyberSecEval Benchmark"
    urls:
      website: "https://meta-llama.github.io/PurpleLlama/CyberSecEval"
      github: "https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks"
      paper: "https://arxiv.org/abs/2312.04724"
    versions:
      - "4.0"
    examples:
      - "secid:control/meta/cyberseceval#insecure-code"
      - "secid:control/meta/cyberseceval#cyberattack-helpfulness"
      - "secid:control/meta/cyberseceval#prompt-injection"
---

# Meta AI Security Controls

Meta provides open-source AI security tools and benchmarks through the Purple Llama project, enabling the community to evaluate and improve LLM safety.

## Why Meta's Tools Matter

Meta's open approach benefits the ecosystem:

- **Open source** - Tools available to all
- **Practical** - Production-ready security controls
- **Benchmarks** - Standardized safety evaluation
- **Community** - Enables independent research

---

## purple-llama

Purple Llama is Meta's open-source project providing tools for evaluating and improving LLM safety and security.

### Format

```
secid:control/meta/purple-llama#<tool>
```

### Purple Llama Components

| Component | Purpose |
|-----------|---------|
| **Llama Guard** | Content safety classifier |
| **Prompt Guard** | Prompt injection detector |
| **Code Shield** | Insecure code detection |
| **CyberSecEval** | Security benchmarks |

### Llama Guard

```
secid:control/meta/purple-llama#llama-guard
```

Content moderation model for LLM inputs/outputs:
- Classifies content against safety taxonomy
- Version 3 is current
- Supports custom taxonomies
- Open weights available

### Prompt Guard

```
secid:control/meta/purple-llama#prompt-guard
```

Detects prompt injection attempts:
- Direct injection detection
- Indirect/embedded injection detection
- Classifier-based approach

### Code Shield

```
secid:control/meta/purple-llama#code-shield
```

Detects insecure code patterns:
- Static analysis for generated code
- Covers common vulnerability patterns
- Integrates with code generation pipelines

### Notes

- "Purple" = Red (attack) + Blue (defense)
- All tools open-source on GitHub
- Designed for Llama but works with other models
- Active development and updates

---

## cyberseceval

CyberSecEval is Meta's benchmark suite for evaluating LLM cybersecurity risks.

### Format

```
secid:control/meta/cyberseceval#<benchmark>
```

### Benchmark Categories

| Benchmark | What It Tests |
|-----------|---------------|
| **insecure-code** | Does model generate vulnerable code? |
| **cyberattack-helpfulness** | Does model assist with attacks? |
| **prompt-injection** | Is model susceptible to injection? |
| **code-interpreter** | Can code interpreter be abused? |
| **auto-patch** | Can model patch vulnerabilities? |

### Insecure Code Generation

```
secid:control/meta/cyberseceval#insecure-code
```

Tests whether LLMs generate code with:
- SQL injection vulnerabilities
- XSS vulnerabilities
- Buffer overflows
- Path traversal
- Other OWASP Top 10 issues

### Cyberattack Helpfulness

```
secid:control/meta/cyberseceval#cyberattack-helpfulness
```

Tests model compliance with attack requests:
- Malware generation
- Exploit development
- Social engineering
- Network attacks

### Prompt Injection

```
secid:control/meta/cyberseceval#prompt-injection
```

Tests susceptibility to:
- Direct prompt injection
- Indirect prompt injection
- Jailbreak attempts

### Version History

| Version | Key Changes |
|---------|-------------|
| 1.0 | Initial release |
| 2.0 | Added prompt injection |
| 3.0 | Expanded attack coverage |
| 4.0 | Added interpreter abuse, auto-patching |

### Notes

- Comprehensive LLM security benchmark
- Open methodology and datasets
- Used for Llama model safety evaluation
- Enables cross-model comparison
