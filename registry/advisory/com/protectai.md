---
type: advisory
namespace: protectai.com
full_name: "Protect AI"
operator: "secid:entity/protectai.com"
website: "https://protectai.com"
status: active

sources:
  sightline:
    full_name: "Sightline AI/ML Vulnerability Database"
    urls:
      website: "https://sightline.protectai.com"
      api: "https://sightline.protectai.com/api"
    examples:
      - "secid:advisory/protectai.com/sightline#PAI-2024-001"

  huntr:
    full_name: "huntr AI/ML Bug Bounty"
    urls:
      website: "https://huntr.com"
      disclosure: "https://huntr.com/bounties"
    examples:
      - "secid:advisory/protectai.com/huntr#vulnerability-id"
---

# Protect AI Security Advisories

Protect AI operates vulnerability databases and bug bounty programs focused on AI/ML security.

## Why Protect AI Matters

Specialized AI security focus:

- **AI-specific** - Vulnerabilities in ML frameworks and models
- **Bug bounty** - huntr incentivizes responsible disclosure
- **Database** - Sightline tracks AI/ML supply chain risks
- **Research** - Active security research in AI/ML

---

## sightline

Sightline is a vulnerability database specifically for AI/ML supply chain security.

### Format

```
secid:advisory/protectai.com/sightline#<id>
```

### Coverage

| Category | Examples |
|----------|----------|
| ML frameworks | PyTorch, TensorFlow, JAX |
| Model formats | ONNX, Pickle, SafeTensors |
| Serving systems | TorchServe, Triton, vLLM |
| Data pipelines | Feature stores, ETL tools |
| MLOps tools | MLflow, Kubeflow, Weights & Biases |

### Vulnerability Types

Common AI/ML vulnerability classes tracked:
- **Arbitrary code execution** - Unsafe deserialization (pickle, etc.)
- **Path traversal** - Model loading from untrusted paths
- **Denial of service** - Resource exhaustion in inference
- **Information disclosure** - Model/data leakage
- **Supply chain** - Malicious models and packages

### Resolution

Access Sightline at `https://sightline.protectai.com` and search by:
- Package name
- CVE ID
- Vulnerability type
- Severity

### Notes

- Launched 2024
- Free access to vulnerability data
- API available for integration
- Regular updates as new vulns discovered

---

## huntr

huntr is a bug bounty platform focused on AI/ML and open-source security.

### Format

```
secid:advisory/protectai.com/huntr#<id>
```

### Program Scope

| Category | In Scope |
|----------|----------|
| ML frameworks | PyTorch, TensorFlow, Keras |
| LLM tools | LangChain, LlamaIndex |
| Model serving | Ollama, vLLM, Text Generation Inference |
| ML libraries | Transformers, Diffusers, Gradio |
| Data tools | Pandas, NumPy, Polars |

### Bounty Ranges

| Severity | Typical Bounty |
|----------|----------------|
| Critical | $1,000 - $5,000+ |
| High | $500 - $2,000 |
| Medium | $100 - $500 |
| Low | Recognition |

### Process

1. Researcher discovers vulnerability
2. Submits to huntr platform
3. Protect AI triages and validates
4. Coordinates disclosure with maintainers
5. Bounty paid upon fix

### Notable Discoveries

huntr has disclosed vulnerabilities in:
- Major ML frameworks
- Popular LLM libraries
- Model serving infrastructure
- Data science tools

### Notes

- Acquired by Protect AI
- Focus on open-source AI/ML
- Responsible disclosure program
- Active researcher community
