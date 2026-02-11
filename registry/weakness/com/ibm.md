---
type: weakness
namespace: ibm.com
full_name: "IBM"
operator: "secid:entity/ibm.com"
website: "https://www.ibm.com"
status: active

sources:
  ai-risk-atlas:
    full_name: "IBM AI Risk Atlas"
    urls:
      website: "https://www.ibm.com/docs/en/watsonx/saas?topic=ai-risk-atlas"
      index: "https://www.ibm.com/docs/en/watsonx/saas?topic=ai-risk-atlas"
    id_pattern: "[a-z-]+"
    examples:
      - "secid:weakness/ibm.com/ai-risk-atlas#hallucination"
      - "secid:weakness/ibm.com/ai-risk-atlas#prompt-injection"
      - "secid:weakness/ibm.com/ai-risk-atlas#jailbreaking"
---

# IBM Weakness Taxonomies

AI and machine learning risk taxonomies published by IBM, providing practical, enterprise-focused AI risk documentation.

## Why IBM Weakness Resources Matter

IBM provides practical, enterprise-focused AI risk documentation drawing from their experience deploying AI systems at scale.

## Related Namespaces

| Namespace | Relationship |
|-----------|--------------|
| `secid:entity/ibm.com` | IBM as an organization |
| `secid:weakness/owasp.org/llm-top10` | Complementary LLM risk taxonomy |
| `secid:weakness/mit.edu/ai-risk-repository` | More comprehensive academic taxonomy |

---

## ai-risk-atlas

Interactive resource for understanding risks of working with agentic AI, generative AI, foundation models, and machine learning.

### Format

```
secid:weakness/ibm.com/ai-risk-atlas#RISK-NAME
secid:weakness/ibm.com/ai-risk-atlas#hallucination
secid:weakness/ibm.com/ai-risk-atlas#prompt-injection
```

### Why IBM AI Risk Atlas Matters

- **Practical focus** - Oriented toward working professionals
- **Agentic AI coverage** - Specific section for AI agent risks
- **Interactive exploration** - Browsable risk categories
- **Industry perspective** - Enterprise AI deployment focus

### Risk Categories (8 Primary)

| Category | Focus |
|----------|-------|
| **Accuracy** | Hallucination, incorrect outputs |
| **Fairness** | Bias, discriminatory behaviors |
| **Privacy** | Data exposure, information sharing |
| **Robustness** | Adversarial attacks, edge cases |
| **Explainability** | Unexplainable actions, opacity |
| **Value Alignment** | Goal misalignment, harmful behaviors |
| **Governance** | Oversight, accountability |
| **Intellectual Property** | Training data rights, output ownership |

### Risk Organization

| Section | Description |
|---------|-------------|
| **Agentic AI Risks** | Risks specific to or amplified by AI agents |
| **Training Data Risks** | Issues from data used in model training |
| **Inference Risks** | Problems during model operation |
| **Output Risks** | Harmful or problematic model outputs |
| **Non-technical Risks** | Societal, environmental, employment impacts |

### Risk Tags

IBM uses color-coded tags:
- **Purple** - Specific to agentic or generative AI
- **Green** - Amplified by these technologies
- **Magenta** - Related to synthetic data use

### Notable Risks Covered

- Prompt injection and manipulation attacks
- Model hallucinations and confabulation
- Jailbreaking vulnerabilities
- Discriminatory behaviors in agentic systems
- Privacy concerns with tool and user interactions
- Environmental and employment societal impacts

### Notes

- Part of IBM watsonx documentation
- Regularly updated with new AI risks
- Useful for enterprise AI risk assessment
- Complements OWASP and MITRE frameworks
