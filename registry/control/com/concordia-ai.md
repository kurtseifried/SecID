---
type: control
namespace: concordia-ai.com
full_name: "Concordia AI"
operator: "secid:entity/concordia-ai.com"
website: "https://concordia-ai.com"
status: active

sources:
  frontier-ai-rmf:
    full_name: "Frontier AI Risk Management Framework"
    urls:
      website: "https://concordia-ai.com/research/frontier-ai-risk-management-framework/"
      index: "https://concordia-ai.com/research/frontier-ai-risk-management-framework/"
      paper: "https://arxiv.org/abs/2502.06656"
      pdf: "https://www.tc260.org.cn/upload/2024-09-09/1725849192841090989.pdf"
    id_pattern: "[a-z-]+"
    versions:
      - "1.0"
    examples:
      - "secid:control/concordia-ai.com/frontier-ai-rmf@1.0#cyber-offense"
      - "secid:control/concordia-ai.com/frontier-ai-rmf@1.0#biological-risks"
      - "secid:control/concordia-ai.com/frontier-ai-rmf@1.0#self-replication"
---

# Concordia AI Control Frameworks

AI safety research organization focused on frontier AI risk management.

## Why Concordia Matters

Concordia AI collaborates with leading AI labs (including Shanghai AI Laboratory) to develop practical frameworks for managing risks from advanced AI systems.

## Related Namespaces

| Namespace | Relationship |
|-----------|--------------|
| `secid:control/nist.gov/ai-rmf` | US-based AI risk management framework |
| `secid:control/tc260.org.cn/ai-safety-governance` | China's regulatory AI safety framework |

---

## frontier-ai-rmf

Comprehensive framework for managing severe risks from general-purpose AI models, developed by Shanghai AI Laboratory and Concordia AI. China's first comprehensive framework for frontier AI risk management.

### Format

```
secid:control/concordia-ai.com/frontier-ai-rmf@1.0#RISK-AREA
secid:control/concordia-ai.com/frontier-ai-rmf@1.0#cyber-offense
secid:control/concordia-ai.com/frontier-ai-rmf@1.0#autonomous-ai-rd
```

### Why This Framework Matters

- **First Chinese frontier AI framework** - Significant for global AI governance
- **E-T-C analysis approach** - Environment, Threat source, Capability methodology
- **Red/Yellow/Green zones** - Clear risk thresholds for decision making
- **Practical protocols** - Guidelines for identifying, assessing, mitigating risks

### Seven Risk Areas

| Risk Area | Description |
|-----------|-------------|
| **Cyber Offense** | AI-enabled cyberattacks |
| **Biological & Chemical Risks** | CBRN-related AI risks |
| **Persuasion & Manipulation** | AI-powered influence operations |
| **Uncontrolled Autonomous AI R&D** | Self-improving AI systems |
| **Strategic Deception & Scheming** | AI systems that deceive operators |
| **Self-Replication** | AI systems that copy themselves |
| **Collusion** | Multiple AI systems coordinating harmfully |

### Risk Evaluation System

The framework uses the "AI-45 Law" to evaluate risks:

| Zone | Threshold | Response |
|------|-----------|----------|
| **Green** | Below yellow line | Routine deployment, continuous monitoring |
| **Yellow** | Above yellow, below red | Strengthened mitigations, controlled deployment |
| **Red** | Above red line | Suspend development/deployment |

### Technical Report Findings

The accompanying technical report evaluated 20+ models across 7 risk domains. Results showed all assessed models in green and yellow zones, with none crossing red line thresholds.

### Notes

- Released at World AI Conference 2025 in Shanghai
- Collaboration between Shanghai AI Lab and Concordia AI
- Designed to integrate with existing risk management practices
- Complements NIST AI RMF and other frameworks
