---
type: control
namespace: sac
full_name: "Standardization Administration of China (SAC) / TC260"
operator: "secid:entity/sac"
website: "https://www.tc260.org.cn"
status: active

sources:
  ai-safety-governance:
    full_name: "AI Safety Governance Framework (China TC260)"
    urls:
      website: "https://www.tc260.org.cn"
      index: "https://www.tc260.org.cn"
      pdf_v1: "https://www.tc260.org.cn/upload/2024-09-09/1725849192841090989.pdf"
    id_pattern: "[a-z-]+"
    versions:
      - "1.0"
      - "2.0"
    examples:
      - "secid:control/sac/ai-safety-governance@1.0"
      - "secid:control/sac/ai-safety-governance@2.0#endemic-risks"
      - "secid:control/sac/ai-safety-governance@2.0#open-source-governance"
---

# SAC / TC260 Control Frameworks

AI safety and cybersecurity standards from China's National Technical Committee 260 on Cybersecurity, under the Standardization Administration of China.

## Why SAC/TC260 Matters

TC260 is one of China's leading AI standards bodies, authoring frameworks that guide AI safety governance for Chinese AI developers and influence global AI governance discussions.

## Related Namespaces

| Namespace | Relationship |
|-----------|--------------|
| `secid:control/nist/ai-rmf` | US AI risk management framework |
| `secid:control/concordia/frontier-ai-rmf` | Frontier AI risk management |
| `secid:reference/ukgov/ai-safety-report` | International AI safety collaboration |

---

## ai-safety-governance

China's national AI safety governance framework, published by the National Technical Committee 260 on Cybersecurity (TC260). Implements the Global AI Governance Initiative.

### Format

```
secid:control/sac/ai-safety-governance@VERSION
secid:control/sac/ai-safety-governance@2.0#endemic-risks
secid:control/sac/ai-safety-governance@2.0#loss-of-control
```

### Why This Framework Matters

- **China's authoritative AI safety standard** - Guides how industry thinks about AI safety
- **Global AI Governance Initiative** - Part of international coordination efforts
- **Includes frontier risks** - CBRN, loss of control, catastrophic risks
- **Regularly updated** - v2.0 released September 2025

### Version History

| Version | Release Date | Key Changes |
|---------|--------------|-------------|
| 1.0 | September 2024 | Initial framework, endemic and application risks |
| 2.0 | September 2025 | Strengthened loss of control/catastrophic risks, open-source governance |

### Risk Categories

Two overarching categories:

| Category | Description |
|----------|-------------|
| **Endemic Generative AI Risks** | Risks inherent to AI by its nature |
| **Application Generative AI Risks** | Misuse or abuse with harmful outcomes |

### Frontier Risk Coverage (v1.0+)

- CBRN (chemical, biological, radiological, nuclear) risks
- Missile domain risks
- Loss of control risks
- Catastrophic risks (expanded in v2.0)

### v2.0 Additions

- Strengthened attention to loss of control and catastrophic risks
- New clauses on open-source AI governance
- Updated risk management measures

### Regulatory Nature

TC260's framework is a roadmap for AI safety governance, not binding law. Details are implemented through subsequent CAC (Cyberspace Administration of China) notices and the Basic Security Requirements national standard.

### Related Standards

| Standard | Relationship |
|----------|--------------|
| Basic Security Requirements | Mandatory security assessments for Chinese LLM developers |
| CAC Notices | Implementation details and updates |

### Notes

- TC260 is one of China's leading AI standards bodies
- Framework promotes consensus among governments, companies, research institutes
- Significant for understanding non-Western AI governance approaches
- Available in Chinese; unofficial translations exist
