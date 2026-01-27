---
type: weakness
namespace: anthropic
full_name: "Anthropic"
operator: "secid:entity/anthropic"
website: "https://www.anthropic.com"
status: active

sources:
  asl:
    full_name: "AI Safety Levels"
    urls:
      website: "https://www.anthropic.com/responsible-scaling-policy"
      rsp: "https://www.anthropic.com/responsible-scaling-policy"
    versions:
      - "2.2"
    examples:
      - "secid:weakness/anthropic/asl#ASL-1"
      - "secid:weakness/anthropic/asl#ASL-2"
      - "secid:weakness/anthropic/asl#ASL-3"
      - "secid:weakness/anthropic/asl#ASL-4"
---

# Anthropic Weakness Taxonomies

Anthropic's AI Safety Levels (ASL) framework defines capability thresholds that determine security and safety requirements for AI systems.

## Why Anthropic's Framework Matters

Anthropic's RSP (Responsible Scaling Policy) introduces a proactive approach:

- **Capability-based** - Requirements scale with model capabilities
- **Proactive** - Safeguards established before capabilities emerge
- **Transparent** - Publicly documented thresholds and requirements
- **Industry influence** - Adopted/adapted by other labs

## Relationship to Other Frameworks

| Framework | Relationship |
|-----------|--------------|
| NIST AI RMF | ASL informs risk assessment |
| Frontier Model Forum | Shared safety commitments |
| UK AI Safety Institute | Evaluation collaboration |

---

## asl

AI Safety Levels (ASL) define capability thresholds that trigger specific security and safety requirements.

### Format

```
secid:weakness/anthropic/asl#ASL-N
```

Where N is the safety level (1-4+).

### Safety Level Definitions

| Level | Capability Threshold | Requirements |
|-------|---------------------|--------------|
| **ASL-1** | No meaningful catastrophic risk | Basic safety practices |
| **ASL-2** | Current frontier models | Standard deployment safeguards |
| **ASL-3** | Significantly uplift attacks (CBRN, cyber) | Enhanced security, red teaming, access controls |
| **ASL-4** | Potential for catastrophic misuse | Stringent containment, government coordination |
| **ASL-4+** | Transformative/existential risk | To be determined |

### ASL-2 (Current State)

Most current frontier models are ASL-2:
- Models can provide some uplift but not beyond expert knowledge
- Standard deployment safeguards sufficient
- Regular safety evaluations required

### ASL-3 Triggers

A model reaches ASL-3 when it can:
- Provide meaningful uplift for CBRN weapon creation
- Enable sophisticated cyberattacks beyond current capabilities
- Significantly assist in other catastrophic scenarios

ASL-3 requirements include:
- Enhanced security for model weights
- Mandatory red teaming for dangerous capabilities
- Restricted deployment and access controls

### Why ASL Matters for Security

| Use Case | Application |
|----------|-------------|
| Risk Assessment | Categorize AI system risk level |
| Security Requirements | Determine appropriate safeguards |
| Compliance | Meet responsible scaling commitments |
| Procurement | Evaluate AI vendor safety practices |

### Evaluation Process

Anthropic's approach:
1. **Capability evaluations** - Test for dangerous capabilities
2. **Red teaming** - Adversarial testing for misuse
3. **Threshold assessment** - Determine ASL level
4. **Safeguard implementation** - Apply level-appropriate controls

### Notes

- ASL framework is part of Anthropic's Responsible Scaling Policy (RSP)
- Version 2.2 is current as of late 2024
- Other labs have similar frameworks (e.g., OpenAI's Preparedness Framework)
- ASL-3 has not yet been triggered for any deployed model
- Framework evolves as understanding of AI risks improves
