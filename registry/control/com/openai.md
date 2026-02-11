---
type: control
namespace: openai.com
full_name: "OpenAI"
operator: "secid:entity/openai.com"
website: "https://openai.com"
status: active

sources:
  model-spec:
    full_name: "OpenAI Model Spec"
    urls:
      website: "https://openai.com/index/the-model-spec"
      document: "https://cdn.openai.com/spec/model-spec-2024-05-08.html"
    versions:
      - "2024"
    examples:
      - "secid:control/openai.com/model-spec@2024#objectives"
      - "secid:control/openai.com/model-spec@2024#behaviors"

  preparedness:
    full_name: "Preparedness Framework"
    urls:
      website: "https://openai.com/safety/preparedness"
      document: "https://cdn.openai.com/openai-preparedness-framework-beta.pdf"
    versions:
      - "beta"
    examples:
      - "secid:control/openai.com/preparedness#risk-categories"
      - "secid:control/openai.com/preparedness#capability-thresholds"

  red-teaming:
    full_name: "Red Teaming Network"
    urls:
      website: "https://openai.com/index/red-teaming-network"
      apply: "https://openai.com/form/red-teaming-network"
    examples:
      - "secid:control/openai.com/red-teaming"

  system-cards:
    full_name: "Model System Cards"
    urls:
      website: "https://openai.com/research"
      gpt4o: "https://openai.com/index/gpt-4o-system-card"
      o1: "https://openai.com/index/openai-o1-system-card"
    examples:
      - "secid:control/openai.com/system-cards#gpt-4o"
      - "secid:control/openai.com/system-cards#o1"
---

# OpenAI Safety Controls

OpenAI publishes safety frameworks, model specifications, and system cards documenting their approach to AI safety.

## Why OpenAI Frameworks Matter

OpenAI operates frontier AI systems:

- **Scale** - GPT-4, ChatGPT serve millions
- **Capabilities** - Leading frontier models
- **Influence** - Sets industry practices
- **Transparency** - Public safety documentation

---

## model-spec

The Model Spec defines how OpenAI models should behave across different situations.

### Format

```
secid:control/openai.com/model-spec@2024#<section>
```

### Core Components

| Component | Description |
|-----------|-------------|
| **Objectives** | What the model should optimize for |
| **Rules** | Hard constraints (always/never behaviors) |
| **Guidelines** | Soft preferences (should/shouldn't) |
| **Defaults** | Default behaviors when uncertain |

### Principal Hierarchy

The model spec defines a principal hierarchy:
1. **OpenAI** - Highest authority (safety, policy)
2. **Operators** - API users deploying the model
3. **Users** - End users interacting with the model

### Key Behavioral Areas

| Area | Guidance |
|------|----------|
| Harmful content | When and how to refuse |
| Sensitive topics | How to handle carefully |
| Honesty | Truth-telling requirements |
| Safety | Self-preservation and impact |

### Notes

- Published May 2024
- Applies to ChatGPT and API
- Updated periodically
- Guides RLHF training

---

## preparedness

The Preparedness Framework defines how OpenAI evaluates and responds to dangerous AI capabilities.

### Format

```
secid:control/openai.com/preparedness#<component>
```

### Risk Categories

| Category | Description |
|----------|-------------|
| **Cybersecurity** | Offensive cyber capabilities |
| **CBRN** | Chemical, biological, radiological, nuclear |
| **Persuasion** | Manipulation and influence |
| **Model Autonomy** | Self-directed action capabilities |

### Risk Levels

| Level | Description | Response |
|-------|-------------|----------|
| **Low** | Minimal uplift | Monitoring |
| **Medium** | Some uplift | Mitigations required |
| **High** | Significant uplift | Deploy only with strong mitigations |
| **Critical** | Dangerous capabilities | Do not deploy |

### Scorecard System

Each model evaluated on:
- Pre-mitigation capabilities
- Post-mitigation capabilities
- Residual risk assessment

### Governance

- Safety Advisory Group review
- Board notification for high-risk
- External audit provisions
- Regular reassessment

### Notes

- Published December 2023
- Beta version
- Evolves with capabilities
- Similar to Anthropic RSP, Google FSF

---

## red-teaming

OpenAI's Red Teaming Network provides external evaluation of model safety.

### Format

```
secid:control/openai.com/red-teaming
```

### Network Structure

| Component | Description |
|-----------|-------------|
| **Domain experts** | Subject matter specialists |
| **Security researchers** | Technical red teamers |
| **Diverse perspectives** | Various backgrounds and regions |

### Red Team Activities

- Pre-deployment capability evaluation
- Jailbreak and bypass testing
- Harmful use case exploration
- Bias and fairness assessment

### Domains Covered

| Domain | Focus |
|--------|-------|
| Cybersecurity | Offensive capabilities |
| Biosecurity | Dangerous knowledge |
| Chemistry | Hazardous synthesis |
| Persuasion | Manipulation techniques |
| Discrimination | Bias and stereotypes |

### Notes

- Launched 2022
- External experts recruited
- Informs model decisions
- Findings shared in system cards

---

## system-cards

System Cards document model capabilities, limitations, and safety evaluations.

### Format

```
secid:control/openai.com/system-cards#<model>
```

### Published System Cards

| Model | Date | Key Features |
|-------|------|--------------|
| **GPT-4** | 2023 | First comprehensive card |
| **GPT-4V** | 2023 | Vision capabilities |
| **GPT-4o** | 2024 | Multimodal (audio, vision) |
| **o1** | 2024 | Reasoning model |

### System Card Contents

| Section | Description |
|---------|-------------|
| Model description | Architecture and training |
| Capabilities | What the model can do |
| Limitations | Known weaknesses |
| Safety evaluations | Red team results |
| Mitigations | Deployed safeguards |
| Risk assessment | Residual risks |

### GPT-4o Highlights

- Voice mode safety (emotional manipulation)
- Vision safety (person identification)
- Multimodal jailbreak resistance

### o1 Highlights

- Reasoning chain safety
- Deceptive alignment testing
- Extended thinking capabilities

### Notes

- Published with major releases
- Informs deployment decisions
- Basis for external research
- Evolving format and depth
