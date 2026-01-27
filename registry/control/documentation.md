---
type: control
namespace: documentation
full_name: "AI/ML Documentation Standards"
operator: "secid:entity/various"
website: "https://modelcards.withgoogle.com"
status: active

sources:
  model-cards:
    full_name: "Model Cards for Model Reporting"
    urls:
      website: "https://modelcards.withgoogle.com"
      paper: "https://arxiv.org/abs/1810.03993"
      template: "https://huggingface.co/docs/hub/model-cards"
    versions:
      - "2019"
    examples:
      - "secid:control/documentation/model-cards"

  datasheets:
    full_name: "Datasheets for Datasets"
    urls:
      website: "https://www.microsoft.com/en-us/research/project/datasheets-for-datasets/"
      paper: "https://arxiv.org/abs/1803.09010"
    versions:
      - "2021"
    examples:
      - "secid:control/documentation/datasheets"

  system-cards:
    full_name: "System Cards"
    urls:
      website: "https://huggingface.co/docs/hub/model-cards"
      openai-example: "https://openai.com/index/gpt-4o-system-card"
    examples:
      - "secid:control/documentation/system-cards"
---

# AI/ML Documentation Standards

Documentation standards prescribe what information should be disclosed about AI models and datasets to enable responsible use.

## Why Documentation Standards Matter

Transparency enables accountability:

- **Informed decisions** - Users know model limitations
- **Risk assessment** - Identify potential harms
- **Reproducibility** - Enable verification
- **Compliance** - Meet regulatory requirements

---

## model-cards

Model Cards prescribe standardized documentation for machine learning models.

### Format

```
secid:control/documentation/model-cards
```

### What Model Cards Prescribe

Every ML model should document:

| Section | Contents |
|---------|----------|
| **Model details** | Architecture, training, version |
| **Intended use** | Primary use cases, users |
| **Out-of-scope use** | What NOT to use it for |
| **Factors** | Relevant demographic/environmental factors |
| **Metrics** | Evaluation metrics and results |
| **Training data** | Data sources and characteristics |
| **Evaluation data** | Test set description |
| **Ethical considerations** | Known risks and mitigations |
| **Caveats** | Limitations and recommendations |

### Model Details Section

| Field | Description |
|-------|-------------|
| Developed by | Organization/team |
| Model type | Architecture category |
| Language | Supported languages |
| License | Usage terms |
| Fine-tuned from | Base model if applicable |

### Intended Use Section

| Field | Description |
|-------|-------------|
| Primary use | Main application |
| Downstream use | Acceptable fine-tuning |
| Out-of-scope | Prohibited or risky uses |

### Bias and Limitations

| Field | Description |
|-------|-------------|
| Known biases | Documented biases |
| Limitations | Technical constraints |
| Recommendations | Mitigation guidance |

### Adoption

- HuggingFace requires model cards
- Google publishes model cards
- Major AI labs adopt format
- Regulatory alignment (EU AI Act)

### Notes

- Introduced by Google (Mitchell et al., 2019)
- Now industry standard
- HuggingFace template widely used
- Evolving with AI governance needs

---

## datasheets

Datasheets for Datasets prescribe standardized documentation for ML training datasets.

### Format

```
secid:control/documentation/datasheets
```

### What Datasheets Prescribe

Every ML dataset should document:

| Section | Questions Answered |
|---------|-------------------|
| **Motivation** | Why was dataset created? |
| **Composition** | What's in the dataset? |
| **Collection** | How was data collected? |
| **Preprocessing** | What processing was applied? |
| **Uses** | What should dataset be used for? |
| **Distribution** | How is dataset shared? |
| **Maintenance** | Who maintains it and how? |

### Motivation Questions

- For what purpose was the dataset created?
- Who created the dataset?
- Who funded the creation?

### Composition Questions

- What do instances represent?
- How many instances are there?
- What data does each instance contain?
- Is there missing information?
- Are there known errors?
- Is the dataset self-contained?
- Does it contain confidential data?
- Does it contain offensive content?
- Does it relate to people?

### Collection Questions

- How was data collected?
- Who was involved in collection?
- What was the timeframe?
- Were ethical review processes used?
- Did individuals consent?

### Uses Questions

- What tasks has dataset been used for?
- What tasks should it NOT be used for?
- Is there anything about composition that might impact future uses?

### Distribution Questions

- How is dataset distributed?
- When was it released?
- What license applies?
- Are there export controls?

### Maintenance Questions

- Who maintains the dataset?
- How can issues be reported?
- Will there be updates?

### Notes

- Proposed by Gebru et al. (2018)
- Microsoft research project
- Increasingly required by journals
- Complements model cards

---

## system-cards

System Cards extend model cards to document complete AI systems, not just models.

### Format

```
secid:control/documentation/system-cards
```

### What System Cards Prescribe

Document the complete system:

| Section | Contents |
|---------|----------|
| **System overview** | What the system does |
| **Model components** | Models used in the system |
| **Data flows** | How data moves through system |
| **Safety evaluations** | Red teaming, testing results |
| **Mitigations** | Deployed safeguards |
| **Limitations** | Known issues |
| **Deployment** | How system is deployed |

### Difference from Model Cards

| Model Card | System Card |
|------------|-------------|
| Single model | Complete application |
| Training focus | Deployment focus |
| Technical metrics | Safety evaluations |
| Research-oriented | Production-oriented |

### Safety Evaluation Sections

| Section | Contents |
|---------|----------|
| Red teaming | Adversarial testing results |
| Capability assessments | What system can do |
| Harm evaluations | Potential negative impacts |
| Mitigation effectiveness | How well safeguards work |

### Examples

- OpenAI GPT-4 System Card
- OpenAI GPT-4o System Card
- OpenAI o1 System Card
- Anthropic Claude Model Card

### Notes

- Evolution of model cards
- Required for frontier models
- Supports regulatory compliance
- Increasing industry adoption
