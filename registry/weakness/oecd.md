---
type: weakness
namespace: oecd
full_name: "Organisation for Economic Co-operation and Development"
operator: "secid:entity/oecd"
website: "https://oecd.ai"
status: active

sources:
  ai-classification:
    full_name: "OECD Framework for Classification of AI Systems"
    urls:
      website: "https://oecd.ai/en/classification"
      paper: "https://www.oecd-ilibrary.org/science-and-technology/oecd-framework-for-the-classification-of-ai-systems_cb6d9eca-en"
    versions:
      - "2022"
    examples:
      - "secid:weakness/oecd/ai-classification#autonomy-level"
      - "secid:weakness/oecd/ai-classification#data-input-type"

  ai-incidents:
    full_name: "OECD AI Incidents Monitor"
    urls:
      website: "https://oecd.ai/en/incidents"
      dashboard: "https://oecd.ai/en/incidents"
    examples:
      - "secid:weakness/oecd/ai-incidents#incident-category"

  incident-framework:
    full_name: "OECD Common AI Incident Reporting Framework"
    urls:
      website: "https://www.oecd.org/en/topics/ai-risks-and-incidents.html"
      publication: "https://www.oecd.org/en/publications/defining-ai-incidents-and-related-terms_d1a8d965-en.html"
    versions:
      - "2025"
    examples:
      - "secid:weakness/oecd/incident-framework#hazard"
      - "secid:weakness/oecd/incident-framework#harm"
---

# OECD AI Risk Frameworks

The OECD provides internationally recognized frameworks for AI classification, risk assessment, and incident reporting, influencing AI policy across member countries.

## Why OECD Matters

OECD sets international AI policy standards:

- **38 member countries** - Broad international adoption
- **Policy influence** - Shapes national AI regulations
- **Interoperability** - Common language across jurisdictions
- **Evidence-based** - Research-driven frameworks

## OECD AI Policy Observatory

The OECD.AI portal (oecd.ai) provides:
- AI policy tracking across countries
- AI incidents monitoring
- Classification frameworks
- Best practices and guidance

---

## ai-classification

The OECD Framework for Classification of AI Systems provides a standardized approach to categorizing AI systems for policy purposes.

### Format

```
secid:weakness/oecd/ai-classification#<dimension>
```

### Classification Dimensions

| Dimension | Description |
|-----------|-------------|
| **context** | Sector, business function, criticality |
| **data-input** | Data types, sources, and modalities |
| **model** | Model type, training approach |
| **task-output** | What the system produces/decides |
| **autonomy** | Human oversight level |

### Autonomy Levels

| Level | Description | Risk Implications |
|-------|-------------|-------------------|
| Human determines | AI provides information only | Lower risk |
| Human confirms | AI recommends, human decides | Moderate risk |
| Human reviews | AI acts, human can override | Higher risk |
| Full autonomy | AI acts independently | Highest risk |

### Risk-Relevant Factors

The classification helps assess:
- Potential for harm
- Need for human oversight
- Regulatory requirements
- Transparency obligations

### Policy Applications

Used for:
- EU AI Act risk categorization
- National AI strategies
- Procurement decisions
- Regulatory compliance

### Notes

- Published 2022
- Used by OECD member countries for policy alignment
- Complements OECD AI Principles
- Updated periodically

---

## ai-incidents

The OECD AI Incidents Monitor (AIM) tracks and categorizes AI-related incidents globally.

### Format

```
secid:weakness/oecd/ai-incidents#<category>
```

### Incident Categories

| Category | Examples |
|----------|----------|
| **Safety** | Physical harm, accidents |
| **Security** | Cyberattacks, adversarial manipulation |
| **Human Rights** | Discrimination, privacy violations |
| **Societal** | Misinformation, manipulation |
| **Economic** | Market manipulation, fraud |

### Incident Attributes

AIM tracks:
- Incident type and severity
- Affected sector and region
- AI system characteristics
- Harm caused
- Response and remediation

### Why Track AI Incidents

- **Pattern recognition** - Identify recurring failure modes
- **Policy evidence** - Inform regulatory decisions
- **Learning** - Prevent similar incidents
- **Accountability** - Public record of AI harms

### Notes

- Available at oecd.ai/en/incidents
- Aggregates incidents from multiple sources
- Policy-focused analysis
- Complements AIID and other incident databases

---

## incident-framework

The OECD Common AI Incident Reporting Framework standardizes how AI incidents are defined and reported across jurisdictions.

### Format

```
secid:weakness/oecd/incident-framework#<term>
```

### Key Definitions

| Term | Definition |
|------|------------|
| **AI Incident** | Event where AI system causes or nearly causes harm |
| **Hazard** | Source of potential harm from AI system |
| **Harm** | Negative impact on people, property, or environment |
| **Near Miss** | Event that could have caused harm but didn't |

### Incident Severity

| Level | Description |
|-------|-------------|
| Minor | Limited, easily reversible harm |
| Moderate | Significant but recoverable harm |
| Severe | Serious, potentially irreversible harm |
| Critical | Widespread catastrophic harm |

### Reporting Elements

Standardized incident reports include:
1. **What happened** - Factual description
2. **AI system** - Classification per OECD framework
3. **Harm** - Type and severity
4. **Cause** - Technical and organizational factors
5. **Response** - Remediation actions

### Why Standardization Matters

- **Cross-border** - Incidents don't respect borders
- **Aggregation** - Combine data across jurisdictions
- **Learning** - Comparable incident analysis
- **Regulation** - Supports compliance requirements

### Notes

- Developed 2024-2025
- Supports AI Safety Summit commitments
- Aligned with EU AI Act incident reporting
- Voluntary adoption by member countries
