# Regulation Type (`regulation`)

This type contains references to laws, directives, and binding legal requirements.

## Purpose

Track and reference regulatory requirements - the "what the law requires":
- GDPR (EU General Data Protection Regulation)
- HIPAA (US Health Insurance Portability and Accountability Act)
- SOX (Sarbanes-Oxley Act)
- NIS2 (EU Network and Information Security Directive)
- EU AI Act
- State/provincial privacy laws (CCPA, etc.)

## Identifier Format

```
secid:regulation/<jurisdiction>/<law>[@version][#article]

secid:regulation/eu/gdpr
secid:regulation/eu/gdpr@2016-04-27
secid:regulation/eu/gdpr#art-32
secid:regulation/eu/gdpr#art-32.1.a
secid:regulation/us/hipaa
secid:regulation/us/hipaa#164.312.a.1
secid:regulation/us/sox
secid:regulation/eu/nis2
secid:regulation/eu/ai-act
secid:regulation/us-ca/ccpa
```

## Namespaces (Jurisdictions)

| Namespace | Jurisdiction | Description |
|-----------|--------------|-------------|
| `eu` | European Union | GDPR, NIS2, AI Act |
| `us` | United States | HIPAA, SOX, federal laws |
| `us-ca` | California | CCPA, CPRA |
| `us-ny` | New York | SHIELD Act, DFS requirements |
| `uk` | United Kingdom | UK GDPR, Data Protection Act |
| `cn` | China | PIPL, Cybersecurity Law |

## Versioning and Citations

Use `@version` for specific versions (often publication dates):

```
secid:regulation/eu/gdpr@2016-04-27     # GDPR publication date
secid:regulation/eu/ai-act@2024-06-13   # AI Act publication date
```

Use `#subpath` for specific articles, sections, or citations:

```
secid:regulation/eu/gdpr#art-32         # Article 32
secid:regulation/eu/gdpr#art-32.1.a     # Article 32(1)(a)
secid:regulation/us/hipaa#164.312.a.1   # Security Rule citation
```

## Key Regulations

### Data Protection
| ID | Name | Jurisdiction |
|----|------|--------------|
| `eu/gdpr` | General Data Protection Regulation | EU |
| `us/hipaa` | Health Insurance Portability and Accountability Act | US |
| `us-ca/ccpa` | California Consumer Privacy Act | California |
| `cn/pipl` | Personal Information Protection Law | China |

### Security and Infrastructure
| ID | Name | Jurisdiction |
|----|------|--------------|
| `eu/nis2` | Network and Information Security Directive 2 | EU |
| `us/fisma` | Federal Information Security Management Act | US |
| `us/sox` | Sarbanes-Oxley Act | US |

### AI-Specific
| ID | Name | Jurisdiction |
|----|------|--------------|
| `eu/ai-act` | EU Artificial Intelligence Act | EU |

## EU AI Act Detail

The EU AI Act (entered into force August 2024) is the first comprehensive AI regulation. It uses a risk-based approach:

### Risk Categories

| Risk Level | Examples | Requirements |
|------------|----------|--------------|
| **Unacceptable** | Social scoring, real-time biometric ID | Prohibited |
| **High-risk** | Critical infrastructure, employment, credit | Conformity assessment, registration |
| **Limited** | Chatbots, deepfakes | Transparency obligations |
| **Minimal** | Spam filters, games | No requirements |

### Key Articles

```
secid:regulation/eu/ai-act#art-5      # Prohibited AI practices
secid:regulation/eu/ai-act#art-6      # High-risk classification
secid:regulation/eu/ai-act#art-9      # Risk management system
secid:regulation/eu/ai-act#art-10     # Data governance
secid:regulation/eu/ai-act#art-13     # Transparency
secid:regulation/eu/ai-act#art-14     # Human oversight
secid:regulation/eu/ai-act#art-52     # Transparency for certain AI systems
```

### Timeline

- **August 2024**: Entry into force
- **February 2025**: Prohibited practices apply
- **August 2025**: GPAI (general-purpose AI) rules apply
- **August 2026**: High-risk AI system rules apply

### Relationship to Controls

The AI Act creates demand for AI-specific controls:

```json
{
  "from": "secid:control/csa/aicm@1.0#GOV-01",
  "to": "secid:regulation/eu/ai-act#art-9",
  "type": "satisfies",
  "description": "AI governance controls address AI Act risk management requirements"
}
```

## Relationships

Controls satisfy regulatory requirements:

```json
{
  "from": "secid:control/iso/27001@2022#A.8.1",
  "to": "secid:regulation/eu/gdpr#art-32",
  "type": "satisfies",
  "description": "Asset management addresses GDPR security requirements"
}
```

Regulations may reference other regulations:

```json
{
  "from": "secid:regulation/eu/nis2",
  "to": "secid:regulation/eu/gdpr",
  "type": "references",
  "description": "NIS2 builds on GDPR data protection requirements"
}
```

## Regulation vs Control vs Standard

- **Regulation** (regulation): What the law requires (GDPR, HIPAA)
- **Control** (control): How to meet requirements (ISO 27001, CIS)
- **Scoring/Formats**: Technical specifications (CVSS via `entity/first/cvss`, etc.)

Regulations are **mandatory** within their jurisdiction. Controls are **voluntary** frameworks (unless regulation mandates them). Technical standards are referenced via their operating entity.

## Notes

- Regulations change over time - use version when precision matters
- Subpaths for article citations follow each regulation's numbering scheme
- Some regulations (like GDPR) have extensive guidance documents that may warrant separate entries

