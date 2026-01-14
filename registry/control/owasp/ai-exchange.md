---
type: control
namespace: owasp
name: ai-exchange
full_name: "OWASP AI Exchange Controls"
operator: "secid:entity/owasp"

urls:
  website: "https://owaspai.org"
  controls: "https://owaspai.org/docs/ai_security_overview/"
  periodic_table: "https://owaspai.org/docs/ai_security_overview/#periodic-table-of-ai-security"
  lookup: "https://owaspai.org/goto/{id}/"

id_pattern: "[A-Z]+\\d*"

examples:
  - "secid:control/owasp/ai-exchange#INPUTFILTERING"
  - "secid:control/owasp/ai-exchange#RATELIMITING"
  - "secid:control/owasp/ai-exchange#MODELACCESSCONTROL"

status: active
---

# OWASP AI Exchange Controls

The OWASP AI Exchange provides security controls mapped directly to AI threats. The "Periodic Table of AI Security" organizes both threats and their corresponding mitigations.

## Format

```
secid:control/owasp/ai-exchange#CONTROL
secid:control/owasp/ai-exchange#INPUTFILTERING
secid:control/owasp/ai-exchange#OUTPUTENCODING
```

## Relationship to Weaknesses

The OWASP AI Exchange exists in both namespaces because it covers both sides:

| Type | Namespace | Purpose |
|------|-----------|---------|
| `weakness` | `secid:weakness/owasp/ai-exchange#...` | AI threats and vulnerabilities |
| `control` | `secid:control/owasp/ai-exchange#...` | Mitigations and controls |

This enables direct linkage:
```
secid:weakness/owasp/ai-exchange#PROMPTINJECTION
  → mitigated_by →
secid:control/owasp/ai-exchange#INPUTFILTERING
```

## Control Categories

### Input Controls
| Control | Description |
|---------|-------------|
| INPUTFILTERING | Filter malicious input patterns |
| INPUTVALIDATION | Validate input format and content |
| RATELIMITING | Limit request frequency |

### Output Controls
| Control | Description |
|---------|-------------|
| OUTPUTENCODING | Encode outputs safely |
| OUTPUTFILTERING | Filter sensitive information |
| CONTENTMODERATION | Moderate generated content |

### Model Controls
| Control | Description |
|---------|-------------|
| MODELACCESSCONTROL | Restrict model access |
| MODELMONITORING | Monitor model behavior |
| MODELHARDENING | Harden model against attacks |

### Data Controls
| Control | Description |
|---------|-------------|
| DATAVALIDATION | Validate training data |
| DATAMINIMIZATION | Minimize data exposure |
| DATASANITIZATION | Sanitize sensitive data |

## The Periodic Table

The OWASP AI Exchange organizes AI security as a "periodic table" showing:
- **Threats** (what can go wrong)
- **Controls** (how to prevent it)
- **Mappings** (which controls address which threats)

This structure enables:
1. Identify a threat → Find applicable controls
2. Select a control → See which threats it addresses
3. Gap analysis → Find threats without adequate controls

## Notes

- Comprehensive threat-to-control mapping
- Continuously updated with emerging threats
- Maps to CWE, MITRE ATLAS, and other frameworks
- Useful for AI security architecture and compliance
