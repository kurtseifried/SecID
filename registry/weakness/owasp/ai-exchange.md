---
type: weakness
namespace: owasp
name: ai-exchange
full_name: "OWASP AI Exchange"
operator: "secid:entity/owasp"

urls:
  website: "https://owaspai.org"
  index: "https://owaspai.org/docs/ai_security_overview/#periodic-table-of-ai-security"
  threats: "https://owaspai.org/docs/ai_security_overview/#how-to-address-ai-security"
  lookup: "https://owaspai.org/goto/{id}/"

id_pattern: "[A-Z]+"

examples:
  - "secid:weakness/owasp/ai-exchange#DIRECTPROMPTINJECTION"
  - "secid:weakness/owasp/ai-exchange#DATAPOISON"
  - "secid:weakness/owasp/ai-exchange#MODELTHEFTUSE"

status: active
---

# OWASP AI Exchange

Comprehensive AI security knowledge base with a "Periodic Table of AI Security" organizing threats and controls.

## Format

```
secid:weakness/owasp/ai-exchange#THREATID
secid:weakness/owasp/ai-exchange#DIRECTPROMPTINJECTION
secid:weakness/owasp/ai-exchange#DATAPOISON
```

## Resolution

The lookup URL `https://owaspai.org/goto/{id}/` redirects to the detailed page for each threat or control.

## Threat Categories

### Prompt Injection

| ID | Name |
|----|------|
| DIRECTPROMPTINJECTION | Direct prompt injection |
| INDIRECTPROMPTINJECTION | Indirect prompt injection |

### Model Attacks

| ID | Name |
|----|------|
| EVASION | Evasion (adversarial examples) |
| RUNTIMEMODELPOISON | Model poisoning at runtime (reprogramming) |
| DEVMODELPOISON | Development-time model poisoning |
| SUPPLYMODELPOISON | Supply-chain model poisoning |

### Data Attacks

| ID | Name |
|----|------|
| DATAPOISON | Training/fine-tune data poisoning |
| DEVDATALEAK | Training data leaks |

### Information Disclosure

| ID | Name |
|----|------|
| DISCLOSUREUSEOUTPUT | Data disclosure in model output |
| MODELINVERSIONANDMEMBERSHIP | Model inversion / Membership inference |
| LEAKINPUT | Model input leak |

### Model Theft

| ID | Name |
|----|------|
| MODELTHEFTUSE | Model theft through use (input-output harvesting) |
| RUNTIMEMODELTHEFT | Direct model theft at runtime |
| DEVMODELLEAK | Model theft at development-time |

### Output & Resource

| ID | Name |
|----|------|
| INSECUREOUTPUT | Model output contains injection |
| AIRESOURCEEXHAUSTION | AI resource exhaustion (model DoS) |

## Complete Threat List

| ID | Category |
|----|----------|
| `DIRECTPROMPTINJECTION` | Prompt Injection |
| `INDIRECTPROMPTINJECTION` | Prompt Injection |
| `EVASION` | Model Attack |
| `RUNTIMEMODELPOISON` | Model Attack |
| `DEVMODELPOISON` | Model Attack |
| `SUPPLYMODELPOISON` | Model Attack |
| `DATAPOISON` | Data Attack |
| `DEVDATALEAK` | Data Attack |
| `DISCLOSUREUSEOUTPUT` | Information Disclosure |
| `MODELINVERSIONANDMEMBERSHIP` | Information Disclosure |
| `LEAKINPUT` | Information Disclosure |
| `MODELTHEFTUSE` | Model Theft |
| `RUNTIMEMODELTHEFT` | Model Theft |
| `DEVMODELLEAK` | Model Theft |
| `INSECUREOUTPUT` | Output Handling |
| `AIRESOURCEEXHAUSTION` | Resource Exhaustion |

## Relationship to Controls

Each threat maps to controls in `secid:control/owasp/ai-exchange`. Example:

```
secid:weakness/owasp/ai-exchange#DIRECTPROMPTINJECTION
  → mitigated_by →
secid:control/owasp/ai-exchange#PROMPTINJECTIONIOHANDLING
```

## Notes

- Part of the "Periodic Table of AI Security"
- Maps to MITRE ATLAS, CWE, and other frameworks
- Continuously updated with emerging threats
- Controls documented in control/owasp/ai-exchange
