---
type: control
namespace: owasp
name: ai-exchange
full_name: "OWASP AI Exchange Controls"
operator: "secid:entity/owasp"

urls:
  website: "https://owaspai.org"
  index: "https://owaspai.org/docs/ai_security_overview/#periodic-table-of-ai-security"
  controls: "https://owaspai.org/docs/ai_security_overview/#how-to-address-ai-security"
  lookup: "https://owaspai.org/goto/{id}/"

id_pattern: "[A-Z]+"

examples:
  - "secid:control/owasp/ai-exchange#RATELIMIT"
  - "secid:control/owasp/ai-exchange#INPUTDISTORTION"
  - "secid:control/owasp/ai-exchange#MODELACCESSCONTROL"

status: active
---

# OWASP AI Exchange Controls

Security controls from the OWASP AI Exchange "Periodic Table of AI Security" - mapped directly to AI threats.

## Format

```
secid:control/owasp/ai-exchange#CONTROLID
secid:control/owasp/ai-exchange#RATELIMIT
secid:control/owasp/ai-exchange#MODELACCESSCONTROL
```

## Resolution

The lookup URL `https://owaspai.org/goto/{id}/` redirects to the detailed page for each control.

## Control Categories

### Governance Controls

| ID | Name |
|----|------|
| AIPROGRAM | AI security program |
| SECPROGRAM | Security program |
| DEVPROGRAM | Development program |
| SECDEVPROGRAM | Secure development program |
| CHECKCOMPLIANCE | Compliance checking |
| SECEDUCATE | Security education |

### Data Protection Controls

| ID | Name |
|----|------|
| DATAMINIMIZE | Data minimization |
| ALLOWEDDATA | Allowed data policy |
| SHORTRETAIN | Short retention periods |
| OBFUSCATETRAININGDATA | Obfuscate training data |
| SEGREGATEDATA | Segregate data |

### Development Security Controls

| ID | Name |
|----|------|
| DEVSECURITY | Development security |
| DISCRETE | Discrete processing |
| FEDERATEDLEARNING | Federated learning |
| SUPPLYCHAINMANAGE | Supply chain management |

### Runtime Protection Controls

| ID | Name |
|----|------|
| RUNTIMEMODELINTEGRITY | Runtime model integrity |
| RUNTIMEMODELIOINTEGRITY | Runtime model I/O integrity |
| RUNTIMEMODELCONFIDENTIALITY | Runtime model confidentiality |
| MODELINPUTCONFIDENTIALITY | Model input confidentiality |
| ENCODEMODELOUTPUT | Encode model output |
| LIMITRESOURCES | Limit resources |

### Monitoring & Access Controls

| ID | Name |
|----|------|
| MONITORUSE | Monitor use |
| MODELACCESSCONTROL | Model access control |
| RATELIMIT | Rate limiting |

### Advanced Controls

| ID | Name |
|----|------|
| CONFCOMPUTE | Confidential compute |
| MODELOBFUSCATION | Model obfuscation |
| INPUTSEGREGATION | Input segregation |

### AI Engineering - Data/Model Controls

| ID | Name |
|----|------|
| CONTINUOUSVALIDATION | Continuous validation |
| UNWANTEDBIASTESTING | Unwanted bias testing |
| EVASIONROBUSTMODEL | Evasion-robust model |
| POISONROBUSTMODEL | Poison-robust model |
| TRAINADVERSARIAL | Adversarial training |
| TRAINDATADISTORTION | Training data distortion |
| ADVERSARIALROBUSTDISTILLATION | Adversarial robust distillation |
| MODELENSEMBLE | Model ensemble |
| MORETRAINDATA | More training data |
| SMALLMODEL | Small model |
| DATAQUALITYCONTROL | Data quality control |
| MODELALIGNMENT | Model alignment |

### AI Engineering - I/O Handling Controls

| ID | Name |
|----|------|
| ANOMALOUSINPUTHANDLING | Anomalous input handling |
| EVASIONINPUTHANDLING | Evasion input handling |
| UNWANTEDINPUTSERIESHANDLING | Unwanted input series handling |
| PROMPTINJECTIONIOHANDLING | Prompt injection I/O handling |
| DOSINPUTVALIDATION | DoS input validation |
| INPUTDISTORTION | Input distortion |
| FILTERSENSITIVEMODELOUTPUT | Filter sensitive model output |
| OBSCURECONFIDENCE | Obscure confidence scores |

### Behavior Limitation Controls

| ID | Name |
|----|------|
| OVERSIGHT | Human oversight |
| LEASTMODELPRIVILEGE | Least model privilege |
| AITRANSPARENCY | AI transparency |
| EXPLAINABILITY | Explainability |

## Complete Control List (48 controls)

| Category | Controls |
|----------|----------|
| Governance | AIPROGRAM, SECPROGRAM, DEVPROGRAM, SECDEVPROGRAM, CHECKCOMPLIANCE, SECEDUCATE |
| Data Protection | DATAMINIMIZE, ALLOWEDDATA, SHORTRETAIN, OBFUSCATETRAININGDATA, SEGREGATEDATA |
| Development | DEVSECURITY, DISCRETE, FEDERATEDLEARNING, SUPPLYCHAINMANAGE |
| Runtime | RUNTIMEMODELINTEGRITY, RUNTIMEMODELIOINTEGRITY, RUNTIMEMODELCONFIDENTIALITY, MODELINPUTCONFIDENTIALITY, ENCODEMODELOUTPUT, LIMITRESOURCES |
| Monitoring | MONITORUSE, MODELACCESSCONTROL, RATELIMIT |
| Advanced | CONFCOMPUTE, MODELOBFUSCATION, INPUTSEGREGATION |
| AI Data/Model | CONTINUOUSVALIDATION, UNWANTEDBIASTESTING, EVASIONROBUSTMODEL, POISONROBUSTMODEL, TRAINADVERSARIAL, TRAINDATADISTORTION, ADVERSARIALROBUSTDISTILLATION, MODELENSEMBLE, MORETRAINDATA, SMALLMODEL, DATAQUALITYCONTROL, MODELALIGNMENT |
| AI I/O | ANOMALOUSINPUTHANDLING, EVASIONINPUTHANDLING, UNWANTEDINPUTSERIESHANDLING, PROMPTINJECTIONIOHANDLING, DOSINPUTVALIDATION, INPUTDISTORTION, FILTERSENSITIVEMODELOUTPUT, OBSCURECONFIDENCE |
| Behavior | OVERSIGHT, LEASTMODELPRIVILEGE, AITRANSPARENCY, EXPLAINABILITY |

## Relationship to Threats

Each control maps to threats in `secid:weakness/owasp/ai-exchange`. Example:

```
secid:control/owasp/ai-exchange#PROMPTINJECTIONIOHANDLING
  → mitigates →
secid:weakness/owasp/ai-exchange#DIRECTPROMPTINJECTION
```

## Notes

- Part of the "Periodic Table of AI Security"
- 48 controls across 9 categories
- Direct mapping to threat IDs
- Threats documented in weakness/owasp/ai-exchange
