---
type: control
namespace: owasp.org
full_name: "Open Web Application Security Project"
operator: "secid:entity/owasp.org"
website: "https://owasp.org"
status: active

sources:
  ai-exchange:
    full_name: "OWASP AI Exchange Controls"
    urls:
      website: "https://owaspai.org"
      index: "https://owaspai.org/docs/ai_security_overview/#periodic-table-of-ai-security"
      controls: "https://owaspai.org/docs/ai_security_overview/#how-to-address-ai-security"
      lookup: "https://owaspai.org/goto/{id}/"
    id_pattern: "[A-Z]+"
    examples:
      - "secid:control/owasp.org/ai-exchange#RATELIMIT"
      - "secid:control/owasp.org/ai-exchange#INPUTDISTORTION"
      - "secid:control/owasp.org/ai-exchange#MODELACCESSCONTROL"
---

# OWASP Control Frameworks

OWASP produces security controls and verification standards alongside their weakness taxonomies.

## Why OWASP Matters for Controls

OWASP controls bridge the gap between identifying risks and implementing solutions:

- **Practitioner-focused** - Written for developers and security teams
- **Mapped to threats** - Controls linked to specific risks
- **Free and open** - No licensing restrictions
- **Community-driven** - Continuous improvement

## Control Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `asvs` | Application Security Verification Standard | V5.3.4 |
| `ai-exchange` | AI Security Controls | INPUTFILTERING |

## ASVS Overview

The Application Security Verification Standard (ASVS) provides:
- Security requirements for web applications
- Three verification levels (L1, L2, L3)
- Testable security controls

## Relationship to OWASP Top 10 Lists

| Project | Purpose |
|---------|---------|
| Top 10 / LLM Top 10 | Identify risks (weaknesses) |
| ASVS / AI Exchange | Provide controls (mitigations) |

---

## ai-exchange

Security controls from the OWASP AI Exchange "Periodic Table of AI Security" - mapped directly to AI threats.

### Format

```
secid:control/owasp.org/ai-exchange#CONTROLID
secid:control/owasp.org/ai-exchange#RATELIMIT
secid:control/owasp.org/ai-exchange#MODELACCESSCONTROL
```

### Resolution

The lookup URL `https://owaspai.org/goto/{id}/` redirects to the detailed page for each control.

### Control Categories

#### Governance Controls

| ID | Name |
|----|------|
| AIPROGRAM | AI security program |
| SECPROGRAM | Security program |
| DEVPROGRAM | Development program |
| SECDEVPROGRAM | Secure development program |
| CHECKCOMPLIANCE | Compliance checking |
| SECEDUCATE | Security education |

#### Data Protection Controls

| ID | Name |
|----|------|
| DATAMINIMIZE | Data minimization |
| ALLOWEDDATA | Allowed data policy |
| SHORTRETAIN | Short retention periods |
| OBFUSCATETRAININGDATA | Obfuscate training data |
| SEGREGATEDATA | Segregate data |

#### Runtime Protection Controls

| ID | Name |
|----|------|
| RUNTIMEMODELINTEGRITY | Runtime model integrity |
| RUNTIMEMODELIOINTEGRITY | Runtime model I/O integrity |
| RUNTIMEMODELCONFIDENTIALITY | Runtime model confidentiality |
| MODELINPUTCONFIDENTIALITY | Model input confidentiality |
| ENCODEMODELOUTPUT | Encode model output |
| LIMITRESOURCES | Limit resources |

#### Monitoring & Access Controls

| ID | Name |
|----|------|
| MONITORUSE | Monitor use |
| MODELACCESSCONTROL | Model access control |
| RATELIMIT | Rate limiting |

#### AI Engineering - I/O Handling Controls

| ID | Name |
|----|------|
| ANOMALOUSINPUTHANDLING | Anomalous input handling |
| PROMPTINJECTIONIOHANDLING | Prompt injection I/O handling |
| FILTERSENSITIVEMODELOUTPUT | Filter sensitive model output |

#### Behavior Limitation Controls

| ID | Name |
|----|------|
| OVERSIGHT | Human oversight |
| LEASTMODELPRIVILEGE | Least model privilege |
| AITRANSPARENCY | AI transparency |
| EXPLAINABILITY | Explainability |

### Complete Control List (48 controls)

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

### Relationship to Threats

Each control maps to threats in `secid:weakness/owasp.org/ai-exchange`. Example:

```
secid:control/owasp.org/ai-exchange#PROMPTINJECTIONIOHANDLING
  -> mitigates ->
secid:weakness/owasp.org/ai-exchange#DIRECTPROMPTINJECTION
```

### Notes

- Part of the "Periodic Table of AI Security"
- 48 controls across 9 categories
- Direct mapping to threat IDs
- Threats documented in weakness/owasp.org/ai-exchange
