---

type: "entity"
namespace: "first.org"

common_name: "FIRST"
full_name: "Forum of Incident Response and Security Teams"

urls:
  website: "https://www.first.org"

names:
  cvss:
    full_name: "Common Vulnerability Scoring System"
    urls:
      website: "https://www.first.org/cvss/"
      calculator: "https://www.first.org/cvss/calculator/4.0"
    description: "Vulnerability severity scoring standard"
  epss:
    full_name: "Exploit Prediction Scoring System"
    urls:
      website: "https://www.first.org/epss/"
      api: "https://api.first.org/data/v1/epss"
    description: "Probability of exploitation scoring"

wikidata: "Q5468579"
status: "active"
established: 1990
---


# FIRST

FIRST is a global forum for incident response and security teams. Key security standards:

- **CVSS** - Common Vulnerability Scoring System
- **EPSS** - Exploit Prediction Scoring System
- **TLP** - Traffic Light Protocol

## Names in This Namespace

| Name | Full Name | Description |
|------|-----------|-------------|
| `cvss` | Common Vulnerability Scoring System | Severity scoring |
| `epss` | Exploit Prediction Scoring System | Exploitation probability |

## Examples

```
secid:entity/first.org/cvss     # CVSS standard
secid:entity/first.org/epss     # EPSS system
```
