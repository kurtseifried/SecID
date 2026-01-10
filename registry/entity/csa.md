---

type: "entity"
namespace: "csa"

common_name: "CSA"
full_name: "Cloud Security Alliance"

urls:
  website: "https://cloudsecurityalliance.org"

names:
  ccm:
    full_name: "Cloud Controls Matrix"
    urls:
      website: "https://cloudsecurityalliance.org/research/cloud-controls-matrix/"
    issues_type: "control"
    issues_namespace: "csa-ccm"
  aicm:
    full_name: "AI Controls Matrix"
    urls:
      website: "https://cloudsecurityalliance.org/research/ai-controls-matrix/"
    issues_type: "control"
    issues_namespace: "csa-aicm"

wikidata: "Q5135907"
status: "active"
established: 2008
---


# CSA

Cloud Security Alliance is a nonprofit focused on cloud and AI security. Key frameworks:

- **CCM** - Cloud Controls Matrix
- **AICM** - AI Controls Matrix
- **STAR** - Security, Trust, Assurance, and Risk

## Names in This Namespace

| Name | Full Name | Identifier Type |
|------|-----------|-----------------|
| `ccm` | Cloud Controls Matrix | `control/csa-ccm/*` |
| `aicm` | AI Controls Matrix | `control/csa-aicm/*` |

## Examples

```
secid:entity/csa/ccm        # Cloud Controls Matrix
secid:entity/csa/aicm       # AI Controls Matrix
```
