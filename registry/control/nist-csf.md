---
namespace: nist-csf
full_name: "NIST Cybersecurity Framework"
type: control
operator: "secid:entity/nist"

urls:
  website: "https://www.nist.gov/cyberframework"
  lookup: "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/"

id_pattern: "[A-Z]{2}(\\.[A-Z]{2})?-\\d{2}"
versions:
  - "2.0"
  - "1.1"

examples:
  - "GV.RM-01"
  - "ID.AM-01"
  - "PR.AC-01"

status: active
---

# NIST CSF Namespace

Cybersecurity Framework for managing and reducing cyber risk.

## Format

```
secid:control/nist-csf/XX.YY-NN@VERSION
secid:control/nist-csf/GV.RM-01@2.0
```

## Functions (CSF 2.0)

| Code | Function |
|------|----------|
| GV | Govern |
| ID | Identify |
| PR | Protect |
| DE | Detect |
| RS | Respond |
| RC | Recover |

## Example Controls

| ID | Name |
|----|------|
| GV.RM-01 | Risk Management Strategy |
| ID.AM-01 | Asset Inventory |
| PR.AC-01 | Identity Management |

## Notes

- CSF 2.0 released 2024 (adds Govern function)
- Maps to other frameworks (ISO 27001, CIS)
- Includes implementation tiers
