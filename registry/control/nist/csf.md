---
type: control
namespace: nist
name: csf
full_name: "NIST Cybersecurity Framework"
operator: "secid:entity/nist"

urls:
  website: "https://www.nist.gov/cyberframework"
  lookup: "https://csf.tools/reference/nist-cybersecurity-framework/v2-0/"

id_pattern: "[A-Z]{2}(\\.[A-Z]{2})?-\\d{2}"
versions:
  - "2.0"
  - "1.1"

examples:
  - "secid:control/nist/csf@2.0#GV.RM-01"
  - "secid:control/nist/csf@2.0#ID.AM-01"
  - "secid:control/nist/csf@2.0#PR.AC-01"

status: active
---

# NIST CSF Namespace

Cybersecurity Framework for managing and reducing cyber risk.

## Format

```
secid:control/nist/csf[@VERSION]#CONTROL-ID
secid:control/nist/csf@2.0#GV.RM-01
secid:control/nist/csf#PR.AC-01          # Current version
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

