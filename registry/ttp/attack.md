---
namespace: attack
full_name: "MITRE ATT&CK"
type: ttp
operator: "secid:entity/mitre/attack"

urls:
  website: "https://attack.mitre.org"
  api: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
  lookup: "https://attack.mitre.org/techniques/{id}/"

id_patterns:
  - pattern: "T\\d{4}(\\.\\d{3})?"
    type: "technique"
  - pattern: "TA\\d{4}"
    type: "tactic"
  - pattern: "M\\d{4}"
    type: "mitigation"
  - pattern: "G\\d{4}"
    type: "group"
  - pattern: "S\\d{4}"
    type: "software"

examples:
  - "T1059"
  - "T1059.003"
  - "TA0001"

status: active
---

# ATT&CK Namespace

Adversarial tactics, techniques, and common knowledge.

## Format

```
secid:ttp/attack/TNNNN          # Technique
secid:ttp/attack/TNNNN.NNN      # Sub-technique
secid:ttp/attack/TANNNN         # Tactic
```

## Matrices

- Enterprise (Windows, Linux, macOS, Cloud, etc.)
- Mobile (Android, iOS)
- ICS (Industrial Control Systems)

## Example Techniques

| ID | Name |
|----|------|
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell |
| T1078 | Valid Accounts |
| T1566 | Phishing |

## Subpaths

```
secid:ttp/attack/T1059#detection
secid:ttp/attack/T1059#mitigation
secid:ttp/attack/T1059#procedure-examples
```

## Notes

- Sub-techniques use `.NNN` suffix (not subpath)
- Updated quarterly
- Maps to mitigations (M*) and detection (CAR)
