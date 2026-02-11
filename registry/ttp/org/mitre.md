---
type: ttp
namespace: mitre.org
full_name: "MITRE TTP Frameworks"
operator: "secid:entity/mitre.org"
status: active

sources:
  attack:
    full_name: "MITRE ATT&CK"
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
      - "secid:ttp/mitre.org/attack#T1059"
      - "secid:ttp/mitre.org/attack#T1059.003"
      - "secid:ttp/mitre.org/attack#TA0001"

  atlas:
    full_name: "MITRE ATLAS"
    urls:
      website: "https://atlas.mitre.org"
      api: "https://atlas.mitre.org/api"
      lookup: "https://atlas.mitre.org/techniques/{id}"
    id_patterns:
      - pattern: "AML\\.T\\d{4}(\\.\\d{3})?"
        type: "technique"
      - pattern: "AML\\.TA\\d{4}"
        type: "tactic"
      - pattern: "AML\\.CS\\d{4}"
        type: "case-study"
    examples:
      - "secid:ttp/mitre.org/atlas#AML.T0043"
      - "secid:ttp/mitre.org/atlas#AML.T0051"
      - "secid:ttp/mitre.org/atlas#AML.TA0001"

  capec:
    full_name: "Common Attack Pattern Enumeration and Classification"
    urls:
      website: "https://capec.mitre.org"
      lookup: "https://capec.mitre.org/data/definitions/{num}.html"
    id_pattern: "CAPEC-\\d+"
    examples:
      - "secid:ttp/mitre.org/capec#CAPEC-66"
      - "secid:ttp/mitre.org/capec#CAPEC-242"
      - "secid:ttp/mitre.org/capec#CAPEC-86"
---

# MITRE TTP Frameworks

MITRE operates several frameworks for describing adversary tactics, techniques, and procedures. Each serves different use cases while maintaining structural consistency.

## ATT&CK

Adversarial tactics, techniques, and common knowledge—the industry-standard framework for describing cyber adversary behavior.

### Format

```
secid:ttp/mitre.org/attack#TNNNN          # Technique
secid:ttp/mitre.org/attack#TNNNN.NNN      # Sub-technique
secid:ttp/mitre.org/attack#TANNNN         # Tactic
```

### Matrices

- Enterprise (Windows, Linux, macOS, Cloud, etc.)
- Mobile (Android, iOS)
- ICS (Industrial Control Systems)

### Example Techniques

| ID | Name |
|----|------|
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell |
| T1078 | Valid Accounts |
| T1566 | Phishing |

### Subpaths

Reference sections within a technique:

```
secid:ttp/mitre.org/attack#T1059/detection
secid:ttp/mitre.org/attack#T1059/mitigation
secid:ttp/mitre.org/attack#T1059/procedure-examples
```

### Notes

- Sub-techniques use `.NNN` suffix (part of the ID, not a subpath)
- Updated quarterly
- Maps to mitigations (M*) and detection (CAR)

## ATLAS

Adversarial Threat Landscape for AI Systems—ATT&CK-style framework specifically for AI/ML threats.

### Format

```
secid:ttp/mitre.org/atlas#AML.TNNNN       # Technique
secid:ttp/mitre.org/atlas#AML.TANNNN      # Tactic
```

### Key Techniques

| ID | Name |
|----|------|
| AML.T0043 | Prompt Injection |
| AML.T0051 | LLM Jailbreak |
| AML.T0040 | ML Supply Chain Compromise |
| AML.T0043.000 | Direct Prompt Injection |
| AML.T0043.001 | Indirect Prompt Injection |

### Relationships

```
secid:ttp/mitre.org/atlas#AML.T0043 → exploits → secid:weakness/mitre.org/cwe#CWE-1427
secid:ttp/mitre.org/atlas#AML.T0043 → exploits → secid:weakness/owasp.org/llm-top10#LLM01
```

### Notes

- AI/ML specific attack framework
- Modeled after ATT&CK structure
- Includes case studies of real attacks

## CAPEC

Common Attack Pattern Enumeration and Classification—higher-abstraction attack patterns that link to CWE weaknesses.

### Format

```
secid:ttp/mitre.org/capec#CAPEC-NNN
```

### Resolution

```
https://capec.mitre.org/data/definitions/{num}.html
```

### Key Attack Patterns

| ID | Name |
|----|------|
| CAPEC-66 | SQL Injection |
| CAPEC-86 | XSS Through HTTP Headers |
| CAPEC-242 | Code Injection |

### Relationships

```
secid:ttp/mitre.org/capec#CAPEC-66 → exploits → secid:weakness/mitre.org/cwe#CWE-89
```

### Notes

- Higher abstraction than ATT&CK
- Links to CWEs (weakness exploited)
- Includes prerequisites and mitigations
