# Tactics, Techniques & Procedures Type (`ttp`)

This type contains references to attack patterns and adversary behavior frameworks.

## Purpose

Track and reference attack methodologies - the "how attackers do this":
- MITRE ATT&CK (enterprise, mobile, ICS)
- MITRE ATLAS (AI/ML attacks)
- CAPEC (Common Attack Pattern Enumeration)

## Identifier Format

```
secid:ttp/<namespace>/<name>[#subpath]

secid:ttp/mitre.org/attack#T1566
secid:ttp/mitre.org/attack#T1566.001
secid:ttp/mitre.org/attack#TA0001
secid:ttp/mitre.org/atlas#AML.T0043
secid:ttp/mitre.org/capec#CAPEC-66
```

## Namespaces

| Namespace | Name | Framework | Description |
|-----------|------|-----------|-------------|
| `mitre.org` | `attack` | ATT&CK | Enterprise/Mobile/ICS attack techniques |
| `mitre.org` | `atlas` | ATLAS | AI/ML attack techniques |
| `mitre.org` | `capec` | CAPEC | Common Attack Pattern Enumeration |

## ATT&CK ID Format

ATT&CK uses hierarchical IDs:

| Prefix | Type | Example |
|--------|------|---------|
| `T` | Technique | T1566 (Phishing) |
| `T*.xxx` | Sub-technique | T1566.001 (Spearphishing Attachment) |
| `TA` | Tactic | TA0001 (Initial Access) |
| `M` | Mitigation | M1049 |
| `G` | Group | G0016 (APT29) |
| `S` | Software | S0154 (Cobalt Strike) |

## Relationships

TTPs relate to weaknesses they exploit:

```json
{
  "from": "secid:ttp/mitre.org/capec#CAPEC-66",
  "to": "secid:weakness/mitre.org/cwe#CWE-89",
  "type": "exploits",
  "description": "SQL Injection attack exploits CWE-89"
}
```

```json
{
  "from": "secid:ttp/mitre.org/atlas#AML.T0043",
  "to": "secid:weakness/mitre.org/cwe#CWE-1427",
  "type": "exploits",
  "description": "Prompt injection attack"
}
```

TTPs can be mitigated by controls:

```json
{
  "from": "secid:control/cloudsecurityalliance.org/aicm#INP-01",
  "to": "secid:ttp/mitre.org/atlas#AML.T0043",
  "type": "mitigates",
  "description": "Input validation mitigates prompt injection"
}
```

## AI Attack Patterns

ATLAS covers AI-specific TTPs:

| ID | Name |
|----|------|
| AML.T0043 | Prompt Injection |
| AML.T0051 | LLM Jailbreak |
| AML.T0054 | LLM Plugin Compromise |
| AML.T0040 | Model Inversion |
| AML.T0048 | Embedding Space Manipulation |

## TTP vs Weakness vs Control

- **Weakness** (weakness): What's wrong (CWE-79 = XSS pattern)
- **TTP** (ttp): How attackers exploit it (T1059 = command execution)
- **Control** (control): How to prevent/detect/respond

