# Controls Type (`control`)

This type contains references to security controls, frameworks, and guidance documents.

## Purpose

Track and reference security controls - both **requirements** (what you need to do) and **capabilities** (how to do it):

**Control Requirements** (frameworks that define what to implement):
- NIST Cybersecurity Framework (CSF)
- CSA Cloud Controls Matrix (CCM)
- CSA AI Controls Matrix (AICM)
- CIS Controls
- ISO 27001 Annex A controls
- OWASP ASVS (Application Security Verification Standard)

**Control Capabilities** (guidance that helps implement requirements):
- NIST SP 800-61 (Incident Response)
- NIST SP 800-86 (Forensics)
- NIST SP 800-53 (Security and Privacy Controls)
- CIS Benchmarks (hardening guides)

## Identifier Format

```
secid:control/<namespace>/<id>[@version]

secid:control/csa-aicm/INP-01
secid:control/csa-ccm/IAM-12@4.0
secid:control/nist-csf/PR.AC-1@2.0
secid:control/cis/1.1@8.0
secid:control/iso27001/A.8.1@2022
secid:control/owasp-asvs/V5.3.4
```

## Namespaces

### Control Requirements (Frameworks)

| Namespace | Framework | Description |
|-----------|-----------|-------------|
| `csa-aicm` | CSA AI Controls Matrix | AI-specific security controls |
| `csa-ccm` | CSA Cloud Controls Matrix | Cloud security controls |
| `nist-csf` | NIST Cybersecurity Framework | Cybersecurity framework |
| `cis` | CIS Controls | Center for Internet Security |
| `iso27001` | ISO 27001 | Information security standard |
| `owasp-asvs` | OWASP ASVS | Application security controls |

### Control Capabilities (Guidance)

| Namespace | Publication | Description |
|-----------|-------------|-------------|
| `nist-800-53` | NIST SP 800-53 | Security and Privacy Controls |
| `nist-800-61` | NIST SP 800-61 | Incident Response guidance |
| `nist-800-86` | NIST SP 800-86 | Forensics guidance |
| `cis-benchmark` | CIS Benchmarks | Platform hardening guides |

## Versioning

Controls frameworks have versions. Use `@version` to pin:

```
secid:control/csa-ccm/IAM-12@4.0      # CCM version 4.0
secid:control/cis/1.1@8.0              # CIS Controls v8
secid:control/nist-csf/PR.AC-1@2.0     # NIST CSF 2.0
```

Omitting version implies "current" or "any version".

## Subpaths

Use `#subpath` to reference specific guidance within a control:

```
secid:control/csa-ccm/IAM-12@4.0#audit           # Audit guidance
secid:control/csa-ccm/IAM-12@4.0#implementation  # Implementation guidance
```

## Relationships

Controls mitigate weaknesses:

```json
{
  "from": "secid:control/csa-aicm/INP-01",
  "to": "secid:weakness/owasp-llm/LLM01",
  "type": "mitigates",
  "strength": "partial",
  "description": "Input validation helps but doesn't fully prevent prompt injection"
}
```

Controls counter TTPs:

```json
{
  "from": "secid:control/nist-csf/DE.CM-1",
  "to": "secid:ttp/attack/T1059",
  "type": "detects",
  "description": "Monitoring detects command execution"
}
```

Controls satisfy regulatory requirements:

```json
{
  "from": "secid:control/iso27001/A.8.1@2022",
  "to": "secid:regulation/eu/gdpr#art-32",
  "type": "satisfies",
  "description": "Asset management control satisfies GDPR security requirement"
}
```

## AI-Specific Controls

The CSA AI Controls Matrix provides AI-specific controls organized around:
- Input validation and sanitization
- Output filtering and validation
- Model governance and security
- Data protection and privacy
- RAG (Retrieval Augmented Generation) security
- Agent and tool security

## Control vs Weakness vs TTP

- **Weakness** (weakness): What's wrong (CWE-79 = XSS pattern)
- **TTP** (ttp): How attackers exploit it (T1059 = command execution)
- **Control** (control): How to prevent/detect/respond - both requirements and capabilities

## Requirements vs Capabilities

Think of it this way:
- **Requirements** answer: "What security controls must we have?"
- **Capabilities** answer: "How do we implement those controls?"

Example:
- `secid:control/nist-csf/RS.RP-1` - Requirement: "Response plan is executed"
- `secid:control/nist-800-61/section-3` - Capability: How to do incident response

