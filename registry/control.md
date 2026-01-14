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
secid:control/<namespace>/<name>[@version][#subpath]

secid:control/csa/aicm@1.0#INP-01
secid:control/csa/ccm@4.0#IAM-12
secid:control/nist/csf@2.0#PR.AC-1
secid:control/cis/controls@8.0#1.1
secid:control/iso/27001@2022#A.8.1
secid:control/owasp/asvs@4.0#V5.3.4
```

The namespace is the organization, the name is the framework/document, and the subpath references specific controls within that framework.

## Namespaces

### Control Requirements (Frameworks)

| Namespace | Name | Framework | Description |
|-----------|------|-----------|-------------|
| `nist` | `csf` | NIST Cybersecurity Framework | Cybersecurity framework |
| `cis` | `controls` | CIS Controls | Center for Internet Security |
| `iso` | `27001` | ISO 27001 | Information security standard |
| `owasp` | `asvs` | OWASP ASVS | Application security controls |
| `csa` | `ccm` | CSA Cloud Controls Matrix | Cloud security controls |

### AI-Specific Control Frameworks

| Namespace | Name | Framework | Description |
|-----------|------|-----------|-------------|
| `csa` | `aicm` | CSA AI Controls Matrix | AI-specific security controls |
| `owasp` | `ai-exchange` | OWASP AI Exchange | AI controls mapped to threats |
| `nist` | `ai-rmf` | NIST AI RMF | AI Risk Management Framework |

### Control Capabilities (Guidance)

| Namespace | Name | Publication | Description |
|-----------|------|-------------|-------------|
| `nist` | `800-53` | NIST SP 800-53 | Security and Privacy Controls |
| `nist` | `800-61` | NIST SP 800-61 | Incident Response guidance |
| `nist` | `800-86` | NIST SP 800-86 | Forensics guidance |
| `cis` | `benchmark` | CIS Benchmarks | Platform hardening guides |

## Versioning

Controls frameworks have versions. Use `@version` to pin:

```
secid:control/csa/ccm@4.0#IAM-12       # CCM version 4.0
secid:control/cis/controls@8.0#1.1     # CIS Controls v8
secid:control/nist/csf@2.0#PR.AC-1     # NIST CSF 2.0
```

Omitting version implies "current" or "any version".

## Subpaths

Use `#subpath` with `/` for hierarchy to reference specific controls and sections:

```
secid:control/csa/ccm@4.0#IAM-12                   # Specific control
secid:control/csa/ccm@4.0#IAM-12/audit             # Audit guidance within control
secid:control/csa/ccm@4.0#IAM-12/implementation    # Implementation guidance
secid:control/csa/aicm@1.0#INP-01/Auditing%20Guidelines  # Section with spaces (percent-encoded)
```

## Relationships

Controls mitigate weaknesses:

```json
{
  "from": "secid:control/csa/aicm@1.0#INP-01",
  "to": "secid:weakness/owasp/llm-top10@2.0#LLM01",
  "type": "mitigates",
  "strength": "partial",
  "description": "Input validation helps but doesn't fully prevent prompt injection"
}
```

Controls counter TTPs:

```json
{
  "from": "secid:control/nist/csf@2.0#DE.CM-1",
  "to": "secid:ttp/mitre/attack#T1059",
  "type": "detects",
  "description": "Monitoring detects command execution"
}
```

Controls satisfy regulatory requirements:

```json
{
  "from": "secid:control/iso/27001@2022#A.8.1",
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
- `secid:control/nist/csf@2.0#RS.RP-1` - Requirement: "Response plan is executed"
- `secid:control/nist/800-61#section-3` - Capability: How to do incident response

