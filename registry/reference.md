# Reference Type

The `reference` type identifies documents and publications that **don't fit into other SecID types**.

## Purpose

References are for citing source materials that aren't covered by other types. If something has a more specific type, use that instead.

## What Belongs Here

| Category | Examples | Why it's a reference |
|----------|----------|---------------------|
| **Executive Orders** | EO 14110 on AI | Policy, not law (yet) |
| **National Strategies** | National Cybersecurity Strategy | Aspirational, not binding |
| **Policy Memos** | OMB M-24-10 | Agency guidance, not regulation |
| **Research Papers** | ArXiv preprints | Academic research |

## What Does NOT Belong Here

| Don't use reference for | Use instead |
|------------------------|-------------|
| NIST SP 800-53 | `secid:control/nist/800-53#AC-1` |
| NIST CSF | `secid:control/nist/csf@2.0#GV.RM-01` |
| ISO 27001 | `secid:control/iso/27001@2022#A.8.1` |
| IETF RFCs | `secid:control/ietf/...` or specific protocol |
| GDPR, HIPAA | `secid:regulation/eu/gdpr`, `secid:regulation/us/hipaa` |
| CWE, OWASP Top 10 | `secid:weakness/mitre/cwe#CWE-79`, `secid:weakness/owasp/top10#A01` |
| CVE, NVD | `secid:advisory/mitre/cve#...`, `secid:advisory/nist/nvd#...` |
| ATT&CK, ATLAS | `secid:ttp/mitre/attack#T1059`, `secid:ttp/mitre/atlas#AML.T0043` |

## Identifier Format

```
secid:reference/<namespace>/<identifier>
```

## Namespaces

| Namespace | Description | Example IDs |
|-----------|-------------|-------------|
| `whitehouse` | US Executive Branch publications | `eo-14110`, `ncs-2023`, `m-24-10` |
| `arxiv` | ArXiv research papers | `2303.08774`, `2402.05369` |

### Examples

```
secid:reference/whitehouse/eo-14110           # AI Executive Order
secid:reference/whitehouse/ncs-2023           # National Cybersecurity Strategy
secid:reference/whitehouse/m-24-10            # OMB AI Governance Memo
secid:reference/whitehouse/nsm-22             # National Security Memo
secid:reference/arxiv/2303.08774              # GPT-4 Technical Report
secid:reference/arxiv/2402.05369              # Sleeper Agents paper
secid:reference/arxiv/2307.03109              # Jailbroken paper
```

## Subpaths

Reference specific sections within documents:

```
secid:reference/whitehouse/eo-14110#section-4.1
secid:reference/whitehouse/eo-14110#section-4.2
secid:reference/arxiv/2303.08774#section-3
secid:reference/arxiv/2303.08774#appendix-a
```

## Relationships

| Relationship | Meaning | Example |
|--------------|---------|---------|
| `precedes` | Policy that led to regulation | `reference/whitehouse/eo-14110 → precedes → regulation/us/...` |
| `cites` | Used as evidence | `weakness/... → cites → reference/arxiv/...` |
| `informs` | Research informing practice | `reference/arxiv/... → informs → control/...` |

## Future Namespaces

As needed, we may add:
- `eu-policy` - EU Commission policy documents (not yet regulations)
- `uk-policy` - UK government policy papers
- `congress` - US Congressional reports, bills

