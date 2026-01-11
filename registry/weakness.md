# Weakness Type (`weakness`)

This type contains references to weakness taxonomies and classifications.

## Purpose

Track and reference weakness types - the abstract "how things go wrong" that underlies vulnerabilities:
- CWE (Common Weakness Enumeration)
- OWASP Top 10 categories
- OWASP LLM Top 10 categories
- Other weakness taxonomies

## Identifier Format

```
secid:weakness/<namespace>/<name>[#subpath]

secid:weakness/mitre/cwe#CWE-79
secid:weakness/mitre/cwe#CWE-1427
secid:weakness/owasp/top10@2021#A01
secid:weakness/owasp/llm-top10@2.0#LLM01
```

## Namespaces

| Namespace | Name | Taxonomy | Description |
|-----------|------|----------|-------------|
| `mitre` | `cwe` | CWE | MITRE Common Weakness Enumeration |
| `owasp` | `top10` | OWASP Top 10 | Web application security risks |
| `owasp` | `llm-top10` | OWASP LLM Top 10 | LLM application security risks |

## Weakness vs Advisory

- **Weakness**: A category of mistake (CWE-79 = XSS pattern)
- **Advisory**: A specific instance (CVE-2024-1234 = XSS in ProductX)

Multiple advisories can share the same weakness type.

## Relationships

Advisories reference their underlying weakness:

```json
{
  "from": "secid:advisory/mitre/cve#CVE-2024-1234",
  "to": "secid:weakness/mitre/cwe#CWE-79",
  "type": "hasWeakness",
  "asserted_by": "nvd"
}
```

Weaknesses can be related to attack techniques:

```json
{
  "from": "secid:weakness/mitre/cwe#CWE-89",
  "to": "secid:ttp/mitre/capec#CAPEC-66",
  "type": "exploitedBy",
  "description": "SQL injection exploited by CAPEC-66"
}
```

## AI-Specific Weaknesses

CWE has added AI-specific entries:

| CWE | Name |
|-----|------|
| CWE-1426 | Improper Validation of Generative AI Output |
| CWE-1427 | Improper Neutralization of Input for LLM Prompting |
| CWE-1434 | Insecure ML Model Inference Parameters |

OWASP LLM Top 10 provides broader AI risk categories:

| ID | Name |
|----|------|
| LLM01 | Prompt Injection |
| LLM02 | Insecure Output Handling |
| LLM03 | Training Data Poisoning |
| LLM04 | Model Denial of Service |
| LLM05 | Supply Chain Vulnerabilities |

Coverage is incomplete - many AI attack patterns lack CWE assignments.

