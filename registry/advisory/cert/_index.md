---
namespace: cert
full_name: "CERT Coordination Center"
website: "https://www.kb.cert.org"
type: nonprofit
founded: 1988
headquarters: "Pittsburgh, Pennsylvania, USA"
parent: "Carnegie Mellon University Software Engineering Institute"
---

# CERT Coordination Center (CERT/CC)

CERT/CC is the original computer security incident response team, established at Carnegie Mellon University after the Morris Worm in 1988. CERT/CC coordinates vulnerability disclosure and publishes vulnerability notes.

## Why CERT/CC Matters

CERT/CC pioneered coordinated vulnerability disclosure:

- **VU# Vulnerability Notes** - Detailed vulnerability analysis with coordination history
- **Multi-vendor coordination** - Specializes in vulnerabilities affecting multiple vendors
- **Historical archive** - VU# numbers predate CVE for some vulnerabilities

## Advisory Sources in This Namespace

| Name | Description | Example ID |
|------|-------------|------------|
| `vu` | Vulnerability Notes | VU#867593 |

## VU# vs CVE

CERT/CC Vulnerability Notes provide different value than CVE:

- **Coordination details** - Who was notified, timeline, vendor responses
- **Multi-vendor focus** - Particularly valuable for protocol/library vulnerabilities
- **Analysis depth** - Often more technical detail than CVE descriptions

Most VU# entries have corresponding CVE IDs, but the VU# note contains additional context.

## Notes

- CERT/CC is funded by CISA through the SEI FFRDC
- "CERT" is a registered trademark - other "CERTs" worldwide are unrelated organizations
- CERT/CC focuses on coordination; they don't scan or discover most vulnerabilities themselves
