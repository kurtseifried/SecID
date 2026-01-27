---
type: advisory
namespace: cert
full_name: "CERT Coordination Center"
operator: "secid:entity/cert"
website: "https://www.kb.cert.org"
status: active

sources:
  vu:
    full_name: "CERT/CC Vulnerability Note"
    urls:
      website: "https://www.kb.cert.org/vuls/"
      lookup: "https://www.kb.cert.org/vuls/id/{id}"
    id_pattern: "VU#\\d+"
    examples:
      - "secid:advisory/cert/vu#VU#867593"
      - "secid:advisory/cert/vu#VU#498544"
---

# CERT Advisory Sources

CERT/CC is the original computer security incident response team, established at Carnegie Mellon University after the Morris Worm in 1988. CERT/CC coordinates vulnerability disclosure and publishes vulnerability notes.

## Why CERT/CC Matters

CERT/CC pioneered coordinated vulnerability disclosure:

- **VU# Vulnerability Notes** - Detailed vulnerability analysis with coordination history
- **Multi-vendor coordination** - Specializes in vulnerabilities affecting multiple vendors
- **Historical archive** - VU# numbers predate CVE for some vulnerabilities

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

---

## vu

CERT Coordination Center vulnerability notes.

### Format

```
secid:advisory/cert/vu#VU#NNNNNN
```

### Resolution

```
secid:advisory/cert/vu#VU#867593
  -> https://www.kb.cert.org/vuls/id/867593
```

### Notes

- CERT/CC at Carnegie Mellon University
- VU# numbers predate CVE for some historical vulnerabilities
- Often includes coordination details and vendor responses
- Historical archive of vulnerability coordination
