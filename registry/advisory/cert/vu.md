---
type: advisory
namespace: cert
name: vu
full_name: "CERT/CC Vulnerability Note"
operator: "secid:entity/cert"

urls:
  website: "https://www.kb.cert.org/vuls/"
  lookup: "https://www.kb.cert.org/vuls/id/{id}"

id_pattern: "VU#\\d+"

examples:
  - "secid:advisory/cert/vu#VU#867593"
  - "secid:advisory/cert/vu#VU#498544"

status: active
---

# CERT/CC Vulnerability Note (VU#)

CERT Coordination Center vulnerability notes.

## Format

```
secid:advisory/cert/vu#VU#NNNNNN
```

## Resolution

```
secid:advisory/cert/vu#VU#867593
  → https://www.kb.cert.org/vuls/id/867593
```

## Notes

- CERT/CC at Carnegie Mellon University
- VU# numbers predate CVE for some historical vulnerabilities
- Often includes coordination details and vendor responses
- Historical archive of vulnerability coordination
