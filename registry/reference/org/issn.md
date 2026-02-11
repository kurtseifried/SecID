---
namespace: issn.org
full_name: "International Standard Serial Number"
type: reference

urls:
  website: "https://www.issn.org"
  lookup: "https://portal.issn.org/resource/ISSN/{id}"

id_pattern: "\\d{4}-\\d{3}[\\dX]"
examples:
  - "2169-3536"
  - "0018-9162"

status: draft
---

# ISSN Namespace

International Standard Serial Numbers - unique identifiers for serial publications (journals, magazines, newspapers).

## Format

```
secid:reference/issn.org/{issn}
secid:reference/issn.org/2169-3536
```

## Resolution

```
https://portal.issn.org/resource/ISSN/{id}
```

## Notes

- Format: NNNN-NNNC where C is a check digit (0-9 or X)
- Identifies the serial publication, not individual articles
- Electronic and print versions may have different ISSNs (eISSN vs pISSN)
- Security-relevant journals: IEEE S&P, USENIX Security, ACM CCS proceedings
