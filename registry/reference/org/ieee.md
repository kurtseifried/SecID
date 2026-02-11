---
namespace: ieee.org
full_name: "IEEE Xplore Digital Library"
type: reference

urls:
  website: "https://ieeexplore.ieee.org"
  lookup: "https://ieeexplore.ieee.org/document/{id}"

id_pattern: "\\d{7,8}"
examples:
  - "9833747"
  - "10179215"

status: draft
---

# IEEE Xplore Namespace

IEEE Xplore Digital Library - major publisher of computer science and security research.

## Format

```
secid:reference/ieee.org/{document-number}
secid:reference/ieee.org/9833747
```

## Resolution

```
https://ieeexplore.ieee.org/document/{id}
```

## Security-Relevant Venues

| Venue | Description |
|-------|-------------|
| IEEE S&P | IEEE Symposium on Security and Privacy (Oakland) |
| IEEE CSF | IEEE Computer Security Foundations |
| IEEE TDSC | IEEE Transactions on Dependable and Secure Computing |
| IEEE TIFS | IEEE Transactions on Information Forensics and Security |

## Notes

- Document numbers are 7-8 digit integers
- Covers journals, conferences, standards
- Many papers behind paywall (institutional access)
- DOI also available for most papers (use `secid:reference/doi.org/...` for DOI access)
