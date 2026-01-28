---
namespace: ssrn
full_name: "Social Science Research Network"
type: reference

urls:
  website: "https://www.ssrn.com"
  lookup: "https://papers.ssrn.com/sol3/papers.cfm?abstract_id={id}"

id_pattern: "\\d{6,7}"
examples:
  - "4567890"
  - "3821234"

status: draft
---

# SSRN Namespace

Social Science Research Network - preprint server covering law, economics, and computer science.

## Format

```
secid:reference/ssrn/{abstract-id}
secid:reference/ssrn/4567890
```

## Resolution

```
https://papers.ssrn.com/sol3/papers.cfm?abstract_id={id}
```

## Relevant Networks

| Network | Focus |
|---------|-------|
| CompSciRN | Computer Science Research Network |
| LSN | Legal Scholarship Network (privacy law, cyber law) |
| ERPN | Economics Research (security economics) |

## Notes

- Abstract IDs are 6-7 digit numbers
- Now owned by Elsevier
- Free to read, registration may be required for download
- Good for interdisciplinary security research (law, policy, economics)
- Many cybersecurity policy papers
