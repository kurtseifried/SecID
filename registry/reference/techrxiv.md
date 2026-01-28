---
namespace: techrxiv
full_name: "TechRxiv"
type: reference

urls:
  website: "https://www.techrxiv.org"
  lookup: "https://www.techrxiv.org/doi/full/10.36227/techrxiv.{id}"

id_pattern: "\\d+(\\.v\\d+)?"
examples:
  - "21397269"
  - "21397269.v2"

status: draft
---

# TechRxiv Namespace

TechRxiv (pronounced "tech archive") - IEEE's preprint server for engineering and computer science.

## Format

```
secid:reference/techrxiv/{id}
secid:reference/techrxiv/21397269
```

## Resolution

```
https://www.techrxiv.org/doi/full/10.36227/techrxiv.{id}
```

## Notes

- Operated by IEEE
- Covers electrical engineering, computer science, and related technology
- Open access preprints
- Papers may be versioned (e.g., 21397269.v2)
- Often a preprint stage before IEEE publication
- DOIs also available: 10.36227/techrxiv.{id}
