---
namespace: openalex
full_name: "OpenAlex"
type: reference

urls:
  website: "https://openalex.org"
  lookup: "https://openalex.org/works/{id}"
  api: "https://api.openalex.org/works/{id}"

id_pattern: "W\\d+"
examples:
  - "W2741809807"
  - "W4385375373"

status: draft
---

# OpenAlex Namespace

OpenAlex - open catalog of the world's scholarly works, authors, venues, and institutions.

## Format

```
secid:reference/openalex/{work-id}
secid:reference/openalex/W2741809807
```

## Resolution

```
https://openalex.org/works/{id}
https://api.openalex.org/works/{id}
```

## Entity Types

| Prefix | Entity |
|--------|--------|
| W | Works (papers) |
| A | Authors |
| S | Sources (venues) |
| I | Institutions |
| C | Concepts |
| P | Publishers |
| F | Funders |

## Notes

- Open replacement for Scopus/Web of Science
- ~250 million works indexed
- Free API (100k requests/day)
- Built on Microsoft Academic Graph data
- Good coverage of non-English works
- Links to DOI, PubMed, arXiv where available
